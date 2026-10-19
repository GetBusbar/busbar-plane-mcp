// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `2024-11-05` HTTP+SSE CLIENT RUNG, HELD (row 159 finding 1; ARCHITECT ruling H1 (a)): busbar
//! reaches a registered server that speaks only the legacy event-stream revision.
//!
//! * ONE HELD STREAM per member AND caller binding ([`crate::tool_sessions::upstream_key`]; the H3
//!   per-caller rule): the `GET` that opens it, its `endpoint` event, the message address the POSTs
//!   go to, the `initialize` handshake, and correlation by JSON-RPC id are the plane's. Two callers'
//!   bindings never share a stream.
//! * THE CONNECTOR HOLDS THE CONNECTION, as it does for every dial. The stream is read on the
//!   instance's ONE driver ticket ([`drive`]): the connector's readiness wakes the driver, `drive`
//!   reads what arrived, and each answer is handed to the call waiting for its id, whose ticket is
//!   woken. Driver-ticket answers are kept only for one tick cycle, so the link numbers its
//!   services per cycle and never re-issues a step that already answered.
//! * A call POSTs its own request (and the first call on a link its `initialize`) on its own
//!   ticket, the answer's id registered BEFORE the POST leaves, then waits for the driver to hand it
//!   the answer under that id.
//! * A REPLY WHOSE ID NO CALL WAITS FOR is dropped, never delivered to another call, and counted:
//!   the next answer on that caller's link carries one rejected `mcp_upstream.reply` audit row per
//!   reply dropped.
//! * THE STREAM DROPPING fails every call waiting on it as any upstream failure fails a call
//!   ([`crate::call::upstream_failed`]), with [`STREAM_CLOSED`]'s words; the next call opens a new
//!   stream.

use std::collections::BTreeMap;
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    ReplyPiece, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_END,
    REQUEST_HEAD,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::Instance;
use busbar_contract::abi::transport::{fields, FrameSpan};
use serde_json::Value;

use super::McpDoor;
use crate::client::compat::{
    initialize_request, initialized_notification, lower_request, offered_revision, EventReader,
    EventStreamLink, LinkEffect,
};
use crate::client::jsonrpc::OutboundRequest;
use crate::client::negotiate::Verb;
use crate::revision::Revision;

/// The words every call waiting on a held stream fails with when the stream drops before its
/// answer arrives.
pub const STREAM_CLOSED: &str =
    "the MCP server's 2024-11-05 event stream closed before it answered this call";

/// The audit action a reply no call waited for is recorded under (rejected: it was never delivered).
pub const ACTION_REPLY_DROPPED: &str = "mcp_upstream.reply";

/// The most calls one held stream waits answers for at once.
const MAX_WAITING: usize = 64;

/// The most bytes of an unfinished event a link keeps.
const MAX_EVENT: usize = 1 << 20;

/// The size of the link's read buffer.
const READ_CHUNK: usize = 1 << 16;

/// The handle seq the link's stream services are numbered from on the driver ticket.
const LINK_SEQ: u32 = 1 << 27;

/// How many handles one link numbers in one tick cycle, before the next link's.
const LINK_SPAN: u32 = 1 << 16;

/// The id `initialize` carries on a held stream.
const INITIALIZE_ID: u64 = u64::MAX;

/// The handles one POST on a call's ticket may number.
const POST_SPAN: u32 = super::door_sessions::HOP_SPAN;

/// Where a link's stream is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Nothing dialled yet.
    Establish,
    /// The `GET`'s head to write.
    Head,
    /// The `GET`'s end to write.
    End,
    /// The stream's reply, read piece by piece for its life.
    Read,
}

/// Where the link's `initialize` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Init {
    /// No call has started it.
    Idle,
    /// A call is running it.
    Running,
    /// Done: calls may POST.
    Done,
}

/// ONE HELD STREAM: one member's `2024-11-05` conversation for one caller binding.
pub(super) struct Link {
    /// Which link this is: a call that began on an earlier one is failed, never answered here.
    generation: u64,
    /// The registered endpoint (the `GET` opens the stream there).
    url: String,
    /// The member it reaches.
    member: String,
    /// The `GET`'s head bytes and descriptors (parked: a pending write reads them).
    head: Box<[u8]>,
    head_piece: Box<RequestPiece>,
    end_piece: Box<RequestPiece>,
    /// The connector's stream, once established.
    stream: Option<u64>,
    step: Step,
    /// Why the stream is gone, once it is.
    dead: Option<String>,
    /// Connector streams this key's earlier (dead) links held, still to close: a dropped stream
    /// is let go at the connector, never left open behind a new one.
    stale: Vec<u64>,
    reader: EventReader,
    link: EventStreamLink,
    init: Init,
    /// Answers read, by their id's JSON text, until their call takes them.
    answers: BTreeMap<String, Vec<u8>>,
    /// The ticket of the call waiting for each id.
    waiters: BTreeMap<String, Ticket>,
    /// Calls waiting for the link to be usable (its address named, its `initialize` done).
    parked: Vec<Ticket>,
    /// The next id a call on this stream carries.
    next_id: u64,
    /// Replies no call waited for, dropped, not yet audited.
    dropped: u32,
    /// The tick cycle the link's handles are numbered in, and how many it issued in it.
    cycle: u64,
    issued: u32,
    buf: Box<[u8]>,
    slot: Box<ReplyPiece>,
}

impl Link {
    fn new(generation: u64, url: &str, member: &str, template: &OutboundRequest) -> Self {
        // The GET carries the request's own head (its credential and the rest), minus what a body
        // states, and asks for the event stream.
        let path = crate::call::path_of(url);
        let mut head = Vec::new();
        head.extend_from_slice(b"GET");
        head.extend_from_slice(path.as_bytes());
        let block_at = head.len();
        for (name, value) in template.headers.iter().filter(|(n, _)| {
            !n.eq_ignore_ascii_case("content-type") && !n.eq_ignore_ascii_case("accept")
        }) {
            head.extend_from_slice(name.as_bytes());
            head.extend_from_slice(fields::SEPARATOR);
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(fields::LINE_END);
        }
        head.extend_from_slice(b"accept");
        head.extend_from_slice(fields::SEPARATOR);
        head.extend_from_slice(crate::framing::EVENT_STREAM.as_bytes());
        head.extend_from_slice(fields::LINE_END);
        let span = |offset: usize, len: usize| FrameSpan {
            offset: offset as u64,
            len: len as u64,
        };
        let head_piece = RequestPiece {
            kind: REQUEST_HEAD,
            _reserved: 0,
            method: span(0, 3),
            target: span(3, path.len()),
            fields: span(block_at, head.len() - block_at),
            timeout_ms: 0,
        };
        Self {
            generation,
            url: url.to_string(),
            member: member.to_string(),
            head: head.into_boxed_slice(),
            head_piece: Box::new(head_piece),
            end_piece: Box::new(RequestPiece {
                kind: REQUEST_END,
                ..RequestPiece::default()
            }),
            stream: None,
            step: Step::Establish,
            dead: None,
            stale: Vec::new(),
            reader: EventReader::new(MAX_EVENT),
            link: EventStreamLink::new(url, MAX_WAITING),
            init: Init::Idle,
            answers: BTreeMap::new(),
            waiters: BTreeMap::new(),
            parked: Vec::new(),
            next_id: 1,
            dropped: 0,
            cycle: 0,
            issued: 0,
            buf: vec![0; READ_CHUNK].into_boxed_slice(),
            slot: Box::default(),
        }
    }

    /// The stream is gone: every waiting call is woken to read why.
    fn die(&mut self, why: &str, woken: &mut Vec<Ticket>) {
        if self.dead.is_none() {
            self.dead = Some(why.to_string());
        }
        woken.extend(self.waiters.values().copied());
        woken.append(&mut self.parked);
    }

    /// One chunk of the stream's body: every event it completed, read.
    fn events(&mut self, chunk: &[u8], woken: &mut Vec<Ticket>) {
        for event in self.reader.feed(chunk) {
            // A REPLY NO CALL WAITS FOR is dropped and counted, never handed to the link's
            // correlation (which would hand nothing) and never to another call.
            if let Ok(v) = serde_json::from_str::<Value>(&event.data) {
                if v.get("method").is_none() {
                    if let Some(id) = v.get("id").map(Value::to_string) {
                        if !self.waiters.contains_key(&id) {
                            self.dropped = self.dropped.saturating_add(1);
                            continue;
                        }
                    }
                }
            }
            match self.link.on_event(&event) {
                LinkEffect::Ready(_) => woken.append(&mut self.parked),
                LinkEffect::Refused(_) => self.die(
                    "the MCP server's 2024-11-05 event stream named a message address busbar \
                     will not POST to",
                    woken,
                ),
                LinkEffect::Answer { id, body } => {
                    if let Some(t) = self.waiters.remove(&id) {
                        self.answers.insert(id, body);
                        woken.push(t);
                    }
                }
                LinkEffect::FromPeer(_) | LinkEffect::Ignored => {}
            }
        }
        if self.reader.overflowed() {
            self.die(STREAM_CLOSED, woken);
        }
    }

    /// DRIVES the stream on the driver ticket, its services numbered from `base` in tick cycle
    /// `cycle`: dialled, its `GET` written, and its reply read until it pends or ends.
    fn drive(
        &mut self,
        host: &Host,
        driver: Ticket,
        (cycle, base): (u64, u32),
        woken: &mut Vec<Ticket>,
    ) {
        if self.cycle != cycle {
            // A tick forgot the last cycle's kept answers: this cycle numbers its own.
            (self.cycle, self.issued) = (cycle, 0);
        }
        while self.issued < LINK_SPAN {
            let mut c = host.connector_from(driver, base.saturating_add(self.issued));
            // A dead stream is closed at the connector before anything else.
            if self.dead.is_some() {
                if let Some(stream) = self.stream.take() {
                    self.stale.push(stream);
                }
            }
            if let Some(&stream) = self.stale.last() {
                if c.close(stream).is_pending() {
                    return;
                }
                self.issued += 1;
                self.stale.pop();
                continue;
            }
            if self.dead.is_some() {
                return;
            }
            match self.step {
                Step::Establish => match c.establish_as(
                    crate::door::NEED_UPSTREAM,
                    Some(&self.url),
                    "",
                    0,
                    Some(&self.member),
                ) {
                    Poll::Pending => return,
                    Poll::Ready(Ok(stream)) => {
                        self.issued += 1;
                        self.stream = Some(stream);
                        self.step = Step::Head;
                    }
                    Poll::Ready(Err(e)) => self.die(&e.to_string(), woken),
                },
                Step::Head | Step::End => {
                    let stream = self.stream.unwrap_or_default();
                    let written = if self.step == Step::Head {
                        c.write_request(stream, &self.head_piece, &self.head)
                    } else {
                        c.write_request(stream, &self.end_piece, &[])
                    };
                    match written {
                        Poll::Pending => return,
                        Poll::Ready(Ok(_)) => {
                            self.issued += 1;
                            self.step = if self.step == Step::Head {
                                Step::End
                            } else {
                                Step::Read
                            };
                        }
                        Poll::Ready(Err(e)) => self.die(&e.to_string(), woken),
                    }
                }
                Step::Read => {
                    let stream = self.stream.unwrap_or_default();
                    match c.read_reply(stream, &mut self.buf, &mut self.slot) {
                        Poll::Pending => return,
                        Poll::Ready(Ok(got)) => {
                            self.issued += 1;
                            match got.piece.kind {
                                REPLY_HEAD => {
                                    let block = spanned(&self.buf[..got.len], got.piece.fields);
                                    let streams = fields::lines(block).any(|(n, v)| {
                                        n.eq_ignore_ascii_case(b"content-type")
                                            && v.starts_with(
                                                crate::framing::EVENT_STREAM.as_bytes(),
                                            )
                                    });
                                    if got.piece.code != 200 || !streams {
                                        self.die(
                                            &format!(
                                                "the MCP server answered its 2024-11-05 event \
                                                 stream's GET with HTTP {} and no event stream",
                                                got.piece.code
                                            ),
                                            woken,
                                        );
                                    }
                                }
                                REPLY_BODY => {
                                    let chunk = self.buf[..got.len].to_vec();
                                    self.events(&chunk, woken);
                                }
                                REPLY_END | REPLY_ACK => self.die(STREAM_CLOSED, woken),
                                _ => self.die(STREAM_CLOSED, woken),
                            }
                        }
                        Poll::Ready(Err(e)) => self.die(&e.to_string(), woken),
                    }
                }
            }
        }
    }
}

/// The bytes `span` names in `buf`, or none past its end.
fn spanned(buf: &[u8], span: FrameSpan) -> &[u8] {
    let (at, len) = (span.offset as usize, span.len as usize);
    buf.get(at..at.saturating_add(len)).unwrap_or(&[])
}

/// Whether the instance holds any stream (the tick wakes the driver for them).
pub(super) fn any(plane: &McpDoor) -> bool {
    !plane.legacy.is_empty()
}

/// THE DRIVER'S PART, on the instance's driver ticket (`drive`): every held stream read as far as
/// it goes, and every call an answer (or the stream's end) reached woken. A dead stream no call
/// waits on any more is let go.
pub(super) fn drive(instance: &Instance<'_, McpDoor>, plane: &McpDoor) {
    let Some(host) = plane.host.as_ref() else {
        return;
    };
    let driver = instance.ticket();
    let cycle = plane.driver.get(&()).map_or(0, |(_, now)| now);
    let mut woken = Vec::new();
    plane.legacy.with_all(|m| {
        for (n, link) in (0_u32..).zip(m.values_mut()) {
            let base = LINK_SEQ.saturating_add(n.saturating_mul(LINK_SPAN));
            link.drive(host, driver, (cycle, base), &mut woken);
        }
        m.retain(|_, l| {
            l.dead.is_none()
                || !l.stale.is_empty()
                || !l.waiters.is_empty()
                || !l.answers.is_empty()
        });
    });
    if let Some(wake) = plane.wake.as_ref() {
        for t in woken {
            wake.wake(t);
        }
    }
}

/// `dropped` replies a call took from the stream of `key` but has no answer to audit them on: counted
/// on the stream again, for the next call's answer.
pub(super) fn recount(plane: &McpDoor, key: &str, dropped: u32) {
    if dropped == 0 {
        return;
    }
    plane.legacy.with(&key.to_string(), |l| {
        if let Some(l) = l {
            l.dropped = l.dropped.saturating_add(dropped);
        }
    });
}

/// The op on `ticket` was cancelled: no call waits there any more, and an answer still to come
/// for it is a reply no call waits for.
pub(super) fn cancelled(plane: &McpDoor, ticket: Ticket) {
    plane.legacy.with_all(|m| {
        for l in m.values_mut() {
            let gone: Vec<String> = l
                .waiters
                .iter()
                .filter(|(_, t)| **t == ticket)
                .map(|(id, _)| id.clone())
                .collect();
            for id in gone {
                l.waiters.remove(&id);
                if let Ok(v) = serde_json::from_str::<Value>(&id) {
                    l.link.abandon(&v);
                }
            }
            l.parked.retain(|t| *t != ticket);
        }
    });
}

/// One call's place on a held stream, parked on its unit across PENDING entries.
#[derive(Debug, Default)]
pub(super) struct Calling {
    /// The link it began on.
    generation: u64,
    /// The id it carries, once allocated.
    id: Option<u64>,
    /// Its own POST was taken.
    posted: bool,
    /// This call runs the link's `initialize`: 1 its POST taken, 2 its answer read, 3 the
    /// notification taken.
    init: u8,
}

/// What a call came to: the answer under the id it carried, the replies dropped on its link since
/// the last answer, or why it failed.
pub(super) type Called = Result<(Vec<u8>, u64, u32), String>;

/// A CALL OVER THE HELD STREAM of `key` (a member and a caller binding), on the call's own ticket:
/// the stream opened if none is, its `initialize` run by the first call that finds none done, the
/// call's request POSTed to the message address under an id of the stream's, and its answer taken
/// once the driver read it. PENDING meanwhile.
pub(super) fn call(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    (key, member): (&str, &str),
    original: &OutboundRequest,
    state: &mut Option<Calling>,
    (base, timeout_ms): (u32, u64),
) -> Poll<Called> {
    let ticket = instance.ticket();
    if state.is_none() {
        let generation = plane.legacy.with_all(|m| {
            let usable = m.get(key).is_some_and(|l| l.dead.is_none());
            if !usable {
                // A dead link's stream, and any it still had to close, are closed by its successor.
                let (generation, stale) = m.remove(key).map_or((1, Vec::new()), |old| {
                    let mut stale = old.stale;
                    stale.extend(old.stream);
                    (old.generation.saturating_add(1), stale)
                });
                let mut link = Link::new(generation, &original.url, member, original);
                link.stale = stale;
                m.insert(key.to_string(), link);
            }
            m.get(key).map_or(0, |l| l.generation)
        });
        *state = Some(Calling {
            generation,
            ..Calling::default()
        });
        super::door_listen::wake_driver(plane);
    }
    let st = state.as_mut().expect("set above");
    loop {
        // What the link says now, under its lock; the POSTs run outside it.
        let next = plane.legacy.with(&key.to_string(), |l| {
            let Some(l) = l.filter(|l| l.generation == st.generation) else {
                return Next::Fail(STREAM_CLOSED.to_string());
            };
            if let Some(id) = st.id {
                let text = Value::from(id).to_string();
                if let Some(body) = l.answers.remove(&text) {
                    return Next::Answered(body, id, std::mem::take(&mut l.dropped));
                }
            }
            if let Some(why) = &l.dead {
                if let Some(id) = st.id {
                    l.waiters.remove(&Value::from(id).to_string());
                }
                return Next::Fail(why.clone());
            }
            let Some(address) = l.link.address().map(str::to_string) else {
                l.parked.push(ticket);
                return Next::Wait;
            };
            match (l.init, st.init) {
                (Init::Idle, 0) => {
                    // This call runs the link's `initialize`: its answer is waited for under its id,
                    // registered before the POST leaves.
                    l.init = Init::Running;
                    let id = Value::from(INITIALIZE_ID);
                    l.link.expect(&id);
                    l.waiters.insert(id.to_string(), ticket);
                    Next::PostInit(address)
                }
                (Init::Running, 1) => {
                    let text = Value::from(INITIALIZE_ID).to_string();
                    match l.answers.remove(&text) {
                        Some(body) => Next::Initialized(body),
                        None => Next::Wait,
                    }
                }
                (Init::Running, 2) => Next::PostInitialized(address),
                (Init::Running, _) | (Init::Idle, _) => {
                    l.parked.push(ticket);
                    Next::Wait
                }
                (Init::Done, _) if st.posted => Next::Wait,
                (Init::Done, _) => {
                    let id = match st.id {
                        Some(id) => id,
                        None => {
                            let id = l.next_id;
                            l.next_id = l.next_id.saturating_add(1);
                            let v = Value::from(id);
                            if !l.link.expect(&v) {
                                return Next::Fail(format!(
                                    "MCP server `{member}`: its 2024-11-05 event stream already \
                                     waits on {MAX_WAITING} calls"
                                ));
                            }
                            l.waiters.insert(v.to_string(), ticket);
                            st.id = Some(id);
                            id
                        }
                    };
                    Next::PostCall(address, id)
                }
            }
        });
        match next {
            Next::Answered(body, id, dropped) => {
                *state = None;
                return Poll::Ready(Ok((body, id, dropped)));
            }
            Next::Fail(why) => {
                *state = None;
                return Poll::Ready(Err(why));
            }
            Next::Wait => return Poll::Pending,
            Next::PostInit(address) => {
                let request = initialize_request(
                    original,
                    &address,
                    Revision::R2024_11_05,
                    INITIALIZE_ID,
                    super::VERSION,
                );
                match post(instance, plane, (base, member), &request, timeout_ms) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => st.init = 1,
                    Poll::Ready(Err(why)) => return Poll::Ready(Err(fail_link(plane, key, &why))),
                }
            }
            Next::Initialized(body) => {
                if offered_revision(&body) != Some(Revision::R2024_11_05) {
                    let why = format!(
                        "MCP server `{member}` answered `initialize` on its 2024-11-05 event \
                         stream with a revision busbar does not carry there"
                    );
                    return Poll::Ready(Err(fail_link(plane, key, &why)));
                }
                st.init = 2;
            }
            Next::PostInitialized(address) => {
                let request =
                    initialized_notification(original, &address, Revision::R2024_11_05, None);
                match post(
                    instance,
                    plane,
                    (base.saturating_add(POST_SPAN), member),
                    &request,
                    timeout_ms,
                ) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => {
                        st.init = 3;
                        let woken = plane.legacy.with(&key.to_string(), |l| {
                            l.map(|l| {
                                l.init = Init::Done;
                                std::mem::take(&mut l.parked)
                            })
                            .unwrap_or_default()
                        });
                        if let Some(wake) = plane.wake.as_ref() {
                            for t in woken {
                                wake.wake(t);
                            }
                        }
                    }
                    Poll::Ready(Err(why)) => return Poll::Ready(Err(fail_link(plane, key, &why))),
                }
            }
            Next::PostCall(address, id) => {
                let mut request = lower_request(original, &address, Revision::R2024_11_05, None);
                if let Ok(mut body) = serde_json::from_slice::<Value>(&request.body) {
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert("id".to_string(), Value::from(id));
                    }
                    if let Ok(bytes) = serde_json::to_vec(&body) {
                        request.body = bytes;
                    }
                }
                match post(
                    instance,
                    plane,
                    (base.saturating_add(POST_SPAN.saturating_mul(2)), member),
                    &request,
                    timeout_ms,
                ) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => st.posted = true,
                    Poll::Ready(Err(why)) => {
                        plane.legacy.with(&key.to_string(), |l| {
                            if let Some(l) = l {
                                let v = Value::from(id);
                                l.waiters.remove(&v.to_string());
                                l.link.abandon(&v);
                            }
                        });
                        *state = None;
                        return Poll::Ready(Err(why));
                    }
                }
            }
        }
    }
}

/// What a call does next, decided under the link's lock.
enum Next {
    Answered(Vec<u8>, u64, u32),
    Fail(String),
    Wait,
    PostInit(String),
    Initialized(Vec<u8>),
    PostInitialized(String),
    PostCall(String, u64),
}

/// The link of `key` failed for `why`: every call on it is woken to read it.
fn fail_link(plane: &McpDoor, key: &str, why: &str) -> String {
    let mut woken = Vec::new();
    plane.legacy.with(&key.to_string(), |l| {
        if let Some(l) = l {
            l.die(why, &mut woken);
        }
    });
    if let Some(wake) = plane.wake.as_ref() {
        for t in woken {
            wake.wake(t);
        }
    }
    why.to_string()
}

/// ONE POST to the message address on the call's ticket: taken when the server answered it 2xx (the
/// answer itself arrives on the stream).
fn post(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    (base, member): (u32, &str),
    request: &OutboundRequest,
    timeout_ms: u64,
) -> Poll<Result<(), String>> {
    let polled = super::exchange_at(
        instance,
        plane.host.as_ref(),
        base,
        &request.url,
        member,
        || super::door_sessions::exchange_request(Verb::Post, request, timeout_ms),
    );
    match polled {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(r)) if (200..300).contains(&r.status) => Poll::Ready(Ok(())),
        Poll::Ready(Ok(r)) => Poll::Ready(Err(format!(
            "MCP server `{member}` refused a POST to its 2024-11-05 message address (HTTP {})",
            r.status
        ))),
        Poll::Ready(Err(e)) => Poll::Ready(Err(e.to_string())),
    }
}
