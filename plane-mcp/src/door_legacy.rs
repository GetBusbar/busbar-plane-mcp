// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `2024-11-05` HTTP+SSE CLIENT RUNG, HELD (row 159 finding 1): busbar reaches a registered
//! server that speaks only the legacy event-stream revision.
//!
//! * ONE HELD STREAM per member AND caller binding: its `GET`, its `endpoint` event, the message
//!   address, the `initialize` handshake and correlation by JSON-RPC id are the plane's.
//! * The connector holds the connection; the stream is read on the instance's ONE driver ticket
//!   ([`drive`]), whose handles are numbered by one counter per tick cycle shared by every link, so
//!   a handle that answered is never re-issued in that cycle.
//! * A call POSTs its own request on its own ticket, its id registered BEFORE the POST leaves, and
//!   waits for the driver to hand it the answer under that id.
//! * A reply whose id no call waits for is dropped and counted: the next answer on that link
//!   carries one rejected `mcp_upstream.reply` audit row per reply, at most
//!   [`MAX_DROPPED_AUDITED`].
//! * The server's own messages are routed as the other rungs route them (`ping` answered, an ask
//!   refused, an unknown request `-32601`, each reply POSTed on the driver ticket); a resource
//!   update is announced, and a call's progress and the stream's log records ride its answer.
//! * The stream dropping fails every waiting call with [`STREAM_CLOSED`]'s words.
//! * BOUNDED: at most [`MAX_LINKS`] live streams (past it an idle one is let go; with none idle the
//!   call is refused), and a stream unused for [`IDLE_NS`] is closed.

use std::collections::{BTreeMap, VecDeque};
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    ReplyPiece, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY,
    REQUEST_END, REQUEST_HEAD,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::{Connector, Host};
use busbar_contract::abi::sdk::Instance;
use busbar_contract::abi::transport::{fields, FrameSpan};
use serde_json::Value;

use super::McpDoor;
use crate::client::compat::{
    initialize_request, initialized_notification, lower_request, message_address, offered_revision,
    EventReader, INITIALIZE_ID,
};
use crate::client::jsonrpc::{OutboundRequest, ServerRequestGrants};
use crate::client::peer::{NotificationEffect, ServerMessage, ServerNotification};
use crate::revision::Revision;

/// The words every call waiting on a held stream fails with when the stream drops before its
/// answer arrives.
pub const STREAM_CLOSED: &str =
    "the MCP server's 2024-11-05 event stream closed before it answered this call";

/// The audit action a reply no call waited for is recorded under (rejected: it was never delivered).
pub const ACTION_REPLY_DROPPED: &str = "mcp_upstream.reply";

/// The most rejected `mcp_upstream.reply` rows one answer carries: replies dropped past it are
/// counted no further, so an upstream that floods replies no call waits for grows neither the count
/// nor the caller's answer.
pub const MAX_DROPPED_AUDITED: u32 = 4;

/// The most calls one held stream waits answers for at once.
const MAX_WAITING: usize = 64;

/// The most live held streams one instance keeps.
const MAX_LINKS: usize = 256;

/// How long (tick clock, ns) a held stream no call uses is kept before it is closed.
const IDLE_NS: u64 = 5 * 60 * 1_000_000_000;

/// The words a stream let go for idleness is closed with (no call waits on it to read them).
const IDLE: &str = "the MCP server's 2024-11-05 event stream went unused and was closed";

/// The most bytes of an unfinished event a link keeps.
const MAX_EVENT: usize = 1 << 20;

/// The size of the link's read buffer.
const READ_CHUNK: usize = 1 << 16;

/// The handle seq the instance's stream services are numbered from on the driver ticket.
const LINK_SEQ: u32 = 1 << 27;

/// How many handles the instance's streams number in one tick cycle, all links together.
const CYCLE_SPAN: u32 = 1 << 26;

/// The most replies to the server's own requests a link holds unsent.
const MAX_OUTBOX: usize = 64;

/// The most progress or log frames a link holds for the next answer.
const MAX_NOTES: usize = 64;

/// The prefix of the progress token a call's request carries on a held stream, before its id.
const PROGRESS_PREFIX: &str = "busbar-";

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

/// Where one reply POST to the message address is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyStep {
    Establish,
    Head,
    Body,
    End,
    Read,
    Close,
}

/// ONE REPLY to a request of the server's own, POSTed to the message address on the driver ticket.
struct Reply {
    step: ReplyStep,
    stream: Option<u64>,
    head: Box<[u8]>,
    head_piece: Box<RequestPiece>,
    body: Box<[u8]>,
    sent: usize,
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
    body_piece: Box<RequestPiece>,
    /// The head fields every POST of the link carries (the credential and the rest, lowered into
    /// the revision: no stateless mirror).
    fields: Vec<(String, String)>,
    /// The connector's stream, once established.
    stream: Option<u64>,
    step: Step,
    /// Why the stream is gone, once it is.
    dead: Option<String>,
    /// Connector streams this key's earlier (dead) links held, still to close: a dropped stream
    /// is let go at the connector, never left open behind a new one.
    stale: Vec<u64>,
    reader: EventReader,
    /// The message address, once the stream named an acceptable one.
    address: Option<String>,
    init: Init,
    /// The ticket of the call running `initialize`, while one is.
    init_by: Option<Ticket>,
    /// Answers read, by their id's JSON text, with the ticket of the call they are for, until it
    /// takes them.
    answers: BTreeMap<String, (Ticket, Vec<u8>)>,
    /// The ticket of the call waiting for each id (at most [`MAX_WAITING`]).
    waiters: BTreeMap<String, Ticket>,
    /// Calls waiting for the link to be usable (its address named, its `initialize` done).
    parked: Vec<Ticket>,
    /// The next id a call on this stream carries.
    next_id: u64,
    /// Replies no call waited for, dropped, not yet audited (at most [`MAX_DROPPED_AUDITED`]).
    dropped: u32,
    /// Replies to the server's own requests, not yet POSTed, and the one being POSTed.
    outbox: VecDeque<Vec<u8>>,
    replying: Option<Reply>,
    /// Progress frames for the call each id names, and log records, for the next answer.
    notes: BTreeMap<String, Vec<Value>>,
    logs: Vec<Value>,
    /// The tick clock a call last used the link at (`0`: not yet stamped).
    last_used: u64,
    buf: Box<[u8]>,
    slot: Box<ReplyPiece>,
}

/// What a drive heard that the instance acts on outside the link's lock: the resource updates
/// announced, as `(server, uri)`.
type Announced = Vec<(String, String)>;

impl Link {
    fn new(generation: u64, url: &str, member: &str, template: &OutboundRequest) -> Self {
        // The GET carries the request's own head (its credential and the rest) lowered into the
        // revision (no stateless mirror: a 2024-11-05 server reads none of it), minus what a body
        // states, and asks for the event stream.
        let fields = lower_request(template, url, Revision::R2024_11_05, None, None).headers;
        let kept = fields.iter().filter(|(n, _)| {
            !n.eq_ignore_ascii_case("content-type") && !n.eq_ignore_ascii_case("accept")
        });
        let accept = (
            "accept".to_string(),
            crate::framing::EVENT_STREAM.to_string(),
        );
        let (head, head_piece) = head_of("GET", url, kept.chain(std::iter::once(&accept)));
        Self {
            generation,
            url: url.to_string(),
            member: member.to_string(),
            head,
            head_piece,
            end_piece: Box::new(RequestPiece {
                kind: REQUEST_END,
                ..RequestPiece::default()
            }),
            body_piece: Box::new(RequestPiece {
                kind: REQUEST_BODY,
                ..RequestPiece::default()
            }),
            fields,
            stream: None,
            step: Step::Establish,
            dead: None,
            stale: Vec::new(),
            reader: EventReader::new(MAX_EVENT),
            address: None,
            init: Init::Idle,
            init_by: None,
            answers: BTreeMap::new(),
            waiters: BTreeMap::new(),
            parked: Vec::new(),
            next_id: 1,
            dropped: 0,
            outbox: VecDeque::new(),
            replying: None,
            notes: BTreeMap::new(),
            logs: Vec::new(),
            last_used: 0,
            buf: vec![0; READ_CHUNK].into_boxed_slice(),
            slot: Box::default(),
        }
    }

    /// No call waits on it, nothing it read waits for a call, and nothing it owes the server.
    fn idle(&self) -> bool {
        self.dead.is_none()
            && self.waiters.is_empty()
            && self.parked.is_empty()
            && self.answers.is_empty()
            && self.init != Init::Running
            && self.outbox.is_empty()
            && self.replying.is_none()
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
    fn events(
        &mut self,
        chunk: &[u8],
        grants: ServerRequestGrants,
        woken: &mut Vec<Ticket>,
        announced: &mut Announced,
    ) {
        for event in self.reader.feed(chunk) {
            // A REPLY NO CALL WAITS FOR is dropped and counted, never handed to the link's
            // correlation (which would hand nothing) and never to another call.
            if let Ok(v) = serde_json::from_str::<Value>(&event.data) {
                if v.get("method").is_none() {
                    if let Some(id) = v.get("id").map(Value::to_string) {
                        if !self.waiters.contains_key(&id) {
                            self.dropped = self.dropped.saturating_add(1).min(MAX_DROPPED_AUDITED);
                            continue;
                        }
                    }
                }
            }
            // The `endpoint` event names the message address, once; a path joins the endpoint's
            // origin, and another origin is refused.
            if event.event.as_deref() == Some("endpoint") {
                if self.address.is_none() {
                    match message_address(&self.url, &event.data) {
                        Ok(a) => {
                            self.address = Some(a);
                            woken.append(&mut self.parked);
                        }
                        Err(_) => self.die(
                            "the MCP server's 2024-11-05 event stream named a message address \
                             busbar will not POST to",
                            woken,
                        ),
                    }
                }
                continue;
            }
            if !matches!(
                event.event.as_deref(),
                None | Some(crate::adapt::EVENT_MESSAGE)
            ) {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(&event.data) else {
                continue;
            };
            if v.get("method").is_some() {
                self.peer_message(&v, grants, woken, announced);
            } else if let Some(id) = v.get("id").map(Value::to_string) {
                if let Some(t) = self.waiters.remove(&id) {
                    self.answers.insert(id, (t, event.data.into_bytes()));
                    woken.push(t);
                }
            }
        }
        if self.reader.overflowed() {
            self.die(STREAM_CLOSED, woken);
        }
    }

    /// ONE MESSAGE OF THE SERVER'S OWN, routed as the other rungs route it (Law 11: busbar answers
    /// only the protocol's housekeeping, and an ask it cannot carry to the caller is refused, never
    /// answered for the caller).
    fn peer_message(
        &mut self,
        v: &Value,
        grants: ServerRequestGrants,
        woken: &mut Vec<Ticket>,
        announced: &mut Announced,
    ) {
        let reply = match crate::client::peer::classify(v) {
            Some(ServerMessage::Notification(n)) => {
                match n.effect() {
                    NotificationEffect::RelayResourceUpdate => {
                        if let Some(uri) = v.pointer("/params/uri").and_then(Value::as_str) {
                            announced.push((self.member.clone(), uri.to_string()));
                        }
                    }
                    // Progress reaches only the call whose request carried the token.
                    NotificationEffect::RelayProgress => {
                        let id = v
                            .pointer("/params/progressToken")
                            .and_then(Value::as_str)
                            .and_then(|t| t.strip_prefix(PROGRESS_PREFIX))
                            .filter(|id| self.waiters.contains_key(*id))
                            .map(str::to_string);
                        if let Some(id) = id {
                            let notes = self.notes.entry(id).or_default();
                            if notes.len() < MAX_NOTES {
                                notes.push(v.clone());
                            }
                        }
                    }
                    NotificationEffect::Log
                        if n == ServerNotification::Message && self.logs.len() < MAX_NOTES =>
                    {
                        self.logs.push(v.clone());
                    }
                    NotificationEffect::Log | NotificationEffect::BringRefreshForward => {}
                }
                None
            }
            Some(ServerMessage::UnknownNotification(_)) | None => None,
            Some(ServerMessage::Request { id, verb }) => match verb.ask() {
                Some(ask) if grants.allows(ask) => Some(crate::client::peer::refused(
                    &id,
                    "ask_unavailable",
                    format!(
                        "server `{}` asked for `{}` on its 2024-11-05 event stream, which carries \
                         no relay of a server's ask to busbar's caller; the ask is refused rather \
                         than answered on the caller's behalf",
                        self.member,
                        ask.key()
                    ),
                )),
                _ => crate::client::peer::answer(&id, verb, &grants, &self.member),
            },
            Some(ServerMessage::UnknownRequest { id, method }) => {
                Some(crate::client::peer::method_not_found(&id, &method))
            }
        };
        if let Some(reply) = reply {
            if self.outbox.len() < MAX_OUTBOX {
                self.outbox
                    .push_back(serde_json::to_vec(&reply).unwrap_or_default());
            }
            // The driver POSTs it; a call waiting on the link is woken to look again.
            woken.extend(self.waiters.values().next().copied());
        }
    }

    /// DRIVES the link on the driver ticket, its services numbered on from `issued` (the
    /// instance's one counter for this tick cycle): an idle stream let go, the replies it owes
    /// POSTed, and the stream dialled, its `GET` written, and its reply read until it pends or ends.
    fn drive(
        &mut self,
        (host, driver, now): (&Host, Ticket, u64),
        issued: &mut u32,
        grants: ServerRequestGrants,
        woken: &mut Vec<Ticket>,
        announced: &mut Announced,
    ) {
        if !self.idle() || self.last_used == 0 {
            self.last_used = now.max(1);
        } else if now.saturating_sub(self.last_used) > IDLE_NS {
            self.die(IDLE, woken);
        }
        self.post_replies(host, driver, issued);
        self.read_stream((host, driver), issued, grants, woken, announced);
        self.post_replies(host, driver, issued);
    }

    /// The connector for the next handle of the cycle, or none once the cycle's span is spent.
    fn next(host: &Host, driver: Ticket, issued: u32) -> Option<Connector<'_>> {
        (issued < CYCLE_SPAN).then(|| host.connector_from(driver, LINK_SEQ.saturating_add(issued)))
    }

    /// The stream: dialled, its `GET` written, and its reply read until it pends or ends.
    fn read_stream(
        &mut self,
        (host, driver): (&Host, Ticket),
        issued: &mut u32,
        grants: ServerRequestGrants,
        woken: &mut Vec<Ticket>,
        announced: &mut Announced,
    ) {
        while let Some(mut c) = Self::next(host, driver, *issued) {
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
                *issued += 1;
                self.stale.pop();
                continue;
            }
            if self.dead.is_some() {
                return;
            }
            match self.step {
                Step::Establish => {
                    let dialled = c.establish_as(
                        crate::door::NEED_UPSTREAM,
                        Some(&self.url),
                        "",
                        0,
                        Some(&self.member),
                    );
                    match dialled {
                        Poll::Pending => return,
                        Poll::Ready(Ok(stream)) => {
                            *issued += 1;
                            self.stream = Some(stream);
                            self.step = Step::Head;
                        }
                        Poll::Ready(Err(e)) => {
                            *issued += 1;
                            self.die(&e.to_string(), woken);
                        }
                    }
                }
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
                            *issued += 1;
                            self.step = if self.step == Step::Head {
                                Step::End
                            } else {
                                Step::Read
                            };
                        }
                        Poll::Ready(Err(e)) => {
                            *issued += 1;
                            self.die(&e.to_string(), woken);
                        }
                    }
                }
                Step::Read => {
                    let stream = self.stream.unwrap_or_default();
                    match c.read_reply(stream, &mut self.buf, &mut self.slot) {
                        Poll::Pending => return,
                        Poll::Ready(Ok(got)) => {
                            *issued += 1;
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
                                    self.events(&chunk, grants, woken, announced);
                                }
                                _ => self.die(STREAM_CLOSED, woken),
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            *issued += 1;
                            self.die(&e.to_string(), woken);
                        }
                    }
                }
            }
        }
    }

    /// THE REPLIES the link owes the server, POSTed one after another to the message address on the
    /// driver ticket, each service numbered on from `issued`; a dead stream owes nothing more.
    fn post_replies(&mut self, host: &Host, driver: Ticket, issued: &mut u32) {
        if self.dead.is_some() {
            self.outbox.clear();
            if let Some(stream) = self.replying.take().and_then(|r| r.stream) {
                self.stale.push(stream);
            }
            return;
        }
        let Some(address) = self.address.clone() else {
            return;
        };
        loop {
            if self.replying.is_none() {
                let Some(body) = self.outbox.pop_front() else {
                    return;
                };
                self.replying = Some(self.reply_to(&address, body));
            }
            let Some(mut c) = Self::next(host, driver, *issued) else {
                return;
            };
            let Some(r) = self.replying.as_mut() else {
                return;
            };
            let stream = r.stream.unwrap_or_default();
            // Each step is one service: PENDING leaves it for the next drive; anything else is
            // taken (a failed reply is let go: the stream itself says whether the server is there).
            let done = match r.step {
                ReplyStep::Establish => match c.establish_as(
                    crate::door::NEED_UPSTREAM,
                    Some(&address),
                    "",
                    0,
                    Some(&self.member),
                ) {
                    Poll::Pending => return,
                    Poll::Ready(Ok(s)) => {
                        r.stream = Some(s);
                        ReplyStep::Head
                    }
                    Poll::Ready(Err(_)) => ReplyStep::Close,
                },
                ReplyStep::Head => match c.write_request(stream, &r.head_piece, &r.head) {
                    Poll::Pending => return,
                    Poll::Ready(Ok(_)) => ReplyStep::Body,
                    Poll::Ready(Err(_)) => ReplyStep::Close,
                },
                ReplyStep::Body if r.sent >= r.body.len() => {
                    // Nothing left of the body: no service made.
                    r.step = ReplyStep::End;
                    continue;
                }
                ReplyStep::Body => {
                    match c.write_request(stream, &self.body_piece, &r.body[r.sent..]) {
                        Poll::Pending => return,
                        Poll::Ready(Ok(0) | Err(_)) => ReplyStep::Close,
                        Poll::Ready(Ok(n)) => {
                            r.sent = r.sent.saturating_add(n);
                            ReplyStep::Body
                        }
                    }
                }
                ReplyStep::End => match c.write_request(stream, &self.end_piece, &[]) {
                    Poll::Pending => return,
                    Poll::Ready(Ok(_)) => ReplyStep::Read,
                    Poll::Ready(Err(_)) => ReplyStep::Close,
                },
                ReplyStep::Read => match c.read_reply(stream, &mut self.buf, &mut self.slot) {
                    Poll::Pending => return,
                    Poll::Ready(Ok(got)) if matches!(got.piece.kind, REPLY_END | REPLY_ACK) => {
                        ReplyStep::Close
                    }
                    Poll::Ready(Ok(_)) => ReplyStep::Read,
                    Poll::Ready(Err(_)) => ReplyStep::Close,
                },
                ReplyStep::Close => {
                    if r.stream.is_some() && c.close(stream).is_pending() {
                        return;
                    }
                    if r.stream.is_some() {
                        *issued += 1;
                    }
                    self.replying = None;
                    continue;
                }
            };
            *issued += 1;
            r.step = done;
        }
    }

    /// The POST of `body` to the message address `address`.
    fn reply_to(&self, address: &str, body: Vec<u8>) -> Reply {
        let (head, head_piece) = head_of("POST", address, self.fields.iter());
        Reply {
            step: ReplyStep::Establish,
            stream: None,
            head,
            head_piece,
            body: body.into_boxed_slice(),
            sent: 0,
        }
    }
}

/// A request head (`method`, the path of `url`, then `fields`) and its descriptor.
fn head_of<'a>(
    method: &str,
    url: &str,
    named: impl Iterator<Item = &'a (String, String)>,
) -> (Box<[u8]>, Box<RequestPiece>) {
    let path = crate::call::path_of(url);
    let mut head = Vec::new();
    head.extend_from_slice(method.as_bytes());
    head.extend_from_slice(path.as_bytes());
    let block_at = head.len();
    for (name, value) in named {
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(fields::SEPARATOR);
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(fields::LINE_END);
    }
    let piece = RequestPiece {
        kind: REQUEST_HEAD,
        _reserved: 0,
        method: span(0, method.len()),
        target: span(method.len(), path.len()),
        fields: span(block_at, head.len() - block_at),
        timeout_ms: 0,
    };
    (head.into_boxed_slice(), Box::new(piece))
}

/// Wakes every call in `woken`.
fn wake_all(plane: &McpDoor, woken: Vec<Ticket>) {
    if let Some(wake) = plane.wake.as_ref() {
        for t in woken {
            wake.wake(t);
        }
    }
}

/// A span of `len` bytes at `offset`.
const fn span(offset: usize, len: usize) -> FrameSpan {
    FrameSpan {
        offset: offset as u64,
        len: len as u64,
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
/// waits on any more is let go. Every link's services are numbered by the instance's ONE counter
/// for the tick cycle, so no two links (and no link replaced or removed within the cycle) ever
/// issue the same handle.
pub(super) fn drive(instance: &Instance<'_, McpDoor>, plane: &McpDoor) {
    let Some(host) = plane.host.as_ref() else {
        return;
    };
    let driver = instance.ticket();
    let cycle = plane.driver.get(&()).map_or(0, |(_, now)| now);
    let mut issued = plane
        .legacy_seq
        .get(&())
        .filter(|(at, _)| *at == cycle)
        .map_or(0, |(_, n)| n);
    let held = plane.current();
    let grants_of = |member: &str| {
        held.as_ref()
            .and_then(|h| h.section.servers.get(member))
            .map(|d| d.grants.as_ask_grants())
            .unwrap_or_default()
    };
    let mut woken = Vec::new();
    let mut announced = Announced::new();
    plane.legacy.with_all(|m| {
        for link in m.values_mut() {
            let grants = grants_of(&link.member);
            link.drive(
                (host, driver, cycle),
                &mut issued,
                grants,
                &mut woken,
                &mut announced,
            );
        }
        m.retain(|_, l| {
            l.dead.is_none()
                || !l.stale.is_empty()
                || l.replying.is_some()
                || !l.waiters.is_empty()
                || !l.answers.is_empty()
        });
    });
    plane.legacy_seq.insert((), (cycle, issued));
    for (server, uri) in announced {
        super::door_sessions::announce(plane, &server, &uri);
    }
    wake_all(plane, woken);
}

/// `dropped` replies a call took from the stream of `key` but has no answer to audit them on: counted
/// on the stream again, for the next call's answer.
pub(super) fn recount(plane: &McpDoor, key: &str, dropped: u32) {
    if dropped == 0 {
        return;
    }
    plane.legacy.with(&key.to_string(), |l| {
        if let Some(l) = l {
            l.dropped = l.dropped.saturating_add(dropped).min(MAX_DROPPED_AUDITED);
        }
    });
}

/// The op on `ticket` was cancelled: no call waits there any more, an answer still to come for it
/// is a reply no call waits for, and one already read for it is dropped. A cancelled call that was
/// running the stream's `initialize` hands it back: the next call runs it, and the calls parked
/// behind it are woken to.
pub(super) fn cancelled(plane: &McpDoor, ticket: Ticket) {
    let woken = plane.legacy.with_all(|m| {
        let mut woken = Vec::new();
        for l in m.values_mut() {
            let gone: Vec<String> = l
                .waiters
                .iter()
                .filter(|(_, t)| **t == ticket)
                .map(|(id, _)| id.clone())
                .collect();
            for id in gone {
                l.waiters.remove(&id);
                l.notes.remove(&id);
            }
            l.answers.retain(|id, (t, _)| {
                let mine = *t == ticket;
                if mine {
                    l.notes.remove(id);
                }
                !mine
            });
            l.parked.retain(|t| *t != ticket);
            if l.init == Init::Running && l.init_by == Some(ticket) {
                l.init = Init::Idle;
                l.init_by = None;
                woken.append(&mut l.parked);
            }
        }
        woken
    });
    wake_all(plane, woken);
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

/// What a call came to: the answer under the id it carried (an event stream, its progress and the
/// link's log records ahead of the answer, when the server said any: the `bool`), the replies dropped
/// on its link since the last answer, or why it failed.
pub(super) type Called = Result<(Vec<u8>, bool, u64, u32), String>;

/// The answer `body`, with `frames` ahead of it as one event stream when there are any: `(bytes,
/// is an event stream)`.
fn framed_answer(body: Vec<u8>, frames: Vec<Value>) -> (Vec<u8>, bool) {
    if frames.is_empty() {
        return (body, false);
    }
    let Ok(answer) = serde_json::from_slice::<Value>(&body) else {
        return (body, false);
    };
    let out: String = frames
        .iter()
        .chain(std::iter::once(&answer))
        .map(|f| crate::adapt::frame(None, Some(crate::adapt::EVENT_MESSAGE), &f.to_string()))
        .collect();
    (out.into_bytes(), true)
}

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
        let now = plane.driver.get(&()).map_or(0, |(_, now)| now);
        let opened = plane.legacy.with_all(|m| {
            let usable = m.get(key).is_some_and(|l| l.dead.is_none());
            if !usable {
                // ADMISSION BOUNDS THE TABLE: past its bound an idle stream (no call on it) is let
                // go for this one; with none idle the call is refused, and no stream a call waits
                // on is closed for another.
                let live = m.values().filter(|l| l.dead.is_none()).count();
                if !m.contains_key(key) && live >= MAX_LINKS {
                    let mut woken = Vec::new();
                    match m.values_mut().find(|l| l.idle()) {
                        Some(idle) => idle.die(IDLE, &mut woken),
                        None => {
                            return Err(format!(
                                "MCP server `{member}`: busbar already holds {MAX_LINKS}                                  2024-11-05 event streams, each in use by a call, and opens no                                  more until one is let go"
                            ))
                        }
                    }
                }
                // A dead link's stream, and any it still had to close, are closed by its successor.
                let (generation, stale) = m.remove(key).map_or((1, Vec::new()), |old| {
                    let mut stale = old.stale;
                    stale.extend(old.stream);
                    stale.extend(old.replying.and_then(|r| r.stream));
                    (old.generation.saturating_add(1), stale)
                });
                let mut link = Link::new(generation, &original.url, member, original);
                link.stale = stale;
                m.insert(key.to_string(), link);
            }
            Ok(m.get_mut(key).map_or(0, |l| {
                if now != 0 {
                    l.last_used = now;
                }
                l.generation
            }))
        });
        let generation = match opened {
            Ok(generation) => generation,
            Err(why) => return Poll::Ready(Err(why)),
        };
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
                if let Some((_, body)) = l.answers.remove(&text) {
                    // The call's own progress, and the link's log records, ride its answer.
                    let mut frames = l.notes.remove(&text).unwrap_or_default();
                    frames.append(&mut l.logs);
                    return Next::Answered(body, frames, id, std::mem::take(&mut l.dropped));
                }
            }
            if let Some(why) = &l.dead {
                if let Some(id) = st.id {
                    l.waiters.remove(&Value::from(id).to_string());
                }
                return Next::Fail(why.clone());
            }
            let Some(address) = l.address.clone() else {
                l.parked.push(ticket);
                return Next::Wait;
            };
            match (l.init, st.init) {
                (Init::Idle, 0) => {
                    // This call runs the link's `initialize`: its answer is waited for under its id,
                    // registered before the POST leaves.
                    l.init = Init::Running;
                    l.init_by = Some(ticket);
                    l.waiters
                        .insert(Value::from(INITIALIZE_ID).to_string(), ticket);
                    Next::PostInit(address)
                }
                (Init::Running, 1) => {
                    let text = Value::from(INITIALIZE_ID).to_string();
                    match l.answers.remove(&text) {
                        Some((_, body)) => Next::Initialized(body),
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
                            if l.waiters.len() >= MAX_WAITING {
                                return Next::Fail(format!(
                                    "MCP server `{member}`: its 2024-11-05 event stream already \
                                     waits on {MAX_WAITING} calls"
                                ));
                            }
                            l.waiters.insert(Value::from(id).to_string(), ticket);
                            st.id = Some(id);
                            id
                        }
                    };
                    Next::PostCall(address, id)
                }
            }
        });
        match next {
            Next::Answered(body, frames, id, dropped) => {
                *state = None;
                let (body, sse) = framed_answer(body, frames);
                return Poll::Ready(Ok((body, sse, id, dropped)));
            }
            Next::Fail(why) => {
                *state = None;
                return Poll::Ready(Err(why));
            }
            Next::Wait => return Poll::Pending,
            Next::PostInit(address) => {
                let request =
                    initialize_request(original, &address, Revision::R2024_11_05, super::VERSION);
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
                                l.init_by = None;
                                std::mem::take(&mut l.parked)
                            })
                            .unwrap_or_default()
                        });
                        wake_all(plane, woken);
                    }
                    Poll::Ready(Err(why)) => return Poll::Ready(Err(fail_link(plane, key, &why))),
                }
            }
            Next::PostCall(address, id) => {
                let mut request =
                    lower_request(original, &address, Revision::R2024_11_05, None, Some(id));
                // A progress token the request carries names this call on the stream, so the
                // server's progress reaches this call and no other.
                if let Ok(mut body) = serde_json::from_slice::<Value>(&request.body) {
                    if let Some(token) = body
                        .pointer_mut("/params/_meta/progressToken")
                        .filter(|t| !t.is_null())
                    {
                        *token = Value::from(format!("{PROGRESS_PREFIX}{id}"));
                        if let Ok(bytes) = serde_json::to_vec(&body) {
                            request.body = bytes;
                        }
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
                                l.waiters.remove(&Value::from(id).to_string());
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
    Answered(Vec<u8>, Vec<Value>, u64, u32),
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
    wake_all(plane, woken);
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
        || super::door_sessions::exchange_request(request, timeout_ms),
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
