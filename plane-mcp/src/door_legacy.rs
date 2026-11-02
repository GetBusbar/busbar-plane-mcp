// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `2024-11-05` HTTP+SSE client rung, held: busbar reaches a registered

use std::collections::{BTreeMap, VecDeque};
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    ReplyPiece, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY,
    REQUEST_END, REQUEST_HEAD,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};
use busbar_contract::abi::plane::PlaneDriveOut;
use busbar_contract::abi::sdk::completion_retirement::{Domain, Error, Handle, Retirement};
use busbar_contract::abi::sdk::conn::{Connector, Host};
use busbar_contract::abi::sdk::{Instance, Out};
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
pub const STREAM_CLOSED: &str =
    "the MCP server's 2024-11-05 event stream closed before it answered this call";

/// The audit action a reply no call waited for is recorded under (rejected: it was never delivered).
pub const ACTION_REPLY_DROPPED: &str = "mcp_upstream.reply";

/// The most rejected `mcp_upstream.reply` rows one answer carries: replies dropped past it are
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

/// The existing legacy handle namespace. Confirmed retirement recycles its slots.
const CYCLE_SPAN: u32 = 1 << 26;

#[derive(Debug, Default)]
pub(super) struct Driver {
    retirement: Retirement,
    issued: u32,
    reusable: Vec<u32>,
    failure: Option<Error>,
}

impl Driver {
    fn reserve(&mut self) -> Option<u32> {
        if self.failure.is_some() || !self.retirement.can_consume(0) {
            return None;
        }
        self.reusable.pop().or_else(|| {
            if self.issued >= CYCLE_SPAN {
                return None;
            }
            let seq = LINK_SEQ + self.issued;
            self.issued += 1;
            Some(seq)
        })
    }

    /// Host and connector operations share the driver's confirmed-retirement namespace.
    pub(super) fn host_handle(
        &mut self,
        ticket: Ticket,
        pending: &mut Option<CompletionHandle>,
    ) -> Option<CompletionHandle> {
        if self.failure.is_some() {
            return None;
        }
        if let Some(handle) = *pending {
            if handle.ticket != ticket {
                self.failure = Some(Error::Invalid);
                return None;
            }
            return self.retirement.can_consume(0).then_some(handle);
        }
        let handle = super::handle_at(ticket, self.reserve()?);
        *pending = Some(handle);
        Some(handle)
    }

    /// Retire a terminal host result only after its caller copied and consumed it.
    pub(super) fn host_consumed(&mut self, pending: &mut Option<CompletionHandle>) -> bool {
        let Some(handle) = *pending else { return true };
        match self.retirement.consumed(Handle {
            domain: Domain::Host,
            seq: handle.seq,
        }) {
            Ok(()) => {
                *pending = None;
                true
            }
            Err(error) => {
                self.failure = Some(error);
                false
            }
        }
    }

    fn begin(&mut self, owner: HostCtx, ticket: Ticket, extensions: &[u8]) -> Result<(), Error> {
        let reusable = self.retirement.begin(owner, ticket, extensions)?;
        self.reusable
            .extend(reusable.into_iter().map(|handle| handle.seq));
        Ok(())
    }

    fn consumed(&mut self, pending: &mut Option<u32>) {
        if let Some(seq) = *pending {
            match self.retirement.consumed(Handle {
                domain: Domain::Connector,
                seq,
            }) {
                Ok(()) => *pending = None,
                Err(error) => self.failure = Some(error),
            }
        }
    }
}

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
    /// Its current service's reserved handle, retained until that service completes.
    handle: Option<u32>,
    buf: Box<[u8]>,
    slot: Box<ReplyPiece>,
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
    fields: Vec<(String, String)>,
    /// The connector's stream, once established.
    stream: Option<u64>,
    step: Step,
    /// Why the stream is gone, once it is.
    dead: Option<String>,
    /// Connector streams this key's earlier (dead) links held, still to close: a dropped stream
    stale: Vec<u64>,
    reader: EventReader,
    /// The message address, once the stream named an acceptable one.
    address: Option<String>,
    init: Init,
    /// The ticket of the call running `initialize`, while one is.
    init_by: Option<Ticket>,
    /// Answers read, by their id's JSON text, with the ticket of the call they are for, until it
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
    notes_bytes: BTreeMap<String, usize>,
    logs_bytes: usize,
    /// The tick clock a call last used the link at (`0`: not yet stamped).
    last_used: u64,
    buf: Box<[u8]>,
    slot: Box<ReplyPiece>,
    handle: Option<u32>,
}

/// What a drive heard that the instance acts on outside the link's lock.
enum Announcement {
    Resource(String, String),
    ListChanged(String),
}

type Announced = Vec<Announcement>;

impl Link {
    fn new(generation: u64, url: &str, member: &str, template: &OutboundRequest) -> Self {
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
            notes_bytes: BTreeMap::new(),
            logs_bytes: 0,
            last_used: 0,
            buf: vec![0; READ_CHUNK].into_boxed_slice(),
            slot: Box::default(),
            handle: None,
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

    fn retiring(&self) -> bool {
        self.stream.is_some()
            || self.handle.is_some()
            || !self.stale.is_empty()
            || self.replying.is_some()
    }

    /// Registers the call on `ticket` as waiting for `id`: `false` when the link already waits on
    fn wait(&mut self, id: u64, ticket: Ticket) -> bool {
        if self.waiters.len() >= MAX_WAITING {
            return false;
        }
        self.waiters.insert(Value::from(id).to_string(), ticket);
        true
    }

    /// The stream is gone: every waiting call is woken to read why.
    fn die(&mut self, why: &str, woken: &mut Vec<Ticket>) {
        if self.dead.is_none() {
            self.dead = Some(why.to_string());
        }
        woken.extend(std::mem::take(&mut self.waiters).into_values());
        self.answers.remove(&INITIALIZE_ID.to_string());
        self.init_by = None;
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
            if self.dead.is_some() {
                break;
            }

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
                self.peer_message(&v, event.data.len(), grants, woken, announced);
            } else if let Some(id) = v.get("id").map(Value::to_string) {
                if let Some(t) = self.waiters.remove(&id) {
                    self.answers.insert(id, (t, event.data.into_bytes()));
                    woken.push(t);
                } else {
                    self.dropped = self.dropped.saturating_add(1).min(MAX_DROPPED_AUDITED);
                }
            }
        }
        if self.reader.overflowed() {
            self.die(
                &format!("the MCP server's 2024-11-05 event exceeded busbar's {MAX_EVENT}-byte event limit"),
                woken,
            );
        }
    }

    /// One message of the server's own, routed as the other rungs route it (busbar answers
    fn peer_message(
        &mut self,
        v: &Value,
        encoded_bytes: usize,
        grants: ServerRequestGrants,
        woken: &mut Vec<Ticket>,
        announced: &mut Announced,
    ) {
        let reply = match crate::client::peer::classify(v) {
            Some(ServerMessage::Notification(n)) => {
                match n.effect() {
                    NotificationEffect::RelayResourceUpdate => {
                        if let Some(uri) = v.pointer("/params/uri").and_then(Value::as_str) {
                            announced
                                .push(Announcement::Resource(self.member.clone(), uri.to_string()));
                        }
                    }

                    NotificationEffect::RelayProgress => {
                        let id = v
                            .pointer("/params/progressToken")
                            .and_then(Value::as_str)
                            .and_then(|t| t.strip_prefix(PROGRESS_PREFIX))
                            .filter(|id| self.waiters.contains_key(*id))
                            .map(str::to_string);
                        if let Some(id) = id {
                            if self
                                .notes
                                .get(&id)
                                .is_none_or(|notes| notes.len() < MAX_NOTES)
                                && self.keep_note(encoded_bytes, woken)
                            {
                                *self.notes_bytes.entry(id.clone()).or_default() += encoded_bytes;
                                self.notes.entry(id).or_default().push(v.clone());
                            }
                        }
                    }
                    NotificationEffect::Log
                        if n == ServerNotification::Message && self.logs.len() < MAX_NOTES =>
                    {
                        if self.keep_note(encoded_bytes, woken) {
                            self.logs_bytes += encoded_bytes;
                            self.logs.push(v.clone());
                        }
                    }
                    NotificationEffect::BringRefreshForward => {
                        announced.push(Announcement::ListChanged(self.member.clone()));
                    }
                    NotificationEffect::Log => {}
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

            woken.extend(self.waiters.values().next().copied());
        }
    }

    fn keep_note(&mut self, bytes: usize, woken: &mut Vec<Ticket>) -> bool {
        let used = self
            .notes_bytes
            .values()
            .copied()
            .sum::<usize>()
            .saturating_add(self.logs_bytes);
        let max = busbar_contract::abi::sdk::exchange::REPLY_MAX;
        if used.saturating_add(bytes) > max {
            self.die(
                &format!("the MCP server's retained 2024-11-05 notifications exceeded busbar's existing {max}-byte reply limit"),
                woken,
            );
            false
        } else {
            true
        }
    }

    /// DRIVES the link on the driver ticket, its services numbered on from `issued` (the
    fn drive(
        &mut self,
        (host, driver, now): (&Host, Ticket, u64),
        issued: &mut Driver,
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
        if self.dead.is_some() && !self.retiring() && self.answers.is_empty() {
            woken.append(&mut self.parked);
        }
    }

    /// Reserve the current operation's handle before invoking the host. A pending service owns
    fn next<'h>(
        host: &'h Host,
        driver: Ticket,
        issued: &mut Driver,
        pending: &mut Option<u32>,
    ) -> Option<Connector<'h>> {
        if issued.failure.is_some() || !issued.retirement.can_consume(0) {
            return None;
        }
        let seq = match *pending {
            Some(seq) => seq,
            None => {
                let seq = issued.reserve()?;
                *pending = Some(seq);
                seq
            }
        };
        Some(host.connector_from(driver, seq))
    }

    /// The stream: dialled, its `GET` written, and its reply read until it pends or ends.
    fn read_stream(
        &mut self,
        (host, driver): (&Host, Ticket),
        issued: &mut Driver,
        grants: ServerRequestGrants,
        woken: &mut Vec<Ticket>,
        announced: &mut Announced,
    ) {
        loop {
            if self.dead.is_some()
                && self.stream.is_none()
                && self.step == Step::Establish
                && self.handle.is_some()
            {
                let Some(mut c) = Self::next(host, driver, issued, &mut self.handle) else {
                    return;
                };
                match c.establish_as(
                    crate::statement::NEED_UPSTREAM,
                    Some(&self.url),
                    "",
                    0,
                    Some(&self.member),
                ) {
                    Poll::Pending => return,
                    Poll::Ready(answer) => {
                        issued.consumed(&mut self.handle);
                        self.stream = answer.ok();
                    }
                }
            }

            if self.dead.is_some() {
                if let Some(stream) = self.stream {
                    if host.connector(Ticket::NONE).close(stream).is_pending() {
                        return;
                    }
                    if self.handle.is_some() {
                        let Some(mut c) = Self::next(host, driver, issued, &mut self.handle) else {
                            return;
                        };
                        let pending = match self.step {
                            Step::Head => c
                                .write_request(stream, &self.head_piece, &self.head)
                                .is_pending(),
                            Step::End => c.write_request(stream, &self.end_piece, &[]).is_pending(),
                            Step::Read => c
                                .read_reply(stream, &mut self.buf, &mut self.slot)
                                .is_pending(),
                            Step::Establish => false,
                        };
                        if pending {
                            return;
                        }
                        issued.consumed(&mut self.handle);
                    }
                    self.stream = None;
                }
            }
            if let Some(&stream) = self.stale.last() {
                if host.connector(Ticket::NONE).close(stream).is_pending() {
                    return;
                }
                self.stale.pop();
                continue;
            }
            if self.dead.is_some() {
                return;
            }
            let Some(mut c) = Self::next(host, driver, issued, &mut self.handle) else {
                return;
            };
            match self.step {
                Step::Establish => {
                    let dialled = c.establish_as(
                        crate::statement::NEED_UPSTREAM,
                        Some(&self.url),
                        "",
                        0,
                        Some(&self.member),
                    );
                    match dialled {
                        Poll::Pending => return,
                        Poll::Ready(Ok(stream)) => {
                            issued.consumed(&mut self.handle);
                            self.stream = Some(stream);
                            self.step = Step::Head;
                        }
                        Poll::Ready(Err(e)) => {
                            issued.consumed(&mut self.handle);
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
                            issued.consumed(&mut self.handle);
                            self.step = if self.step == Step::Head {
                                Step::End
                            } else {
                                Step::Read
                            };
                        }
                        Poll::Ready(Err(e)) => {
                            issued.consumed(&mut self.handle);
                            self.die(&e.to_string(), woken);
                        }
                    }
                }
                Step::Read => {
                    let stream = self.stream.unwrap_or_default();
                    match c.read_reply(stream, &mut self.buf, &mut self.slot) {
                        Poll::Pending => return,
                        Poll::Ready(Ok(got)) => {
                            issued.consumed(&mut self.handle);
                            match got.piece.kind {
                                REPLY_HEAD => {
                                    let block = spanned(&self.buf[..got.len], got.piece.fields);
                                    let streams = fields::lines(block).any(|(n, v)| {
                                        n.eq_ignore_ascii_case(b"content-type")
                                            && v.split(|b| *b == b';').next().is_some_and(|mime| {
                                                mime.trim_ascii().eq_ignore_ascii_case(
                                                    crate::framing::EVENT_STREAM.as_bytes(),
                                                )
                                            })
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
                            issued.consumed(&mut self.handle);
                            self.die(&e.to_string(), woken);
                        }
                    }
                }
            }
        }
    }

    /// THE REPLIES the link owes the server, POSTed one after another to the message address on the
    fn post_replies(&mut self, host: &Host, driver: Ticket, issued: &mut Driver) {
        if self.dead.is_some() {
            self.outbox.clear();
            if let Some(r) = self.replying.as_mut() {
                if r.stream.is_none() && r.handle.is_some() {
                    let Some(address) = self.address.as_deref() else {
                        return;
                    };
                    let Some(mut c) = Self::next(host, driver, issued, &mut r.handle) else {
                        return;
                    };
                    match c.establish_as(
                        crate::statement::NEED_UPSTREAM,
                        Some(address),
                        "",
                        0,
                        Some(&self.member),
                    ) {
                        Poll::Pending => return,
                        Poll::Ready(answer) => {
                            issued.consumed(&mut r.handle);
                            r.stream = answer.ok();
                        }
                    }
                }

                if let Some(stream) = r.stream {
                    if host.connector(Ticket::NONE).close(stream).is_pending() {
                        return;
                    }
                    if r.handle.is_some() {
                        let Some(mut c) = Self::next(host, driver, issued, &mut r.handle) else {
                            return;
                        };
                        let pending = match r.step {
                            ReplyStep::Head => {
                                c.write_request(stream, &r.head_piece, &r.head).is_pending()
                            }
                            ReplyStep::Body => c
                                .write_request(stream, &self.body_piece, &r.body[r.sent..])
                                .is_pending(),
                            ReplyStep::End => {
                                c.write_request(stream, &self.end_piece, &[]).is_pending()
                            }
                            ReplyStep::Read => {
                                c.read_reply(stream, &mut r.buf, &mut r.slot).is_pending()
                            }
                            ReplyStep::Close => c.close(stream).is_pending(),
                            ReplyStep::Establish => false,
                        };
                        if pending {
                            return;
                        }
                        issued.consumed(&mut r.handle);
                    }
                }
            }
            self.replying = None;
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
            let Some(r) = self.replying.as_mut() else {
                return;
            };
            if r.step == ReplyStep::Body && r.sent >= r.body.len() {
                r.step = ReplyStep::End;
            }
            if r.step == ReplyStep::Close && r.stream.is_none() {
                self.replying = None;
                continue;
            }
            let Some(mut c) = Self::next(host, driver, issued, &mut r.handle) else {
                return;
            };
            let stream = r.stream.unwrap_or_default();

            let done = match r.step {
                ReplyStep::Establish => match c.establish_as(
                    crate::statement::NEED_UPSTREAM,
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
                ReplyStep::Read => match c.read_reply(stream, &mut r.buf, &mut r.slot) {
                    Poll::Pending => return,

                    Poll::Ready(Ok(got))
                        if got.piece.kind == REPLY_HEAD
                            && (got.piece.code >= 200 || got.piece.code == 101) =>
                    {
                        ReplyStep::Close
                    }
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
                    issued.consumed(&mut r.handle);
                    self.replying = None;
                    continue;
                }
            };
            issued.consumed(&mut r.handle);
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
            handle: None,
            buf: vec![0; READ_CHUNK].into_boxed_slice(),
            slot: Box::default(),
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

/// Whether streams or child-work cleanup need maintenance on the instance's driver.
pub(super) fn any(plane: &McpDoor) -> bool {
    !plane.legacy.is_empty()
        || !plane.relays.is_empty()
        || plane.legacy_seq.with_all(|state| {
            state
                .get(&())
                .is_some_and(|driver| driver.retirement.queued())
        })
}

/// THE DRIVER'S PART, on the instance's driver ticket (`drive`): every held stream read as far as
pub(super) fn drive(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    owner: HostCtx,
    extensions: &[u8],
) -> Result<bool, Error> {
    if !any(plane) {
        return Ok(false);
    }
    let Some(host) = plane.host.as_ref() else {
        return Ok(false);
    };
    let driver = instance.ticket();
    let cycle = plane.driver.get(&()).map_or(0, |(_, now)| now);
    let held = plane.current();
    let grants_of = |member: &str| {
        held.as_ref()
            .and_then(|h| h.section.servers.get(member))
            .map(|d| d.grants)
            .unwrap_or_default()
    };
    let mut woken = Vec::new();
    let mut announced = Announced::new();
    let result = plane.legacy_seq.with_all(|states| {
        let state = states.entry(()).or_default();
        state.begin(owner, driver, extensions)?;
        plane.legacy.with_all(|m| {
            for link in m.values_mut() {
                let grants = grants_of(&link.member);
                link.drive(
                    (host, driver, cycle),
                    state,
                    grants,
                    &mut woken,
                    &mut announced,
                );
            }
            m.retain(|_, l| {
                l.dead.is_none() || l.retiring() || !l.waiters.is_empty() || !l.answers.is_empty()
            });
        });
        let cleanup_pending = super::door_relay_cleanup::drive(plane, driver, state);
        if let Some(error) = state.failure {
            return Err(error);
        }
        Ok(pending(plane) || cleanup_pending || state.retirement.queued())
    });
    for announcement in announced {
        match announcement {
            Announcement::Resource(server, uri) => {
                super::door_sessions::announce(plane, &server, &uri)
            }
            Announcement::ListChanged(server) => super::door_sessions::list_changed(
                plane,
                &server,
                (cycle != 0).then_some(cycle / 1_000_000),
            ),
        }
    }
    wake_all(plane, woken);
    result
}

pub(super) fn acknowledge(
    plane: &McpDoor,
    out: &mut Out<'_, PlaneDriveOut>,
) -> Result<bool, Error> {
    plane.legacy_seq.with_all(|states| {
        let Some(state) = states.get_mut(&()) else {
            return Ok(false);
        };

        if let Some(ack) = state.retirement.acknowledgement(0)? {
            out.completion_ack(&plane.inspection_leases, &ack)?;
        }
        Ok(state.retirement.queued())
    })
}

fn pending(plane: &McpDoor) -> bool {
    plane.legacy.with_all(|links| {
        links.values().any(|link| {
            link.handle.is_some()
                || link
                    .replying
                    .as_ref()
                    .is_some_and(|reply| reply.handle.is_some())
        })
    })
}

/// `dropped` replies a call took from the stream of `key` but has no answer to audit them on: counted
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
                l.notes_bytes.remove(&id);
            }
            l.answers.retain(|id, (t, _)| {
                let mine = *t == ticket;
                if mine {
                    l.notes.remove(id);
                    l.notes_bytes.remove(id);
                }
                !mine
            });
            l.parked.retain(|t| *t != ticket);
            if l.init == Init::Running && l.init_by == Some(ticket) {
                l.init = Init::Idle;
                l.init_by = None;
                woken.append(&mut l.parked);
            }
            if l.dead.is_some() && l.answers.is_empty() {
                woken.append(&mut l.parked);
            }
        }
        woken
    });
    wake_all(plane, woken);
}

/// The initialization work owned by one call, retained before a POST can pend.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum CallInit {
    #[default]
    Waiting,
    Posting,
    Answer,
    Notifying,
    Done,
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
    /// This call's owned initialization phase, including a pending first POST.
    init: CallInit,
}

/// What a call came to: the answer under the id it carried (an event stream, its progress and the
pub(super) type Called = Result<(Vec<u8>, bool, u64, u32), String>;

/// The answer `body`, with `frames` ahead of it as one event stream when there are any: `(bytes,
fn framed_answer(body: Vec<u8>, frames: Vec<Value>) -> (Vec<u8>, bool) {
    if frames.is_empty() {
        return (body, false);
    }

    match crate::framing::event_stream(&body, &frames) {
        Some(stream) => (stream, true),
        None => (body, false),
    }
}

/// A CALL OVER THE HELD STREAM of `key` (a member and a caller binding), on the call's own ticket:
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
        let mut retired = Vec::new();
        let opened = plane.legacy.with_all(|m| {
            if let Some(link) = m.get_mut(key).filter(|link| link.url != original.url) {
                link.die(
                    "the registered MCP endpoint changed; this legacy stream is no longer used",
                    &mut retired,
                );
            }
            if let Some(previous) = m
                .get_mut(key)
                .filter(|link| link.dead.is_some() && (!link.answers.is_empty() || link.retiring()))
            {
                if !previous.parked.contains(&ticket) {
                    previous.parked.push(ticket);
                }
                return Ok(None);
            }
            let usable = m.get(key).is_some_and(|l| l.dead.is_none());
            if !usable {
                let live = m.values().filter(|l| l.dead.is_none()).count();
                if !m.contains_key(key) && live >= MAX_LINKS {
                    let mut woken = Vec::new();
                    match m.values_mut().find(|l| l.idle()) {
                        Some(idle) => idle.die(IDLE, &mut woken),
                        None => {
                            return Err(format!(
                                "MCP server `{member}`: busbar already holds {MAX_LINKS} \
                                 2024-11-05 event streams, each in use by a call, and opens no \
                                 more until one is let go"
                            ));
                        }
                    }
                }

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
            Ok(m.get_mut(key).map(|l| {
                if now != 0 {
                    l.last_used = now;
                }
                l.generation
            }))
        });
        wake_all(plane, retired);
        let generation = match opened {
            Ok(Some(generation)) => generation,
            Ok(None) => {
                super::door_listen::wake_driver(plane);
                return Poll::Pending;
            }
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
        let next = plane.legacy.with(&key.to_string(), |l| {
            let Some(l) = l.filter(|l| l.generation == st.generation) else {
                return Next::Fail(STREAM_CLOSED.to_string());
            };
            if let Some(id) = st.id {
                let text = Value::from(id).to_string();
                if let Some((_, body)) = l.answers.remove(&text) {
                    let mut frames = l.notes.remove(&text).unwrap_or_default();
                    l.notes_bytes.remove(&text);
                    frames.append(&mut l.logs);
                    l.logs_bytes = 0;
                    let woken = if l.dead.is_some() && l.answers.is_empty() {
                        std::mem::take(&mut l.parked)
                    } else {
                        Vec::new()
                    };
                    return Next::Answered(body, frames, id, std::mem::take(&mut l.dropped), woken);
                }
            }
            if let Some(why) = &l.dead {
                if let Some(id) = st.id {
                    l.waiters.remove(&Value::from(id).to_string());
                }
                return Next::Fail(why.clone());
            }
            let Some(address) = l.address.clone() else {
                if !l.parked.contains(&ticket) {
                    l.parked.push(ticket);
                }
                return Next::Wait;
            };
            match (l.init, st.init) {
                (Init::Idle, CallInit::Waiting) => {
                    l.init = Init::Running;
                    l.init_by = Some(ticket);
                    st.init = CallInit::Posting;
                    l.waiters
                        .insert(Value::from(INITIALIZE_ID).to_string(), ticket);
                    Next::PostInit(address)
                }
                (Init::Running, CallInit::Posting) if l.init_by == Some(ticket) => {
                    Next::PostInit(address)
                }
                (Init::Running, CallInit::Answer) if l.init_by == Some(ticket) => {
                    let text = Value::from(INITIALIZE_ID).to_string();
                    match l.answers.remove(&text) {
                        Some((_, body)) => Next::Initialized(body),
                        None => Next::Wait,
                    }
                }
                (Init::Running, CallInit::Notifying) if l.init_by == Some(ticket) => {
                    Next::PostInitialized(address)
                }
                (Init::Running, _) | (Init::Idle, _) => {
                    if !l.parked.contains(&ticket) {
                        l.parked.push(ticket);
                    }
                    Next::Wait
                }
                (Init::Done, _) if st.posted => Next::Wait,
                (Init::Done, _) => {
                    let id = match st.id {
                        Some(id) => id,
                        None => {
                            let id = l.next_id;
                            l.next_id = l.next_id.saturating_add(1);
                            if !l.wait(id, ticket) {
                                return Next::Fail(format!(
                                    "MCP server `{member}`: its 2024-11-05 event stream already \
                                     waits on {MAX_WAITING} calls"
                                ));
                            }
                            st.id = Some(id);
                            id
                        }
                    };
                    Next::PostCall(address, id)
                }
            }
        });
        match next {
            Next::Answered(body, frames, id, dropped, woken) => {
                wake_all(plane, woken);
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
                    Poll::Ready(Ok(())) => st.init = CallInit::Answer,
                    Poll::Ready(Err(why)) => {
                        *state = None;
                        return Poll::Ready(Err(fail_link(plane, key, &why)));
                    }
                }
            }
            Next::Initialized(body) => {
                if let crate::client::jsonrpc::RpcOutcome::Error { code, message } =
                    crate::client::jsonrpc::parse_response(&body, INITIALIZE_ID)
                {
                    let why = format!(
                        "MCP server `{member}` refused legacy `initialize` with JSON-RPC {code}: {}",
                        message.escape_debug()
                    );
                    *state = None;
                    return Poll::Ready(Err(fail_link(plane, key, &why)));
                }
                if offered_revision(&body) != Some(Revision::R2024_11_05) {
                    let why = format!(
                        "MCP server `{member}` answered `initialize` on its 2024-11-05 event \
                         stream with a revision busbar does not carry there"
                    );
                    *state = None;
                    return Poll::Ready(Err(fail_link(plane, key, &why)));
                }
                st.init = CallInit::Notifying;
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
                        st.init = CallInit::Done;
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
                    Poll::Ready(Err(why)) => {
                        *state = None;
                        return Poll::Ready(Err(fail_link(plane, key, &why)));
                    }
                }
            }
            Next::PostCall(address, id) => {
                let request =
                    lower_request(original, &address, Revision::R2024_11_05, None, Some(id));
                plane.legacy.with(&key.to_string(), |link| {
                    if let Some(link) = link.filter(|link| link.generation == st.generation) {
                        link.fields.clone_from(&request.headers);
                    }
                });
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
    Answered(Vec<u8>, Vec<Value>, u64, u32, Vec<Ticket>),
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

#[cfg(test)]
#[path = "tests/legacy_link_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/relay_cleanup_regressions.rs"]
mod relay_cleanup_tests;
