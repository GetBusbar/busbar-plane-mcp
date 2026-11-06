// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use std::collections::{BTreeMap, VecDeque};
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    ReplyPiece, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY,
    REQUEST_END, REQUEST_HEAD,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};
use busbar_contract::abi::sdk::completion_retirement::{Domain, Error, Handle, Retirement};
use busbar_contract::abi::sdk::conn::{Connector, Host};
use busbar_contract::abi::transport::{fields, FrameSpan};
use serde_json::Value;

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

/// The legacy handle namespace. Confirmed retirement recycles its slots.
const CYCLE_SPAN: u32 = 1 << 26;

#[derive(Debug, Default)]
pub(super) struct Driver {
    pub(super) retirement: Retirement,
    issued: u32,
    reusable: Vec<u32>,
    pub(super) retired_hosts: Vec<u32>,
    pub(super) cleanup_clock_seq: Option<u32>,
    pub(super) failure: Option<Error>,
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

    /// The SDK found no host slot, so no crossing or stored completion exists to retire.
    /// Only use for ServiceError::Unserved, never for a host refusal or failure.
    pub(super) fn host_unserved(&mut self, pending: &mut Option<CompletionHandle>) {
        if let Some(handle) = pending.take() {
            self.reusable.push(handle.seq);
        }
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

    pub(super) fn begin(
        &mut self,
        owner: HostCtx,
        ticket: Ticket,
        extensions: &[u8],
    ) -> Result<(), Error> {
        let reusable = self.retirement.begin(owner, ticket, extensions)?;
        self.retired_hosts = reusable
            .iter()
            .filter(|handle| handle.domain == Domain::Host)
            .map(|handle| handle.seq)
            .collect();
        // Observe the clock's acknowledgement even when no relays remain this cycle.
        if self
            .cleanup_clock_seq
            .is_some_and(|seq| self.retired_hosts.contains(&seq))
        {
            self.cleanup_clock_seq = None;
        }
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
    /// Woken calls that still need to consume this link's terminal cause.
    failed: Vec<Ticket>,
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
            failed: Vec::new(),
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
    /// [`MAX_WAITING`] calls.
    fn wait(&mut self, id: u64, ticket: Ticket) -> bool {
        if self.waiters.len() >= MAX_WAITING {
            return false;
        }
        self.waiters.insert(Value::from(id).to_string(), ticket);
        true
    }

    /// The stream is gone: every waiting call is woken to read why.
    fn die(&mut self, why: &str, woken: &mut Vec<Ticket>) {
        if self.dead.is_some() {
            return;
        }
        self.dead = Some(why.to_string());
        self.failed
            .extend(std::mem::take(&mut self.waiters).into_values());
        self.failed.append(&mut self.parked);
        woken.extend(self.failed.iter().copied());
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
            let Ok(v) = crate::codec::wire_json::parse_str(&event.data) else {
                self.die(
                    "the MCP server sent malformed JSON on its 2024-11-05 event stream",
                    woken,
                );
                break;
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
    /// only the protocol's housekeeping, and an ask it cannot carry to the caller is refused, never
    /// answered for the caller).
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
            } else {
                self.die(
                    "the MCP server exceeded the legacy reply queue limit",
                    woken,
                );
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
                &format!("the MCP server's retained 2024-11-05 notifications exceeded busbar's {max}-byte reply limit"),
                woken,
            );
            false
        } else {
            true
        }
    }

    /// DRIVES the link on the driver ticket, its services numbered on from `issued` (the
    /// instance's one counter for this tick cycle): an idle stream let go, the replies it owes
    /// POSTed, and the stream dialled, its `GET` written, and its reply read until it pends or ends.
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
        self.post_replies(host, driver, issued, woken);
        self.read_stream((host, driver), issued, grants, woken, announced);
        self.post_replies(host, driver, issued, woken);
        if self.dead.is_some() && !self.retiring() && self.answers.is_empty() {
            woken.append(&mut self.parked);
        }
    }

    /// Reserve the current operation's handle before invoking the host. A pending service owns
    /// it across links and ticks; a completed service clears it before starting its next step.
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
                                    let buffer = std::mem::take(&mut self.buf);
                                    self.events(&buffer[..got.len], grants, woken, announced);
                                    self.buf = buffer;
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
    /// driver ticket, each service numbered on from `issued`; a dead stream owes nothing more.
    fn post_replies(
        &mut self,
        host: &Host,
        driver: Ticket,
        issued: &mut Driver,
        woken: &mut Vec<Ticket>,
    ) {
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
        if self.outbox.is_empty() && self.replying.is_none() {
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

            let mut failed = false;
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
                    Poll::Ready(Err(_)) => {
                        failed = true;
                        ReplyStep::Close
                    }
                },
                ReplyStep::Head => match c.write_request(stream, &r.head_piece, &r.head) {
                    Poll::Pending => return,
                    Poll::Ready(Ok(_)) => ReplyStep::Body,
                    Poll::Ready(Err(_)) => {
                        failed = true;
                        ReplyStep::Close
                    }
                },
                ReplyStep::Body => {
                    match c.write_request(stream, &self.body_piece, &r.body[r.sent..]) {
                        Poll::Pending => return,
                        Poll::Ready(Ok(0) | Err(_)) => {
                            failed = true;
                            ReplyStep::Close
                        }
                        Poll::Ready(Ok(n)) => {
                            r.sent = r.sent.saturating_add(n);
                            ReplyStep::Body
                        }
                    }
                }
                ReplyStep::End => match c.write_request(stream, &self.end_piece, &[]) {
                    Poll::Pending => return,
                    Poll::Ready(Ok(_)) => ReplyStep::Read,
                    Poll::Ready(Err(_)) => {
                        failed = true;
                        ReplyStep::Close
                    }
                },
                ReplyStep::Read => match c.read_reply(stream, &mut r.buf, &mut r.slot) {
                    Poll::Pending => return,

                    Poll::Ready(Ok(got)) => match reply_step(&got.piece) {
                        Some(next) => next,
                        None => {
                            failed = true;
                            ReplyStep::Close
                        }
                    },
                    Poll::Ready(Err(_)) => {
                        failed = true;
                        ReplyStep::Close
                    }
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
            if failed {
                self.die(
                    "the MCP server failed to accept a legacy server-request reply POST",
                    woken,
                );
                return;
            }
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

/// A reply POST is delivered only after a successful final HTTP head.
fn reply_step(piece: &ReplyPiece) -> Option<ReplyStep> {
    if piece.kind == REPLY_HEAD && (piece.code >= 200 || piece.code == 101) {
        (200..300).contains(&piece.code).then_some(ReplyStep::Close)
    } else if matches!(piece.kind, REPLY_END | REPLY_ACK) {
        None
    } else {
        Some(ReplyStep::Read)
    }
}
