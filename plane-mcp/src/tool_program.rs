// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Stdio upstream servers: a `transport: stdio`

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::VecDeque;
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    ReplyPiece, REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::{Host, Replied};
use serde_json::Value;

use crate::client::jsonrpc::{ServerRequestGrants, HANDSHAKE_REQUEST_ID};
use crate::client::peer::{NotificationEffect, ServerMessage};

/// THE WORK BUDGET of one exchange: how many messages of its own a child may send while busbar
pub const MAX_INTERLEAVED_MESSAGES: u32 = 256;

/// The most host services one exchange makes (each read is one): past it the exchange fails
pub const EXCHANGE_SERVICES: u32 = 1 << 12;

/// How much one read of a child's messages asks for.
const READ_CHUNK: usize = 16 * 1024;

/// The most one message may grow to before the exchange fails (the exchange SDK's reply bound).
const MESSAGE_MAX: usize = busbar_contract::abi::sdk::exchange::REPLY_MAX;

/// The ids busbar's program exchanges carry: above every dispatch id and the handshake's, so none
const PROGRAM_IDS: u64 = 1 << 40;

/// Within [`PROGRAM_IDS`]: the `tools/list` exchanges.
const LIST_IDS: u64 = 1 << 39;

const _: () = assert!(PROGRAM_IDS > HANDSHAKE_REQUEST_ID);

/// The JSON-RPC id unit `unit`'s call carries on a child, round `round`: the unit's own, so two
#[must_use]
pub fn call_id(unit: u64, round: u32) -> Value {
    if unit <= u64::from(u32::MAX) && round <= 0x7F {
        Value::from(PROGRAM_IDS | (unit << 7) | u64::from(round))
    } else {
        Value::String(format!("busbar-call:unit:{unit}:{round}"))
    }
}

/// A unit's `tools/list` id. Existing numeric ids stay byte-for-byte the same when the complete
#[must_use]
pub fn unit_list_id(key: u64, n: u32) -> Value {
    if key <= u64::from(u32::MAX) && n <= 0x7F {
        Value::from(PROGRAM_IDS | LIST_IDS | (key << 7) | u64::from(n))
    } else {
        Value::String(format!("busbar-list:unit:{key}:{n}"))
    }
}

/// An operator's `tools/list` id, with its complete slot, generation and fetch. Its string
#[must_use]
pub fn list_id(key: u64, n: u32) -> Value {
    Value::String(format!(
        "busbar-list:ticket:{}:{}:{n}",
        key >> 32,
        key & 0xFFFF_FFFF
    ))
}

/// The sentence a child that ended its output mid-exchange fails the exchange with.
pub const CLOSED: &str = "stdio MCP child closed its stdout";

/// One message a child wrote: a JSON value, or bytes that are none (returned as an answer, never
/// judged here: the JSON-RPC reader owns that complaint).
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A JSON value.
    Value(Value),
    /// Not JSON at all.
    NotJson(Vec<u8>),
}

/// THE CHILD'S MESSAGES, out of its frames however the host's buffer cut them: whole JSON values,
/// back to back (the stdio framer hands each line without its newline). Each byte is scanned ONCE
/// for where a value ends (its nesting depth, outside strings) and a value is parsed only once it is
/// whole, so a message read in many pieces costs its size, never its size per piece: bounded work
/// on the worker.
#[derive(Debug, Default)]
pub struct Frames {
    buf: Vec<u8>,
    /// How far `buf` is scanned.
    seen: usize,
    /// Where the value being read starts in `buf`, once its first byte came.
    start: Option<usize>,
    depth: usize,
    in_string: bool,
    escaped: bool,
    overgrown: bool,
}

impl Frames {
    /// Take `bytes`; every message they complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Message> {
        if self.overgrown {
            return Vec::new();
        }
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut used = 0;
        while let Some(&b) = self.buf.get(self.seen) {
            let at = self.seen;
            self.seen += 1;
            let Some(start) = self.start else {
                match b {
                    b' ' | b'\t' | b'\r' | b'\n' => used = self.seen,
                    b'{' | b'[' => {
                        self.start = Some(at);
                        self.depth = 1;
                    }
                    _ => {
                        let rest = self.buf.split_off(at);
                        if rest.len() > MESSAGE_MAX {
                            self.overgrown = true;
                            self.buf.clear();
                            return Vec::new();
                        }
                        *self = Frames::default();
                        out.push(Message::NotJson(rest));
                        return out;
                    }
                }
                continue;
            };

            if self.seen - start > MESSAGE_MAX {
                self.overgrown = true;
                self.buf.clear();
                return Vec::new();
            }
            if self.in_string {
                match b {
                    _ if self.escaped => self.escaped = false,
                    b'\\' => self.escaped = true,
                    b'"' => self.in_string = false,
                    _ => {}
                }
                continue;
            }
            match b {
                b'"' => self.in_string = true,
                b'{' | b'[' => self.depth += 1,
                b'}' | b']' => {
                    self.depth -= 1;
                    if self.depth == 0 {
                        let whole = &self.buf[start..self.seen];
                        out.push(match serde_json::from_slice(whole) {
                            Ok(value) => Message::Value(value),
                            Err(_) => Message::NotJson(whole.to_vec()),
                        });
                        self.start = None;
                        used = self.seen;
                    }
                }
                _ => {}
            }
        }
        self.buf.drain(..used);
        self.seen -= used;
        self.start = self.start.map(|s| s - used);
        out
    }

    /// Whether a message exceeded [`MESSAGE_MAX`], including its completing piece.
    #[must_use]
    pub fn overgrown(&self) -> bool {
        self.overgrown || self.buf.len() > MESSAGE_MAX
    }
}

/// What an exchange needs of the door while it reads a child's own messages.
pub trait Peer {
    /// Validate the first host-generated program head and scope its generation to this peer.
    fn program_generation(
        &mut self,
        need: u32,
        member: &str,
        status: u32,
        fields: &[u8],
    ) -> Result<u64, String> {
        let _ = (need, member, status);
        Ok(generation_of(fields))
    }
    /// The member's grants, read now.
    fn grants(&self) -> ServerRequestGrants;
    /// Whether this exchange is the first to read the request `id` of the child of `generation`,
    fn claim(&mut self, generation: u64, id: &Value) -> bool;
    /// WHOSE the child's GRANTED ask `id` of `generation` is, fixed by the first exchange to read
    fn owner(&mut self, generation: u64, id: &Value) -> AskOwner;
    /// The child said its lists changed: verify-on-call is brought forward.
    fn notice(&mut self);
    /// The child announced that its resource `uri` changed (`notifications/resources/updated`):
    fn announced(&mut self, uri: &str) {
        let _ = uri;
    }

    /// Claim this generation's initialization, or wait for its current owner.
    fn greeting(&mut self, _: u64, _: Ticket) -> Poll<Greeting> {
        Poll::Ready(Greeting::Start(None))
    }

    /// Initialization finished before any subsequent tool exchange can fail.
    fn greeted(&mut self, _: u64) {}
}

/// Whether initialization is complete or this exchange owns its execution.
#[derive(Debug)]
pub enum Greeting {
    /// Another exchange already finished this generation's initialization.
    Done,
    /// This exchange initializes it; an owned claim is released on cancellation or failure.
    Start(Option<GreetingLease>),
}

/// A generation claim whose cancellation does not strand the exchanges waiting behind it.
pub struct GreetingLease {
    release: Option<Box<dyn FnOnce(bool) + Send + Sync>>,
}

impl std::fmt::Debug for GreetingLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GreetingLease").finish_non_exhaustive()
    }
}

impl GreetingLease {
    /// A claim completed with `true`, or released with `false` if dropped unfinished.
    pub fn new(release: impl FnOnce(bool) + Send + Sync + 'static) -> Self {
        Self {
            release: Some(Box::new(release)),
        }
    }

    fn finish(mut self) {
        if let Some(release) = self.release.take() {
            release(true);
        }
    }
}

impl Drop for GreetingLease {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release(false);
        }
    }
}

/// Whose one of a child's granted asks is, as the exchange reading it is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskOwner {
    /// The call relayed under this id: the call first in the child's line when the ask was first
    /// read. Its exchange takes the ask for its caller; every other passes it over.
    Call(Value),
    /// No call of the child's: this exchange read it first, and refuses it on the child's input.
    Refuse,
    /// No call of the child's, and an exchange that read it first refused it.
    Refused,
}

/// The call a child's ask belongs to. A request over stdio names no call it serves
pub fn first_in_line(
    line: impl IntoIterator<Item = (Value, u64)>,
    generation: u64,
) -> Option<Value> {
    let (call, on) = line.into_iter().next()?;
    (on == 0 || on == generation).then_some(call)
}

/// The audit word a child's ask that no call owns is refused under.
pub const UNATTRIBUTED: &str = "ask_unattributed";

/// ONE EXCHANGE'S READING of a child's messages: its answer by id, the replies it owes the child,
/// and the progress it relays.
#[derive(Debug, Default)]
pub struct Correlator {
    frames: Frames,
    interleaved: u32,
    /// The replies to the child's own requests, owed on its input, in order.
    pub outbox: VecDeque<Vec<u8>>,
    /// The progress frames carrying this exchange's token, in order.
    pub progress: Vec<Value>,
    /// This exchange relays a caller's call: a granted authority ask it reads is the caller's
    /// ([`Self::asks`]), never answered here.
    pub relays: bool,
    /// THE CHILD'S GRANTED ASKS this exchange took, in order, for busbar's caller to answer.
    pub asks: Vec<ChildAsk>,
}

/// One request of a child's own, for busbar's caller to answer: its id (the answer goes
/// back under it) and the request as the child sent it, less its envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct ChildAsk {
    /// The child's request id, verbatim.
    pub id: Value,
    /// `{method, params}`, verbatim: the `inputRequests` entry the caller is handed.
    pub request: Value,
}

/// THE CHILD'S ASKS AS THE CALLER IS HANDED THEM: an `input_required` result whose `inputRequests`
#[must_use]
pub fn relayed_asks(asks: &[ChildAsk]) -> (Value, Vec<(String, Value)>) {
    let mut requests = serde_json::Map::new();
    let mut keys = Vec::new();
    for ask in asks {
        let base = match &ask.id {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let mut key = base.clone();
        let mut n = 1;
        while requests.contains_key(&key) {
            n += 1;
            key = format!("{base}#{n}");
        }
        requests.insert(key.clone(), ask.request.clone());
        keys.push((key, ask.id.clone()));
    }
    let result = serde_json::json!({
            "resultType": crate::codec::RESULT_TYPE_INPUT_REQUIRED
    ,
            "inputRequests": Value::Object(requests),
        });
    (result, keys)
}

/// THE CALLER'S ANSWERS, AS THE CHILD IS WRITTEN THEM: one JSON-RPC response per request it asked,
#[must_use]
pub fn child_replies(child: &crate::ask::ChildLeg, responses: Option<&Value>) -> Vec<Vec<u8>> {
    child
        .asks
        .iter()
        .filter_map(|(key, id)| {
            let answer = responses?.get(key)?;
            Some(busbar_contract::jsonrpc::result_bytes(
                &crate::codec::json(id),
                &crate::codec::json(answer),
            ))
        })
        .collect()
}

impl Correlator {
    /// The reading of an exchange that relays a caller's call ([`Self::relays`]).
    #[must_use]
    pub fn relaying() -> Self {
        Correlator {
            relays: true,
            ..Correlator::default()
        }
    }

    /// Read `bytes` of member `member`'s messages (its child of `generation`), waiting for the
    pub fn take(
        &mut self,
        bytes: &[u8],
        wait: impl Into<Value>,
        member: &str,
        generation: u64,
        peer: &mut dyn Peer,
    ) -> Result<Option<Vec<u8>>, String> {
        let wait = wait.into();
        let mut answer = None;
        for message in self.frames.push(bytes) {
            let value = match message {
                Message::NotJson(raw) => {
                    answer.get_or_insert(raw);
                    continue;
                }
                Message::Value(value) => value,
            };
            if let Value::Array(messages) = value {
                for value in messages {
                    self.take_value(value, &wait, member, generation, peer, &mut answer)?;
                }
            } else {
                self.take_value(value, &wait, member, generation, peer, &mut answer)?;
            }
        }
        if self.frames.overgrown() {
            return Err(format!(
                "stdio MCP child wrote a message of more than {MESSAGE_MAX} bytes; \
                 the read is abandoned rather than grown to whatever the child chooses"
            ));
        }
        Ok(answer)
    }

    fn take_value(
        &mut self,
        value: Value,
        wait: &Value,
        member: &str,
        generation: u64,
        peer: &mut dyn Peer,
        answer: &mut Option<Vec<u8>>,
    ) -> Result<(), String> {
        let Some(own) = crate::client::peer::classify(&value) else {
            if value.is_object() && value.get("id") == Some(wait) {
                answer.get_or_insert_with(|| serde_json::to_vec(&value).unwrap_or_default());
            }
            return Ok(());
        };
        self.interleaved = self.interleaved.saturating_add(1);
        if self.interleaved > MAX_INTERLEAVED_MESSAGES {
            return Err(format!(
                "stdio MCP child sent more than {MAX_INTERLEAVED_MESSAGES} messages of its own \
                 while busbar waited for one answer; the exchange is abandoned rather than \
                 served at whatever rate the child chooses"
            ));
        }
        self.own(&value, own, (wait, generation), member, peer);
        Ok(())
    }

    /// One message of the child's own, handled.
    fn own(
        &mut self,
        value: &Value,
        message: ServerMessage,
        (wait, generation): (&Value, u64),
        member: &str,
        peer: &mut dyn Peer,
    ) {
        let reply = match message {
            ServerMessage::Notification(n) => {
                match n.effect() {
                    NotificationEffect::BringRefreshForward => peer.notice(),
                    NotificationEffect::RelayResourceUpdate => {
                        if let Some(uri) = value.pointer("/params/uri").and_then(Value::as_str) {
                            peer.announced(uri);
                        }
                    }
                    NotificationEffect::RelayProgress => {
                        let token = crate::client::jsonrpc::progress_token(wait);
                        if value
                            .pointer("/params/progressToken")
                            .and_then(Value::as_str)
                            == Some(token.as_str())
                        {
                            self.progress.push(value.clone());
                        }
                    }
                    NotificationEffect::Log => {}
                }
                None
            }
            ServerMessage::UnknownNotification(_) => None,

            ServerMessage::Request { id, verb }
                if verb.ask().is_some_and(|a| peer.grants().allows(a)) =>
            {
                match peer.owner(generation, &id) {
                    AskOwner::Call(call) if self.relays && *wait == call => {
                        let mut request = value.as_object().cloned().unwrap_or_default();
                        request.remove("jsonrpc");
                        request.remove("id");
                        self.asks.push(ChildAsk {
                            id,
                            request: Value::Object(request),
                        });
                        None
                    }
                    AskOwner::Refuse => {
                        let kind = verb.ask().map(|a| a.key()).unwrap_or_default();
                        Some(crate::client::peer::refused(
                            &id,
                            UNATTRIBUTED,
                            format!(
                                "server `{member}` asked for `{kind}` while busbar was relaying it \
                                 no call, and a request over stdio names no call it serves, so the \
                                 ask has no caller to go to; it is refused rather than put to \
                                 another caller."
                            ),
                        ))
                    }
                    AskOwner::Call(_) | AskOwner::Refused => None,
                }
            }
            ServerMessage::Request { id, verb } => peer
                .claim(generation, &id)
                .then(|| crate::client::peer::answer(&id, verb, &peer.grants(), member))
                .flatten(),
            ServerMessage::UnknownRequest { id, method } => peer
                .claim(generation, &id)
                .then(|| crate::client::peer::method_not_found(&id, &method)),
        };
        if let Some(reply) = reply {
            self.outbox
                .push_back(serde_json::to_vec(&reply).unwrap_or_default());
        }
    }
}

/// What a [`ProgramExchange`] came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchanged {
    /// The generation of the child it reached.
    pub generation: u64,
    /// The answer to its request, when it sent one.
    pub answer: Option<Vec<u8>>,
    /// It greeted the child (`initialize`): the generation is the door's now.
    pub greeted: bool,
}

/// Where a [`ProgramExchange`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Establish,
    Head,
    Greeting,
    Next,
    Write(Vec<u8>),
    Read,
    Close,
}

/// ONE EXCHANGE WITH A MEMBER'S CHILD over the door's own program need, parked across its op's
/// pending entries: open a lease on the member, read its head (the generation), greet a generation
/// the door has not greeted, write each message and read to each one's answer by id (answering the
/// child's own requests on the way), close the lease. Each host service is numbered on from the
/// exchange's base, so a pending one is re-issued under its own number and a completed one never
/// runs twice.
#[derive(Debug)]
pub struct ProgramExchange {
    member: String,
    need: u32,
    step: Step,
    issued: u32,
    service_limit: u32,
    stream: u64,
    buf: Box<[u8]>,
    slot: Box<ReplyPiece>,
    corr: Correlator,
    generation: u64,
    /// The messages still to send, each with the id whose answer it waits for.
    queue: VecDeque<(Vec<u8>, Option<Value>)>,
    /// The answer being waited for.
    waiting: Option<Value>,
    /// Write only on this generation (a reply owed to one child is never written to the next).
    only: Option<u64>,
    greet: bool,
    greeted: bool,
    greeting: Option<GreetingLease>,
    answer: Option<Vec<u8>>,
    failed: Option<String>,
    /// The bound the lease is opened under, milliseconds (`0` = the need's own): the host holds the
    /// exchange to it until the child first answers.
    timeout_ms: u32,
}

/// THE LEASE OPERATIONS AN EXCHANGE MAKES on its member's program: each is the host connector's
pub trait ProgramConn {
    /// Lease the member's program over `need`, its dial bounded by `timeout_ms`: the stream.
    fn establish(
        &self,
        ticket: Ticket,
        issued: u32,
        need: u32,
        member: &str,
        timeout_ms: u32,
    ) -> Poll<Result<u64, String>>;
    /// The next piece of the reply on `stream`, written into `buf`, its descriptor into `slot`.
    fn read_reply(
        &self,
        ticket: Ticket,
        issued: u32,
        stream: u64,
        buf: &mut [u8],
        slot: &mut ReplyPiece,
    ) -> Poll<Result<Replied, String>>;
    /// Write `bytes` to `stream`: how many the host took.
    fn write(
        &self,
        ticket: Ticket,
        issued: u32,
        stream: u64,
        bytes: &[u8],
    ) -> Poll<Result<usize, String>>;
    /// Close `stream`.
    fn close(&self, ticket: Ticket, issued: u32, stream: u64) -> Poll<()>;
}

impl ProgramConn for Host {
    fn establish(
        &self,
        ticket: Ticket,
        issued: u32,
        need: u32,
        member: &str,
        timeout_ms: u32,
    ) -> Poll<Result<u64, String>> {
        self.connector_from(ticket, issued)
            .establish_timed(need, Some(member), "", timeout_ms)
            .map(|r| r.map_err(|e| e.to_string()))
    }

    fn read_reply(
        &self,
        ticket: Ticket,
        issued: u32,
        stream: u64,
        buf: &mut [u8],
        slot: &mut ReplyPiece,
    ) -> Poll<Result<Replied, String>> {
        self.connector_from(ticket, issued)
            .read_reply(stream, buf, slot)
            .map(|r| r.map_err(|e| e.to_string()))
    }

    fn write(
        &self,
        ticket: Ticket,
        issued: u32,
        stream: u64,
        bytes: &[u8],
    ) -> Poll<Result<usize, String>> {
        self.connector_from(ticket, issued)
            .write(stream, bytes)
            .map(|r| r.map_err(|e| e.to_string()))
    }

    fn close(&self, ticket: Ticket, issued: u32, stream: u64) -> Poll<()> {
        self.connector_from(ticket, issued)
            .close(stream)
            .map(|_| ())
    }
}

impl ProgramExchange {
    /// An exchange with member `member` over need `need`: `messages` sent in order, each read to
    #[must_use]
    pub fn new(
        member: &str,
        need: u32,
        messages: Vec<(Vec<u8>, Option<u64>)>,
        greet: bool,
    ) -> Self {
        Self {
            member: member.to_string(),
            need,
            step: Step::Establish,
            issued: 0,
            service_limit: EXCHANGE_SERVICES,
            stream: 0,
            buf: vec![0; READ_CHUNK].into_boxed_slice(),
            slot: Box::default(),
            corr: Correlator::default(),
            generation: 0,
            queue: messages
                .into_iter()
                .map(|(bytes, id)| (bytes, id.map(Value::from)))
                .collect(),
            waiting: None,
            only: None,
            greet,
            greeted: false,
            greeting: None,
            answer: None,
            failed: None,
            timeout_ms: 0,
        }
    }

    /// A tool-list exchange retaining the exact string or numeric id across every pending entry.
    #[must_use]
    pub fn listing(member: &str, need: u32, id: Value, greet: bool) -> Self {
        Self::listing_page(member, need, id, greet, None)
    }

    /// One page of a tool-list exchange under its exact typed correlation id.
    #[must_use]
    pub fn listing_page(
        member: &str,
        need: u32,
        id: Value,
        greet: bool,
        cursor: Option<&str>,
    ) -> Self {
        let request = crate::client::jsonrpc::tools_list_page_id("", &id, None, cursor).body;
        let mut exchange = Self::new(member, need, Vec::new(), greet);
        exchange.queue.push_back((request, Some(id)));
        exchange
    }

    /// Opened under `timeout_ms`: the server's own `timeout:`.
    #[must_use]
    pub fn timed(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = u32::try_from(timeout_ms).unwrap_or(u32::MAX);
        self
    }

    /// Write only to the child of `generation`: on another, nothing is sent.
    #[must_use]
    pub fn only_on(mut self, generation: u64) -> Self {
        self.only = Some(generation);
        self
    }

    /// Restrict this exchange to the remainder of its caller's existing service range.
    #[must_use]
    pub fn within_services(mut self, remaining: u32) -> Self {
        self.service_limit = remaining.min(EXCHANGE_SERVICES);
        self
    }

    /// Completed services, including the cleanup CLOSE, consumed from that range.
    #[must_use]
    pub const fn services_used(&self) -> u32 {
        self.issued
    }

    /// Drive the exchange on `ticket`, its services numbered from `base`: READY with what it came
    pub fn drive(
        &mut self,
        host: &dyn ProgramConn,
        ticket: Ticket,
        base: u32,
        greeted: &dyn Fn(u64) -> bool,
        peer: &mut dyn Peer,
    ) -> Poll<Result<Exchanged, String>> {
        if self.step == Step::Establish
            && (self.service_limit < 2 || base.checked_add(self.service_limit - 1).is_none())
        {
            return Poll::Ready(Err(
                "the exchange with the stdio MCP child has no complete service range left".into(),
            ));
        }
        loop {
            if self.issued >= self.service_limit.saturating_sub(1)
                && !matches!(self.step, Step::Close | Step::Next | Step::Greeting)
            {
                self.failed.get_or_insert_with(|| {
                    "the exchange with the stdio MCP child passed its bound".to_string()
                });
                self.step = Step::Close;
                self.greeting = None;
            }
            let seq = base.saturating_add(self.issued);
            match self.step.clone() {
                Step::Establish => {
                    match host.establish(ticket, seq, self.need, &self.member, self.timeout_ms) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(stream)) => {
                            self.issued += 1;
                            self.stream = stream;
                            self.step = Step::Head;
                        }
                        Poll::Ready(Err(e)) => {
                            self.issued += 1;
                            return Poll::Ready(Err(e));
                        }
                    }
                }
                Step::Head => {
                    match host.read_reply(ticket, seq, self.stream, &mut self.buf, &mut self.slot) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(got)) => {
                            self.issued += 1;
                            if got.piece.kind != REPLY_HEAD {
                                self.fail(CLOSED.to_string());
                                continue;
                            }
                            let block = spanned(&self.buf[..got.len], got.piece.fields);
                            self.generation = match peer.program_generation(
                                self.need,
                                &self.member,
                                got.piece.code,
                                block,
                            ) {
                                Ok(generation) => generation,
                                Err(reason) => {
                                    self.fail(reason);
                                    continue;
                                }
                            };
                            if self.only.is_some_and(|g| g != self.generation) {
                                self.queue.clear();
                            }
                            self.step = Step::Greeting;
                        }
                        Poll::Ready(Err(e)) => {
                            self.issued += 1;
                            self.fail(e);
                        }
                    }
                }
                Step::Greeting => {
                    if self.greet && !greeted(self.generation) {
                        match peer.greeting(self.generation, ticket) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Greeting::Done) => {}
                            Poll::Ready(Greeting::Start(claim)) => {
                                self.greeting = claim;
                                self.queue.push_front((initialized_notification(), None));
                                self.queue.push_front((
                                    initialize(),
                                    Some(Value::from(HANDSHAKE_REQUEST_ID)),
                                ));
                            }
                        }
                    }
                    self.step = Step::Next;
                }
                Step::Next => {
                    if let Some(reply) = self.corr.outbox.pop_front() {
                        self.step = Step::Write(reply);
                    } else if self.waiting.is_some() {
                        self.step = Step::Read;
                    } else if let Some((message, wait)) = self.queue.pop_front() {
                        self.waiting = wait;
                        self.step = Step::Write(message);
                    } else {
                        self.step = Step::Close;
                    }
                }
                Step::Write(message) => match host.write(ticket, seq, self.stream, &message) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(_)) => {
                        self.issued += 1;
                        if message == initialized_notification() {
                            self.greeted = true;
                            self.completed_greeting(peer);
                        }
                        self.step = Step::Next;
                    }
                    Poll::Ready(Err(e)) => {
                        self.issued += 1;
                        self.fail(e);
                    }
                },
                Step::Read => {
                    match host.read_reply(ticket, seq, self.stream, &mut self.buf, &mut self.slot) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(got)) => {
                            self.issued += 1;
                            match got.piece.kind {
                                REPLY_BODY => {
                                    let wait = self.waiting.clone().unwrap_or(Value::Null);
                                    let taken = self.corr.take(
                                        &self.buf[..got.len],
                                        wait.clone(),
                                        &self.member,
                                        self.generation,
                                        peer,
                                    );
                                    match taken {
                                        Ok(Some(answer)) => {
                                            self.waiting = None;
                                            if wait.as_u64() == Some(HANDSHAKE_REQUEST_ID) {
                                                self.greeted(&answer);
                                                if self.greeted {
                                                    self.completed_greeting(peer);
                                                }
                                            } else {
                                                self.answer = Some(answer);
                                            }
                                            self.step = Step::Next;
                                        }
                                        Ok(None) => self.step = Step::Next,
                                        Err(e) => self.fail(e),
                                    }
                                }
                                REPLY_HEAD => self.fail(crate::program_trust::REPEATED.to_string()),
                                REPLY_END | REPLY_ACK => self.fail(CLOSED.to_string()),
                                _ => {}
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            self.issued += 1;
                            self.fail(e);
                        }
                    }
                }
                Step::Close => {
                    if host.close(ticket, seq, self.stream).is_pending() {
                        return Poll::Pending;
                    }
                    self.issued += 1;
                    if let Some(failed) = self.failed.take() {
                        return Poll::Ready(Err(failed));
                    }
                    return Poll::Ready(Ok(Exchanged {
                        generation: self.generation,
                        answer: self.answer.take(),
                        greeted: self.greeted,
                    }));
                }
            }
        }
    }

    /// The exchange failed: the lease is closed, and the failure is its answer.
    fn fail(&mut self, why: String) {
        self.failed.get_or_insert(why);
        self.greeting = None;
        self.step = Step::Close;
    }

    fn completed_greeting(&mut self, peer: &mut dyn Peer) {
        peer.greeted(self.generation);
        if let Some(claim) = self.greeting.take() {
            claim.finish();
        }
    }

    /// The handshake's answer: a result is acknowledged; a refusal (a child that does no handshake)
    fn greeted(&mut self, answer: &[u8]) {
        let accepted = matches!(
            crate::client::jsonrpc::parse_response(answer, HANDSHAKE_REQUEST_ID),
            crate::client::jsonrpc::RpcOutcome::Result(_)
        );
        if accepted {
            return;
        }
        self.queue.retain(|(m, _)| *m != initialized_notification());
        self.greeted = true;
    }
}

/// The bytes `span` names in `buf`.
fn spanned(buf: &[u8], span: busbar_contract::abi::transport::FrameSpan) -> &[u8] {
    let at = usize::try_from(span.offset).unwrap_or(usize::MAX);
    let len = usize::try_from(span.len).unwrap_or(0);
    buf.get(at..at.saturating_add(len)).unwrap_or(&[])
}

/// The generation a lease's head names; `0` when it names none.
#[must_use]
pub fn generation_of(block: &[u8]) -> u64 {
    busbar_contract::abi::transport::fields::lines(block)
        .find(|(n, _)| {
            n.eq_ignore_ascii_case(busbar_contract::conn::PROGRAM_GENERATION_FIELD.as_bytes())
        })
        .and_then(|(_, v)| std::str::from_utf8(v).ok()?.trim().parse().ok())
        .unwrap_or(0)
}

/// The handshake: `initialize`, under its own id.
#[must_use]
pub fn initialize() -> Vec<u8> {
    crate::client::verb::UpstreamVerb::Initialize {
        client_version: crate::plane_door::VERSION,
    }
    .build("", HANDSHAKE_REQUEST_ID, None)
    .body
}

/// The handshake's acknowledgement, a notification.
#[must_use]
pub fn initialized_notification() -> Vec<u8> {
    crate::client::verb::UpstreamVerb::NotificationsInitialized
        .build("", HANDSHAKE_REQUEST_ID, None)
        .body
}

#[cfg(test)]
#[path = "tests/tool_program.rs"]
mod tests;
