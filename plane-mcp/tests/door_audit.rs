// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ROW 159 DOOR FINDINGS, THROUGH THE DOOR: verify-on-call never reads a failed clock as the
//! epoch (P-M4); the operator `connect` reaches every server verify-on-call reaches and a failed one
//! blocks nothing (A-H1); a line the unit cap refuses moves nothing on its carrier session (A-M3);
//! a name the routing key cannot spell is refused at validate (P-M11).
//!
//! The host and its upstreams are the stand-ins `sessions.rs` drives the door under, with a clock
//! that can be made to fail and one upstream that is down.

#![allow(unsafe_code, dead_code)]

use std::collections::{HashMap, VecDeque};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::host::conn::connector::{
    ConnectorSlots, EstablishIn, ReplyIn, ReplyPiece, RequestIn, RequestPiece, StreamIn,
    REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY, REQUEST_HEAD, SERVICES as CONN_SERVICES,
};
use busbar_contract::abi::host::service::{
    ClockNowIn, HostSlots, RandomFillIn, ServiceOut, DISTRUST_NONE, ENTITLED,
    SERVICES as HOST_SERVICES, TRUST_NEW,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, OutHead, Outcome, RawOutcome, BLOB_OCTETS, FLAG_RESUME,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, DriveIn, OpenIn, OpenOut, OpsHead, TickIn, TickOut,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, Ops, OutField, PlaneDriveIn, PlaneDriveOut,
    PlaneOpenIn, PlaneOpenOut, RecordWrite, ServeIn, ServeOut, UnitCount, AUDIT_REJECTED,
    EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS,
    PIECE_LAST, RECORD_AUDIT,
};
use busbar_contract::abi::transport::FrameSpan;
use busbar_plane_mcp::{door, tool_door};
use serde_json::{json, Value};

// ── the host's services ─────────────────────────────────────────────────────────────────────────

fn answer(out: *mut ServiceOut, outcome: Outcome, value: u64, len: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(outcome),
            value,
            len,
            ..ServiceOut::ZERO
        });
    }
    RawOutcome::of(outcome)
}

/// The host's monotonic clock: it moves a second on every reading.
static MONO: AtomicU64 = AtomicU64::new(1_000_000_000);

/// While set, the host's clock read FAILS.
static CLOCK_FAILS: AtomicBool = AtomicBool::new(false);

/// The clock failing for as long as it is held.
struct ClockFails;

impl ClockFails {
    fn on() -> Self {
        CLOCK_FAILS.store(true, Ordering::SeqCst);
        ClockFails
    }
}

impl Drop for ClockFails {
    fn drop(&mut self) {
        CLOCK_FAILS.store(false, Ordering::SeqCst);
    }
}

extern "C" fn clock_now(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    if CLOCK_FAILS.load(Ordering::SeqCst) {
        return answer(out, Outcome::Failed, 0, 0);
    }
    // SAFETY: the SDK hands a `ClockNowIn` whose reading slot it owns.
    let i = unsafe { input.cast::<ClockNowIn>().read() };
    let mono = MONO.fetch_add(1_000_000_000, Ordering::SeqCst);
    // SAFETY: as above.
    unsafe {
        (*i.reading).wall_ns = 1_800_000_000_000_000_000 + mono;
        (*i.reading).mono_ns = mono;
    }
    answer(out, Outcome::Ready, 0, 0)
}

extern "C" fn entitled(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, ENTITLED, 0)
}

/// Every fill differs from the last: a counter, spelled into the buffer.
static FILLS: AtomicU64 = AtomicU64::new(0);

extern "C" fn random_fill(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `RandomFillIn` over its own buffer.
    let i = unsafe { input.cast::<RandomFillIn>().read() };
    let n = FILLS.fetch_add(1, Ordering::SeqCst) + 1;
    let len = usize::try_from(i.len).expect("a small fill");
    // SAFETY: the SDK's buffer of `cap >= len` bytes.
    let buf = unsafe { std::slice::from_raw_parts_mut(i.into.buf, i.into.cap) };
    for (k, b) in buf.iter_mut().take(len).enumerate() {
        *b = (n as u8).wrapping_mul(31).wrapping_add(k as u8) | 1;
    }
    answer(out, Outcome::Ready, 0, i.len)
}

extern "C" fn serves(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, DISTRUST_NONE, 0)
}

extern "C" fn sighted(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, TRUST_NEW, 0)
}

static HOST_SLOTS: HostSlots = HostSlots {
    size: std::mem::size_of::<HostSlots>() as u32,
    slots: HOST_SERVICES,
    clock_now: Some(clock_now),
    records_get: None,
    records_list: None,
    records_claim: None,
    dest_judge: None,
    sign: None,
    unit_nest: None,
    work_open: None,
    work_find: None,
    work_settle: None,
    work_resume: None,
    trust_sight: Some(sighted),
    trust_due: None,
    verify_lookup: None,
    verify_store: None,
    entitlement_check: Some(entitled),
    content_scan: None,
    hook_call: None,
    random_fill: Some(random_fill),
    need_admit: None,
    trust_verify: None,
    records_secret: None,
    disk_append: None,
    snapshot_read: None,
    trust_sight_item: Some(sighted),
    trust_serves: Some(serves),
    trust_decide: None,
    trust_state: None,
    session_emit: None,
    auth_call: None,
    unit_hand_in: None,
    unit_refuse: None,
};

// ── the upstreams behind the connector ──────────────────────────────────────────────────────────

/// The upstream that requires a session.
const SESSION_URL: &str = "https://up.example/sess";
/// The upstream that speaks the stateless revision.
const STATELESS_URL: &str = "https://up.example/st";
/// The session the session upstream names.
const UPSTREAM_SESSION: &str = "up-session-1";

/// One request an upstream received over the connector.
#[derive(Debug, Clone)]
struct Seen {
    url: String,
    fields: Vec<(String, String)>,
    body: Value,
}

/// One reply an upstream writes: its status, its head fields and its body.
type Reply = (u32, Vec<(String, String)>, Vec<u8>);

/// One open exchange: where it goes, what it sent so far, and its reply once the request ended.
#[derive(Default)]
struct Wire {
    url: String,
    method: String,
    head: Vec<(String, String)>,
    body: Vec<u8>,
    reply: Option<Reply>,
    step: u8,
    /// A `2024-11-05` event stream this wire is (the legacy upstream's `GET`).
    sse: Option<Sse>,
}

/// One legacy event stream: its session, the events not yet read, the call answers the upstream
/// holds back, and whether it ended.
#[derive(Default)]
struct Sse {
    session: String,
    events: VecDeque<Vec<u8>>,
    held: Vec<Vec<u8>>,
    closed: bool,
}

#[derive(Default)]
struct Upstreams {
    next: u64,
    open: HashMap<u64, Wire>,
    seen: Vec<Seen>,
    /// The legacy upstream holds its `tools/call` answers until the test releases them.
    hold_calls: bool,
}

static UPSTREAMS: Mutex<Option<Upstreams>> = Mutex::new(None);

fn upstreams() -> MutexGuard<'static, Option<Upstreams>> {
    UPSTREAMS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn field_of<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn rpc_result(id: &Value, result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": result})).unwrap()
}

const JSON_TYPE: (&str, &str) = ("content-type", "application/json");

fn json_head() -> Vec<(String, String)> {
    vec![(JSON_TYPE.0.to_string(), JSON_TYPE.1.to_string())]
}

/// The upstream that speaks only the `2024-11-05` event stream.
const LEGACY_URL: &str = "https://up.example/legacy";
/// The message address its stream names, before the session's token.
const LEGACY_MESSAGES: &str = "/legacy/messages?session=";

/// One event on a legacy stream.
fn sse_event(name: &str, data: &str) -> Vec<u8> {
    format!("event: {name}\ndata: {data}\n\n").into_bytes()
}

/// What the legacy upstream answers a message POSTed in its session, on the stream: `None` for a
/// notification. A call's answer echoes the `path` it was asked for.
fn legacy_answer(body: &Value) -> Option<Vec<u8>> {
    let id = body.get("id").cloned()?;
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "legacy", "version": "1"},
        }),
        "tools/list" => {
            json!({"tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]})
        }
        "tools/call" => {
            let path = body
                .pointer("/params/arguments/path")
                .and_then(Value::as_str)
                .unwrap_or("");
            json!({"content": [{"type": "text", "text": format!("legacy {path}")}]})
        }
        _ => return None,
    };
    Some(sse_event(
        "message",
        &serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "result": result})).unwrap(),
    ))
}

/// THE LEGACY UPSTREAM, at the end of a request on wire `id`: a `GET` of the endpoint opens an
/// event stream naming its message address; a POST to that address is `202` and its answer goes on
/// the stream (a `tools/call`'s held back while the test holds them); any other POST is `405`.
fn legacy_request(ups: &mut Upstreams, id: u64) {
    let wire = ups.open.get_mut(&id).expect("the wire");
    if wire.method == "GET" {
        let session = format!("s{id}");
        let endpoint = sse_event("endpoint", &format!("{LEGACY_MESSAGES}{session}"));
        wire.sse = Some(Sse {
            session,
            events: VecDeque::from([endpoint]),
            ..Sse::default()
        });
        return;
    }
    let Some(session) = wire.url.split(LEGACY_MESSAGES).nth(1).map(str::to_string) else {
        wire.reply = Some((405, Vec::new(), b"Method Not Allowed".to_vec()));
        return;
    };
    wire.reply = Some((202, Vec::new(), Vec::new()));
    let body: Value = serde_json::from_slice(&wire.body).unwrap_or(Value::Null);
    let call = body.get("method").and_then(Value::as_str) == Some("tools/call");
    let hold = ups.hold_calls && call;
    if let Some(answer) = legacy_answer(&body) {
        if let Some(sse) = ups
            .open
            .values_mut()
            .filter_map(|w| w.sse.as_mut())
            .find(|s| s.session == session)
        {
            if hold {
                sse.held.push(answer);
            } else {
                sse.events.push_back(answer);
            }
        }
    }
}

/// The legacy streams open now, by session, in the order they opened.
fn legacy_sessions() -> Vec<String> {
    let ups = upstreams();
    let mut open: Vec<(u64, String)> = ups
        .as_ref()
        .map(|u| {
            u.open
                .iter()
                .filter_map(|(id, w)| w.sse.as_ref().map(|s| (*id, s.session.clone())))
                .collect()
        })
        .unwrap_or_default();
    open.sort();
    open.into_iter().map(|(_, s)| s).collect()
}

/// Run `f` over legacy session `session`'s stream.
fn on_stream(session: &str, f: impl FnOnce(&mut Sse)) {
    let mut ups = upstreams();
    let sse = ups
        .as_mut()
        .and_then(|u| {
            u.open
                .values_mut()
                .filter_map(|w| w.sse.as_mut())
                .find(|s| s.session == session)
        })
        .expect("the stream is open");
    f(sse);
}

/// The upstream that is down: every request is answered `503`.
const DOWN_URL: &str = "https://up.example/down";

/// What an upstream answers one request.
fn upstream_answer(url: &str, fields: &[(String, String)], body: &Value) -> Reply {
    if url.starts_with(DOWN_URL) {
        return (503, Vec::new(), b"down".to_vec());
    }
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let tools = json!({"tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]});
    if url.starts_with(STATELESS_URL) {
        return match method {
            "tools/list" => (200, json_head(), rpc_result(&id, tools)),
            "tools/call" => (
                200,
                json_head(),
                rpc_result(
                    &id,
                    json!({"content": [{"type": "text", "text": "stateless"}], "resultType": "complete"}),
                ),
            ),
            _ => (404, Vec::new(), b"no such method".to_vec()),
        };
    }
    if method == "initialize" {
        let mut head = json_head();
        head.push(("mcp-session-id".to_string(), UPSTREAM_SESSION.to_string()));
        let asked = body
            .pointer("/params/protocolVersion")
            .cloned()
            .unwrap_or(Value::Null);
        let result = json!({
            "protocolVersion": asked,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "up", "version": "1"},
        });
        return (200, head, rpc_result(&id, result));
    }
    if field_of(fields, "mcp-session-id") != Some(UPSTREAM_SESSION) {
        return (
            400,
            json_head(),
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Bad Request: no valid session ID"}}"#
                .to_vec(),
        );
    }
    match method {
        "notifications/initialized" => (202, Vec::new(), Vec::new()),
        "tools/list" => (200, json_head(), rpc_result(&id, tools)),
        "tools/call" => (
            200,
            json_head(),
            rpc_result(
                &id,
                json!({"content": [{"type": "text", "text": "in-session"}]}),
            ),
        ),
        _ => (404, Vec::new(), Vec::new()),
    }
}

fn span(buf: &[u8], s: FrameSpan) -> &[u8] {
    let at = usize::try_from(s.offset).unwrap();
    &buf[at..at + usize::try_from(s.len).unwrap()]
}

extern "C" fn establish(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands an `EstablishIn`.
    let i = unsafe { input.cast::<EstablishIn>().read() };
    // SAFETY: the SDK's target text, live for the call.
    let url = unsafe { std::slice::from_raw_parts(i.target.ptr(), i.target.len()) };
    let url = String::from_utf8_lossy(url).into_owned();
    let mut ups = upstreams();
    let ups = ups.get_or_insert_with(Upstreams::default);
    ups.next += 1;
    let id = ups.next;
    ups.open.insert(
        id,
        Wire {
            url,
            ..Wire::default()
        },
    );
    answer(out, Outcome::Ready, id, 0)
}

extern "C" fn write_request(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `RequestIn` over its own bytes and descriptor.
    let i = unsafe { input.cast::<RequestIn>().read() };
    // SAFETY: as above.
    let (bytes, piece) = unsafe {
        (
            std::slice::from_raw_parts(i.buf, i.len),
            i.piece.cast::<RequestPiece>().read(),
        )
    };
    let mut ups = upstreams();
    let ups = ups.get_or_insert_with(Upstreams::default);
    let Some(wire) = ups.open.get_mut(&i.stream) else {
        return answer(out, Outcome::Failed, 0, 0);
    };
    match piece.kind {
        REQUEST_HEAD => {
            wire.method = String::from_utf8_lossy(span(bytes, piece.method)).into_owned();
            let block = String::from_utf8_lossy(span(bytes, piece.fields)).into_owned();
            wire.head = block
                .split("\r\n")
                .filter_map(|l| l.split_once(": "))
                .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
                .collect();
        }
        REQUEST_BODY => wire.body.extend_from_slice(bytes),
        _ if wire.url.starts_with(LEGACY_URL) => {
            let body: Value = serde_json::from_slice(&wire.body).unwrap_or(Value::Null);
            let seen = Seen {
                url: wire.url.clone(),
                fields: wire.head.clone(),
                body,
            };
            ups.seen.push(seen);
            legacy_request(ups, i.stream);
        }
        _ => {
            let body: Value = serde_json::from_slice(&wire.body).unwrap_or(Value::Null);
            wire.reply = Some(upstream_answer(&wire.url, &wire.head, &body));
            let seen = Seen {
                url: wire.url.clone(),
                fields: wire.head.clone(),
                body,
            };
            ups.seen.push(seen);
        }
    }
    answer(out, Outcome::Ready, 0, i.len as u64)
}

extern "C" fn read_reply(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `ReplyIn` over its own buffer and descriptor slot.
    let i = unsafe { input.cast::<ReplyIn>().read() };
    // SAFETY: as above.
    let buf = unsafe { std::slice::from_raw_parts_mut(i.buf, i.len) };
    let mut ups = upstreams();
    let ups = ups.get_or_insert_with(Upstreams::default);
    let Some(wire) = ups.open.get_mut(&i.stream) else {
        return answer(out, Outcome::Failed, 0, 0);
    };
    // A LEGACY EVENT STREAM: its head, then each event as it is there, PENDING while none is, and
    // its end once it closed.
    if let Some(sse) = wire.sse.as_mut() {
        let (piece, n) = if wire.step == 0 {
            let block = "content-type: text/event-stream\r\n";
            buf[..block.len()].copy_from_slice(block.as_bytes());
            (
                ReplyPiece {
                    kind: REPLY_HEAD,
                    code: 200,
                    fields: FrameSpan {
                        offset: 0,
                        len: block.len() as u64,
                    },
                    ..ReplyPiece::default()
                },
                block.len(),
            )
        } else if let Some(event) = sse.events.pop_front() {
            buf[..event.len()].copy_from_slice(&event);
            (
                ReplyPiece {
                    kind: REPLY_BODY,
                    ..ReplyPiece::default()
                },
                event.len(),
            )
        } else if sse.closed {
            (
                ReplyPiece {
                    kind: REPLY_END,
                    ..ReplyPiece::default()
                },
                0,
            )
        } else {
            return answer(out, Outcome::Pending, 0, 0);
        };
        wire.step = wire.step.saturating_add(1);
        // SAFETY: the SDK's descriptor slot.
        unsafe { i.piece.write(piece) };
        return answer(out, Outcome::Ready, 0, n as u64);
    }
    let Some((status, head, body)) = wire.reply.clone() else {
        return answer(out, Outcome::Failed, 0, 0);
    };
    let (piece, n) = match wire.step {
        0 => {
            let block: String = head.iter().map(|(n, v)| format!("{n}: {v}\r\n")).collect();
            buf[..block.len()].copy_from_slice(block.as_bytes());
            (
                ReplyPiece {
                    kind: REPLY_HEAD,
                    code: status,
                    fields: FrameSpan {
                        offset: 0,
                        len: block.len() as u64,
                    },
                    ..ReplyPiece::default()
                },
                block.len(),
            )
        }
        1 if !body.is_empty() => {
            buf[..body.len()].copy_from_slice(&body);
            (
                ReplyPiece {
                    kind: REPLY_BODY,
                    ..ReplyPiece::default()
                },
                body.len(),
            )
        }
        _ => (
            ReplyPiece {
                kind: REPLY_END,
                ..ReplyPiece::default()
            },
            0,
        ),
    };
    wire.step = if wire.step == 0 && body.is_empty() {
        2
    } else {
        wire.step + 1
    };
    // SAFETY: the SDK's descriptor slot.
    unsafe { i.piece.write(piece) };
    answer(out, Outcome::Ready, 0, n as u64)
}

extern "C" fn close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `StreamIn`.
    let i = unsafe { input.cast::<StreamIn>().read() };
    if let Some(ups) = upstreams().as_mut() {
        ups.open.remove(&i.stream);
    }
    answer(out, Outcome::Ready, 0, 0)
}

static CONN_SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: CONN_SERVICES,
    establish: Some(establish),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: None,
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: Some(close),
    random: None,
    identity: None,
    read_reply: Some(read_reply),
    write_request: Some(write_request),
};

struct Tables(HostTables);
// SAFETY: the tables name only `'static` tables of `extern "C"` functions.
unsafe impl Sync for Tables {}

static TABLES: Tables = Tables(HostTables {
    size: std::mem::size_of::<HostTables>() as u32,
    _reserved: 0,
    ctx: HostCtx::NONE,
    wake: None,
    conns: &CONN_SLOTS,
    io: std::ptr::null(),
    services: &HOST_SLOTS,
});

/// One test at a time: the upstreams are the process's.
static SERIAL: Mutex<()> = Mutex::new(());

// ── the door, op by op ──────────────────────────────────────────────────────────────────────────

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { std::mem::zeroed() }
}

fn str_of(s: &str) -> AbiStr {
    // SAFETY: the test's own bytes, which outlive the call each `in` is built for.
    unsafe { AbiStr::from_raw_parts(s.as_ptr(), s.len()) }
}

fn octets(b: &[u8]) -> Blob {
    // SAFETY: the test's own bytes, which outlive the call each `in` is built for.
    unsafe { Blob::from_raw_parts(b.as_ptr(), b.len(), BLOB_OCTETS, 0) }
}

fn head<T>(op: u32, ticket: Ticket) -> InHead {
    InHead {
        size: std::mem::size_of::<T>() as u32,
        op,
        ticket,
        ..z()
    }
}

fn out_head<T>() -> OutHead {
    OutHead {
        size: std::mem::size_of::<T>() as u32,
        ..z()
    }
}

fn ops() -> &'static Ops {
    // SAFETY: the door is a `'static` table whose ops are the plane kind's.
    unsafe { &*(*tool_door::door()).ops.cast::<Ops>() }
}

fn lifecycle() -> &'static OpsHead {
    &ops().head
}

/// One opened instance of the door.
struct Door {
    instance: *mut c_void,
}

/// The section: a registration that requires a session, and one that speaks the stateless revision.
const SECTION: &str = r#"{
    "fs": {"url": "https://up.example/sess", "pin": {"mechanism": "unpinned"}, "verify_ttl": "1h", "tools_allow": {"read_file": {}}},
    "st": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "verify_ttl": "1h", "tools_allow": {"read_file": {}}, "resources_allow": {"file:///readme": {"name": "readme", "text": "hi"}}}
}"#;

fn open() -> Door {
    open_with(SECTION)
}

/// The section with one registration that speaks only the `2024-11-05` event stream.
const LEGACY_SECTION: &str = r#"{
    "lg": {"url": "https://up.example/legacy", "pin": {"mechanism": "unpinned"}, "verify_ttl": "1h", "tools_allow": {"read_file": {}}}
}"#;

/// The instance's driver ticket, as the kernel lends it.
const DRIVER: Ticket = Ticket {
    slot: u32::MAX - 1,
    generation: 1,
};

/// The tick clock, on from every earlier tick.
static TICKS: AtomicU64 = AtomicU64::new(1);

fn open_with(section: &str) -> Door {
    let mut i: PlaneOpenIn = z();
    i.open = OpenIn {
        head: head::<PlaneOpenIn>(life::OPEN, Ticket::NONE),
        host: &TABLES.0,
        settings: octets(section.as_bytes()),
        generation: 1,
        ..z()
    };
    i.public_url = str_of("https://busbar.example");
    let mut o: PlaneOpenOut = z();
    o.open = OpenOut {
        head: out_head::<PlaneOpenOut>(),
        ..z()
    };
    let f = lifecycle().open.expect("the door opens");
    // SAFETY: the slot is the door's own, called with an in and an out of the types it declares.
    #[allow(unused_unsafe)]
    let ret = unsafe {
        f(
            std::ptr::null_mut(),
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    assert_eq!(ret.outcome(), Outcome::Ready, "the door opens");
    Door {
        instance: o.open.instance,
    }
}

/// What `arrive` answered: its outcome and, refused, the status the refusal wears.
#[derive(Debug)]
struct Arrived {
    outcome: Outcome,
    refusal_status: u32,
}

fn claim(verb: &str) -> u32 {
    let i = door::ROUTES
        .iter()
        .position(|r| r.verb == verb && r.target == "/mcp" && r.carrier == "http")
        .expect("the door routes it");
    u32::try_from(i).unwrap()
}

impl Door {
    /// The kernel's tick, on the driver ticket.
    fn tick(&self) {
        let now = TICKS.fetch_add(1, Ordering::Relaxed);
        let i = TickIn {
            head: head::<TickIn>(life::TICK, DRIVER),
            now_ns: now,
        };
        let mut o = TickOut {
            head: out_head::<TickOut>(),
            next_tick_ns: 0,
        };
        let f = lifecycle().tick.expect("tick");
        // SAFETY: the slot is the door's own, called with an in and an out of the types it declares.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        assert_eq!(ret.outcome(), Outcome::Ready);
    }

    /// The driver ticket woke: `drive`.
    fn drive(&self) {
        let mut sessions = [0_u64; 16];
        let i = PlaneDriveIn {
            drive: DriveIn {
                head: head::<PlaneDriveIn>(life::DRIVE, DRIVER),
                driver: DRIVER,
            },
            sessions_buf: sessions.as_mut_ptr(),
            sessions_cap: sessions.len(),
        };
        let mut o: PlaneDriveOut = z();
        o.head = out_head::<PlaneDriveOut>();
        let f = lifecycle().drive.expect("drive");
        // SAFETY: the slot is the door's own, called with an in and an out of the types it declares.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        assert_eq!(ret.outcome(), Outcome::Ready);
    }

    /// A tick and the drive it wakes: every held stream read as far as it goes.
    fn turn(&self) {
        self.tick();
        self.drive();
    }

    /// `unit`'s piece re-called (as the kernel does when the door wakes its ticket) while it pends,
    /// the driver turning between: what it came to.
    fn pump(&self, unit: u64, given: &Given<'_>) -> Answered {
        for _ in 0..32 {
            let got = self.piece(unit, given);
            if got.outcome != Some(Outcome::Pending) {
                return got;
            }
            self.turn();
        }
        panic!("unit {unit} never stopped pending");
    }

    fn arrive(
        &self,
        unit: u64,
        verb: &str,
        target: &str,
        body: &[u8],
        fields: &[(&str, &str)],
    ) -> Arrived {
        let fields: Vec<Field> = fields
            .iter()
            .map(|(n, v)| Field {
                name: str_of(n),
                value: str_of(v),
            })
            .collect();
        let mut i: ArriveIn = z();
        i.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
        i.unit = unit;
        i.claim = claim(verb);
        i.target = str_of(target);
        i.method = str_of(verb);
        i.body = octets(body);
        (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
        let mut units = [z::<UnitCount>(); 8];
        (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
        let mut o: ArriveOut = z();
        o.head = out_head::<ArriveOut>();
        let f = ops().arrive.expect("arrive");
        // SAFETY: the slot is the door's own, called with an in and an out of the types it declares.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        Arrived {
            outcome: ret.outcome(),
            refusal_status: o.refusal_status,
        }
    }

    /// One piece of `unit`, re-called while the door says `more`: the outcome, the status, the
    /// head fields, the bytes, whether the bytes went to the far end, and the request line.
    fn piece(&self, unit: u64, given: &Given<'_>) -> Answered {
        let ticket = Ticket {
            slot: u32::try_from(unit).unwrap(),
            generation: 1,
        };
        let head_fields: Vec<Field> = given
            .head
            .iter()
            .map(|(n, v)| Field {
                name: str_of(n),
                value: str_of(v),
            })
            .collect();
        let mut reply = vec![0_u8; 1 << 16];
        let mut fields = [z::<OutField>(); 16];
        let mut arena = vec![0_u8; 1 << 14];
        let mut records = [z::<RecordWrite>(); 16];
        let mut units = [z::<UnitCount>(); 8];
        let mut got = Answered::default();
        let mut first = true;
        for _ in 0..64 {
            let mut i: OnPieceIn = z();
            i.head = head::<OnPieceIn>(slot::ON_PIECE, ticket);
            i.unit = unit;
            i.from = given.from;
            i.stream = given.stream;
            i.caller_ref = str_of(given.caller);
            if first {
                i.flags = given.flags;
                i.bytes = octets(given.bytes);
                i.status_code = given.status;
                i.attempt_no = given.attempt;
                i.member = str_of(given.member);
                (i.head_fields, i.head_fields_len) = (head_fields.as_ptr(), head_fields.len());
            } else {
                i.bytes = octets(b"");
            }
            (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
            (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
            (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
            (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
            (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
            let mut o: OnPieceOut = z();
            o.head = out_head::<OnPieceOut>();
            let f = ops().on_piece.expect("on_piece");
            // SAFETY: the slot is the door's own, called with an in and an out of the types it declares.
            #[allow(unused_unsafe)]
            let ret = unsafe {
                f(
                    self.instance,
                    std::ptr::from_ref(&i).cast(),
                    std::ptr::from_mut(&mut o).cast(),
                )
            };
            first = false;
            got.outcome = Some(ret.outcome());
            if o.reply_status != 0 {
                got.status = o.reply_status;
            }
            let at = |s: busbar_contract::abi::mechanism::call::Span| {
                let from = s.offset as usize;
                String::from_utf8_lossy(&arena[from..from + s.len as usize]).into_owned()
            };
            got.fields.extend(
                fields[..o.fields_written as usize]
                    .iter()
                    .map(|f| (at(f.name), at(f.value))),
            );
            if o.verb.len != 0 {
                got.request = format!("{} {}", at(o.verb), at(o.target));
            }
            got.far |= o.flags & EMIT_TO_FAR_END != 0;
            got.done |= o.flags & EMIT_DONE != 0;
            got.audits.extend(
                records[..o.records_written as usize]
                    .iter()
                    .filter(|r| r.op == RECORD_AUDIT)
                    .map(|r| (at(r.key), at(r.value), r.kind == AUDIT_REJECTED)),
            );
            got.bytes
                .extend_from_slice(&reply[..usize::try_from(o.emitted).unwrap()]);
            if ret.outcome() != Outcome::Ready || o.more == 0 {
                break;
            }
        }
        got
    }
}

/// One piece as the kernel pushes it.
struct Given<'a> {
    from: u32,
    flags: u32,
    stream: u64,
    status: u32,
    attempt: u32,
    member: &'a str,
    caller: &'a str,
    head: Vec<(&'a str, &'a str)>,
    bytes: &'a [u8],
}

impl<'a> Given<'a> {
    /// The caller's whole body, under the caller reference `caller`.
    fn caller(caller: &'a str, bytes: &'a [u8]) -> Self {
        Given {
            from: FROM_CALLER,
            flags: PIECE_LAST,
            stream: 0,
            status: 0,
            attempt: 0,
            member: "",
            caller,
            head: Vec::new(),
            bytes,
        }
    }

    /// The caller's side of a held stream opening: the request's (empty) body.
    fn stream_open(caller: &'a str, stream: u64) -> Self {
        Given {
            flags: 0,
            stream,
            ..Given::caller(caller, b"")
        }
    }

    /// The kernel collecting a held stream's output.
    fn collect(caller: &'a str, stream: u64) -> Self {
        Given {
            from: FROM_KERNEL,
            flags: 0,
            stream,
            ..Given::caller(caller, b"")
        }
    }

    /// The kernel's ATTEMPT naming `member`.
    fn attempt(caller: &'a str, member: &'a str) -> Self {
        Given {
            from: FROM_KERNEL,
            flags: 0,
            attempt: 1,
            member,
            ..Given::caller(caller, b"")
        }
    }

    /// The far end's whole answer.
    fn far(caller: &'a str, status: u32, head: Vec<(&'a str, &'a str)>, bytes: &'a [u8]) -> Self {
        Given {
            from: FROM_FAR_END,
            flags: PIECE_LAST | PIECE_HAS_STATUS,
            status,
            head,
            ..Given::caller(caller, bytes)
        }
    }
}

#[derive(Debug, Default)]
struct Answered {
    outcome: Option<Outcome>,
    status: u32,
    fields: Vec<(String, String)>,
    bytes: Vec<u8>,
    far: bool,
    done: bool,
    request: String,
    /// The audit rows written: action, resource, rejected.
    audits: Vec<(String, String, bool)>,
}

impl Answered {
    fn field(&self, name: &str) -> Option<&str> {
        field_of(&self.fields, name)
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap_or_else(|e| {
            panic!(
                "a JSON answer ({e}): {}",
                String::from_utf8_lossy(&self.bytes)
            )
        })
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// Two callers' opaque references, as the kernel lends them.
const ALICE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const BOB: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

const INIT_2025: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"client","version":"1"}}}"#;
const LIST_2025: &[u8] = br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
const INITIALIZED: &[u8] = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const ACCEPT_BOTH: (&str, &str) = ("accept", "application/json, text/event-stream");

/// `initialize` on the endpoint, as `caller`: the answer.
fn initialize(d: &Door, unit: u64, caller: &str) -> Answered {
    let arrived = d.arrive(unit, "POST", "/mcp", INIT_2025, &[ACCEPT_BOTH]);
    assert_eq!(
        arrived.outcome,
        Outcome::Ready,
        "a 2025-06-18 `initialize` is served, not refused: {arrived:?}"
    );
    d.piece(unit, &Given::caller(caller, INIT_2025))
}

/// A `tools/list` in session `session` as `caller`.
fn listed(d: &Door, unit: u64, session: &str, caller: &str) -> Answered {
    let fields = [
        ACCEPT_BOTH,
        ("mcp-session-id", session),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    let arrived = d.arrive(unit, "POST", "/mcp", LIST_2025, &fields);
    assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
    d.piece(unit, &Given::caller(caller, LIST_2025))
}

// ── (e): busbar as a client ──────────────────────────────────────────────────────────────────────

const CALL: &[u8] = br#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"fs_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
const CALL_FIELDS: &[(&str, &str)] = &[
    ("mcp-protocol-version", "2026-07-28"),
    ("mcp-method", "tools/call"),
    ("mcp-name", "fs_read_file"),
];
const ST_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"st_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
const ST_FIELDS: &[(&str, &str)] = &[
    ("mcp-protocol-version", "2026-07-28"),
    ("mcp-method", "tools/call"),
    ("mcp-name", "st_read_file"),
];

fn seen() -> Vec<Seen> {
    upstreams()
        .as_ref()
        .map(|u| u.seen.clone())
        .unwrap_or_default()
}

// ── the `2024-11-05` rung: busbar as a client of a legacy-only server (row 159 finding 1) ───────

/// A `tools/call` of the legacy registration's `read_file`, asking for `path`, under JSON-RPC id
/// `id`.
fn legacy_call(id: u64, path: &str) -> (Vec<u8>, [(&'static str, &'static str); 3]) {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "lg_read_file",
            "arguments": {"path": path},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    let fields = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "lg_read_file"),
    ];
    (serde_json::to_vec(&body).unwrap(), fields)
}

/// The walk's answer to a relayed call's stateless first hop, as the legacy server gives it.
const REFUSED: &[u8] = b"Method Not Allowed";

/// `caller`'s call `body` relayed on `unit`: admitted, verified against the legacy server (over
/// its held stream), and its stateless first hop handed to the walk.
fn relayed(d: &Door, unit: u64, caller: &str, body: &[u8], fields: &[(&str, &str)]) {
    assert_eq!(
        d.arrive(unit, "POST", "/mcp", body, fields).outcome,
        Outcome::Ready
    );
    d.piece(unit, &Given::attempt(caller, "lg"));
    let send = d.pump(unit, &Given::caller(caller, body));
    assert!(
        send.far,
        "the call is relayed, not refused: {} {}",
        send.status,
        send.text()
    );
}

/// The walk refused the stateless hop (the server speaks only `2024-11-05`): the call goes to the
/// held stream. One entry: what it came to (PENDING while its answer is not on the stream).
fn walk_refused<'a>(caller: &'a str) -> Given<'a> {
    Given::far(caller, 405, Vec::new(), REFUSED)
}

/// The `tools/call` POSTs the legacy server received, by the session they were POSTed in and the
/// path they asked for.
fn legacy_calls() -> Vec<(String, String)> {
    seen()
        .into_iter()
        .filter(|s| s.body["method"] == json!("tools/call"))
        .filter_map(|s| {
            let session = s.url.split(LEGACY_MESSAGES).nth(1)?.to_string();
            let path = s
                .body
                .pointer("/params/arguments/path")?
                .as_str()?
                .to_string();
            Some((session, path))
        })
        .collect()
}

/// The one legacy server's text answer to `answered`, with the caller's own id.
fn legacy_text(answered: &Answered) -> (Value, String) {
    let body = answered.json();
    let text = body
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a tool result: {body}"))
        .to_string();
    (body["id"].clone(), text)
}

// ── the operator's verbs and the line carrier, op by op ─────────────────────────────────────────

/// What `serve` answered: its outcome, its status and its body.
#[derive(Debug)]
struct Served {
    outcome: Outcome,
    status: u32,
    body: Vec<u8>,
}

impl Door {
    /// One entry of the trust verb `verb` (its index in the admin routes) on server `name`, on
    /// `unit`'s ticket; `resume` = the kernel's RESUME of a call that answered PENDING.
    fn serve_once(&self, unit: u64, verb: u32, name: &str, resume: bool) -> Served {
        let ticket = Ticket {
            slot: u32::try_from(unit).unwrap(),
            generation: 1,
        };
        let target = format!("/tools/{name}/connect");
        let mut reply = vec![0_u8; 1 << 16];
        let mut fields = [z::<OutField>(); 16];
        let mut arena = vec![0_u8; 1 << 14];
        let mut records = [z::<RecordWrite>(); 16];
        let mut i: ServeIn = z();
        i.head = head::<ServeIn>(slot::SERVE, ticket);
        if resume {
            i.head.flags = FLAG_RESUME;
        }
        i.route = verb;
        i.target = str_of(&target);
        i.body = octets(b"");
        (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
        let mut o: ServeOut = z();
        o.head = out_head::<ServeOut>();
        let f = ops().serve.expect("serve");
        // SAFETY: the slot is the door's own, called with an in and an out of the types it declares.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        Served {
            outcome: ret.outcome(),
            status: o.status,
            body: reply[..usize::try_from(o.reply_written).unwrap()].to_vec(),
        }
    }

    /// The operator's `connect` of server `name`, resumed (the driver turning between) until it
    /// answers.
    fn connect(&self, unit: u64, name: &str) -> Served {
        let mut got = self.serve_once(unit, 0, name, false);
        for _ in 0..32 {
            if got.outcome != Outcome::Pending {
                return got;
            }
            self.turn();
            got = self.serve_once(unit, 0, name, true);
        }
        panic!("the connect of `{name}` never stopped pending");
    }

    /// A line of carrier session `session` arriving as `unit`.
    fn line(&self, unit: u64, session: u64, body: &[u8]) -> Arrived {
        let session = session.to_string();
        let fields = [Field {
            name: str_of(busbar_contract::abi::host::service::CARRIER_SESSION_FIELD),
            value: str_of(&session),
        }];
        let route = &door::ROUTES[door::LINE_ROUTE];
        let mut i: ArriveIn = z();
        i.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
        i.unit = unit;
        i.claim = u32::try_from(door::LINE_ROUTE).unwrap();
        i.target = str_of(route.target);
        i.method = str_of(route.verb);
        i.body = octets(body);
        (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
        let mut units = [z::<UnitCount>(); 8];
        (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
        let mut o: ArriveOut = z();
        o.head = out_head::<ArriveOut>();
        let f = ops().arrive.expect("arrive");
        // SAFETY: the slot is the door's own, called with an in and an out of the types it declares.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        Arrived {
            outcome: ret.outcome(),
            refusal_status: o.refusal_status,
        }
    }
}

/// The `tools/list` requests `url`'s upstream received.
fn lists_to(url: &str) -> usize {
    seen()
        .iter()
        .filter(|s| s.url.starts_with(url) && s.body["method"] == json!("tools/list"))
        .count()
}

/// Every request `url`'s upstream received.
fn requests_to(url: &str) -> usize {
    seen().iter().filter(|s| s.url.starts_with(url)).count()
}

/// `st_read_file` called on `unit` as ALICE, up to the moment it is handed to the walk.
fn call_st(d: &Door, unit: u64) {
    assert_eq!(
        d.arrive(unit, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(unit, &Given::attempt(ALICE, "st"));
    d.piece(unit, &Given::caller(ALICE, ST_CALL));
}

// ── P-M4: a failed clock read is never a time ───────────────────────────────────────────────────

/// RED P-M4: WHILE THE HOST'S CLOCK READ FAILS, A CACHED TOOL LIST IS STALE. A call within
/// `verify_ttl` of the last fetch reuses it; once the clock cannot be read, every call fetches the
/// list again (the failure is never read as the epoch, at which every list looks fresh), and what
/// such a fetch landed is not stamped.
#[test]
fn a_failed_clock_read_fetches_the_tool_list_again() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    call_st(&d, 80);
    assert_eq!(
        lists_to(STATELESS_URL),
        1,
        "the first call fetched the list"
    );
    call_st(&d, 81);
    assert_eq!(
        lists_to(STATELESS_URL),
        1,
        "within verify_ttl the sighting is reused"
    );
    {
        let _fails = ClockFails::on();
        call_st(&d, 82);
        assert_eq!(
            lists_to(STATELESS_URL),
            2,
            "a failed clock read is never a time: the cached list is stale and fetched again"
        );
        call_st(&d, 83);
        assert_eq!(
            lists_to(STATELESS_URL),
            3,
            "a fetch made while the clock failed is not stamped (at the epoch or otherwise)"
        );
    }
}

// ── A-H1: the operator's `connect` ──────────────────────────────────────────────────────────────

/// The trust view's `failure`, and how many tools the last sighting carried.
fn view_of(served: &Served) -> (Value, Value) {
    assert_eq!(served.outcome, Outcome::Ready, "{served:?}");
    assert_eq!(
        served.status,
        200,
        "{}",
        String::from_utf8_lossy(&served.body)
    );
    let view: Value = serde_json::from_slice(&served.body).expect("the trust view");
    (view["failure"].clone(), view["observed_tools"].clone())
}

/// RED A-H1 (a): THE OPERATOR'S `connect` REACHES A SERVER THAT REQUIRES A SESSION, as
/// verify-on-call does: negotiated, its list seen, no failure recorded.
#[test]
fn connect_reaches_a_server_that_requires_a_session() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let served = d.connect(90, "fs");
    assert_eq!(
        view_of(&served),
        (Value::Null, json!(1)),
        "the connect negotiated a session and saw the one tool: {}",
        String::from_utf8_lossy(&served.body)
    );
}

/// RED A-H1 (b): THE OPERATOR'S `connect` REACHES A SERVER THAT SPEAKS ONLY `2024-11-05`, over the
/// held event stream, and a call within `verify_ttl` of it is relayed, never answered "not sent".
#[test]
fn connect_reaches_a_legacy_only_server_and_its_calls_go_on() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let served = d.connect(91, "lg");
    assert_eq!(
        view_of(&served),
        (Value::Null, json!(1)),
        "the connect reached the legacy server over its stream: {}",
        String::from_utf8_lossy(&served.body)
    );
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 92, ALICE, &a, &fields);
    let answered = d.pump(92, &walk_refused(ALICE));
    assert_eq!(
        legacy_text(&answered),
        (json!(30), "legacy a.txt".to_string())
    );
}

/// The section with one registration whose server is down.
const DOWN_SECTION: &str = r#"{
    "dn": {"url": "https://up.example/down", "pin": {"mechanism": "unpinned"}, "verify_ttl": "1h", "tools_allow": {"read_file": {}}}
}"#;

const DN_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":33,"method":"tools/call","params":{"name":"dn_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
const DN_FIELDS: &[(&str, &str)] = &[
    ("mcp-protocol-version", "2026-07-28"),
    ("mcp-method", "tools/call"),
    ("mcp-name", "dn_read_file"),
];

/// RED A-H1 (c): A `connect` THAT FAILED STAMPS NOTHING: the next call to that server fetches its
/// list again rather than being answered off the operator's failed refresh for `verify_ttl`.
#[test]
fn a_failed_connect_never_holds_back_the_next_calls_fetch() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(DOWN_SECTION);
    let served = d.connect(93, "dn");
    let (failure, _) = view_of(&served);
    assert!(failure.is_string(), "the down server failed: {failure}");
    let before = requests_to(DOWN_URL);
    assert_eq!(
        d.arrive(94, "POST", "/mcp", DN_CALL, DN_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(94, &Given::attempt(ALICE, "dn"));
    d.pump(94, &Given::caller(ALICE, DN_CALL));
    let after = requests_to(DOWN_URL);
    assert!(
        after > before,
        "the call fetched the list again: {before} requests before, {after} after"
    );
}

// ── A-M3: the unit cap judged before a line moves its carrier session ───────────────────────────

const LINE_INIT: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}"#;
const LINE_LIST: &[u8] = br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
const FILLER: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
const FILLER_FIELDS: &[(&str, &str)] = &[
    ("mcp-protocol-version", "2026-07-28"),
    ("mcp-method", "tools/list"),
];

/// RED A-M3: A LINE THE UNIT CAP REFUSES HAS MOVED NOTHING ON ITS CARRIER SESSION. A session's
/// `initialize` keeps its revision, so its later plain lines are raised and served; an `initialize`
/// refused at the cap keeps nothing, so a later plain line on that session is refused as it is on a
/// session that never initialized.
#[test]
fn a_line_refused_at_the_unit_cap_moves_nothing_on_its_session() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    // The control: an initialized session serves a plain line; a fresh one refuses it.
    assert_eq!(d.line(100, 7, LINE_INIT).outcome, Outcome::Ready);
    let raised = d.line(101, 7, LINE_LIST);
    assert_eq!(raised.outcome, Outcome::Ready, "{raised:?}");
    let plain = d.line(102, 8, LINE_LIST);
    assert_eq!(plain.outcome, Outcome::Refused, "{plain:?}");

    // The table filled to its cap.
    let mut filler = 1000_u64;
    loop {
        let arrived = d.arrive(filler, "POST", "/mcp", FILLER, FILLER_FIELDS);
        if arrived.outcome != Outcome::Ready {
            assert_eq!(
                (arrived.outcome, arrived.refusal_status),
                (Outcome::Refused, 429),
                "only the cap refuses a filler"
            );
            break;
        }
        filler += 1;
        assert!(filler < 1000 + 8192, "the table has a cap");
    }
    let at_cap = d.line(200, 9, LINE_INIT);
    assert_eq!(
        (at_cap.outcome, at_cap.refusal_status),
        (Outcome::Refused, 429),
        "the cap refuses the line"
    );

    // One place freed: a filler answered.
    let done = d.piece(1000, &Given::caller(ALICE, FILLER));
    assert_eq!(done.status, 200, "{}", done.text());
    let after = d.line(201, 9, LINE_LIST);
    assert_eq!(
        after.outcome,
        Outcome::Refused,
        "the refused `initialize` kept no revision for session 9: {after:?}"
    );
}

// ── P-M11: a name the routing key cannot spell ──────────────────────────────────────────────────

/// RED P-M11: A SERVER ID OR A `tools_allow` NAME THE ROUTING KEY CANNOT SPELL IS REFUSED AT
/// VALIDATE, in words naming it; never accepted and then silently undispatchable.
#[test]
fn a_name_the_routing_key_cannot_spell_is_refused_at_validate() {
    let tool = br#"{"st": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "tools_allow": {"read file": {}}}}"#;
    let refused = door::read_tools_section(tool).expect_err("a tool name with a space");
    assert!(
        refused.contains("`tools.st`") && refused.contains("read file"),
        "{refused}"
    );
    let server = br#"{"s+t": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "tools_allow": {"read_file": {}}}}"#;
    let refused = door::read_tools_section(server).expect_err("a server id with a `+`");
    assert!(refused.contains("s+t"), "{refused}");
    let fine = br#"{"st": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "tools_allow": {"read_file.v2-x": {}}}}"#;
    assert!(door::read_tools_section(fine).is_ok());
}

// ── A-M2: the event stream carries the answer's own bytes ─────────────────────────────────────

/// The `data` of the stream's last event, its `data:` lines joined back with `\n` as a client
/// joins them.
fn last_data(bytes: &[u8]) -> String {
    let text = String::from_utf8(bytes.to_vec()).expect("an event stream is text");
    let last = text
        .trim_end_matches('\n')
        .rsplit("\n\n")
        .next()
        .expect("an event");
    last.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// RED A-M2: THE STREAM CARRIES THE ANSWER'S OWN BYTES (Law 11): its members in the upstream's
/// order, its numbers as the upstream spelled them (an integer past 64 bits, a float's exponent),
/// and its line breaks as `data:` lines a client joins back. Never parsed and printed again.
#[test]
fn the_stream_carries_the_answers_own_bytes() {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "fs_read", "_meta": {"progressToken": "p"}}});
    let framing = busbar_plane_mcp::framing::Framing::of(
        Some(busbar_plane_mcp::framing::EVENT_STREAM),
        "tools/call",
        &body,
    )
    .expect("framed");
    let answer = b"{\"jsonrpc\":\"2.0\",\"id\":1,\n  \"result\":{\"zeta\":123456789012345678901234567890,\n  \"alpha\":1.0e0,\"content\":[]}}".to_vec();
    let (bytes, framed) = framing.frame(200, answer.clone(), &[]);
    assert!(framed);
    assert_eq!(
        last_data(&bytes),
        String::from_utf8(answer).unwrap(),
        "the answer's own bytes, line for line: {}",
        String::from_utf8_lossy(&bytes)
    );
}

// ── a kernel refusal that ended no unit (audit K4#2(b)) ─────────────────────────────────────────

/// `refusal` for a kernel refusal before any unit: the status and body the door answers.
fn unitless_kernel_refusal(d: &Door, status: u32, reason: u32) -> (Outcome, u32, Vec<u8>) {
    use busbar_contract::abi::plane::{RefusalIn, RefusalOut, REFUSAL_KERNEL};
    let mut reply = vec![0_u8; 1 << 12];
    let mut fields = [z::<OutField>(); 8];
    let mut arena = vec![0_u8; 1 << 12];
    let mut i: RefusalIn = z();
    i.head = head::<RefusalIn>(slot::REFUSAL, Ticket::NONE);
    i.cause = REFUSAL_KERNEL;
    i.status = status;
    i.reason = reason;
    i.unit = 0;
    i.text = str_of("unauthenticated");
    i.target = str_of("/mcp/sub");
    (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
    (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
    (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
    let mut o: RefusalOut = z();
    o.head = out_head::<RefusalOut>();
    let f = ops().refusal.expect("refusal");
    // SAFETY: the slot is the door's own, called with an in and an out of the types it declares.
    #[allow(unused_unsafe)]
    let ret = unsafe {
        f(
            d.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    // `0`: the kernel's status stands.
    let status = if o.status == 0 { status } else { o.status };
    (
        ret.outcome(),
        status,
        reply[..usize::try_from(o.reply_written).unwrap()].to_vec(),
    )
}

/// THE PLANE OWNS THE WORDS OF A KERNEL REFUSAL BEFORE ANY UNIT (audit K4#2(b), ARCHITECT ruling: the
/// plugin owns the text). A mounted path's failed authentication and the body limit answer the
/// JSON-RPC envelope with no id, in the bytes the kernel rendered before: the 1.6.0 baseline.
/// RED: the door fell to its generic arm (`-32000` with the reason's word).
#[test]
fn a_kernel_refusal_with_no_unit_answers_the_baseline_json_rpc_bytes() {
    use busbar_contract::abi::plane::RefusalCode;
    let d = open();
    assert_eq!(
        unitless_kernel_refusal(&d, 401, RefusalCode::Unauthenticated.code()),
        (
            Outcome::Ready,
            401,
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"authentication failed"}}"#
                .to_vec()
        )
    );
    assert_eq!(
        unitless_kernel_refusal(&d, 413, RefusalCode::BodyTooLarge.code()),
        (
            Outcome::Ready,
            413,
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"request body exceeds the maximum allowed size"}}"#
                .to_vec()
        )
    );
}
