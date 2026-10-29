// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION REVISIONS AND THE LEGACY EVENT STREAM, THROUGH THE DOOR (THE DESIGN section 2, the mcp
//! bullet): a `2025-06-18` client opens a session with `initialize` and is served inside it, a
//! session presented by another owner is unknown (`404`), a GET naming no revision opens the
//! `2024-11-05` event stream and a GET or DELETE naming no session is `405`; as a client, busbar
//! reaches an upstream that requires a session by negotiation, and sends a stateless upstream the
//! bytes it always sent.
//!
//! The door is driven over its own ABI here, op by op, under a host whose services and connector
//! are stand-ins written in this file: a clock, the kernel's entitlement and trust answers (all
//! yes), a counting `random.fill`, and two upstreams behind the connector, one that requires a
//! session and one that speaks the stateless revision.
//!
//! This suite drives the door over its C ABI with a host it stands up itself, so it needs
//! `unsafe`, and it reaches the crate through `door` alone (the crate's only public item). The
//! door facts it needs are `tests/support/door_facts.rs`, pinned to the crate's own items in
//! `src/tests/door_facts_tests.rs`.

#![allow(unsafe_code)]

// The door's private constants these tests need, restated and held to the crate's own items by the
// crate's unit test `door_facts_tests`. Each test binary reads only some of them.
#[path = "support/door_facts.rs"]
#[allow(dead_code)]
mod door_facts;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
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
    AbiStr, Blob, Field, InHead, OutHead, Outcome, RawOutcome, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, DriveIn, OpenIn, OpenOut, OpsHead, TickIn, TickOut,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables, Ticket};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, Ops, OutField, PlaneCancelIn, PlaneCancelOut,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, RecordWrite, UnitCount, AUDIT_REJECTED,
    EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS,
    PIECE_LAST, RECORD_AUDIT,
};
use busbar_contract::abi::transport::FrameSpan;
use busbar_plane_mcp::door;
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
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            ..ServiceOut::ZERO
        });
    }
    RawOutcome::of(outcome)
}

/// The host's monotonic clock: it moves a second on every reading.
static MONO: AtomicU64 = AtomicU64::new(1_000_000_000);

extern "C" fn clock_now(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
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
    ticket_mint: None,
    ticket_take: None,
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
    /// The legacy upstream holds its `initialize` answers until the test releases them.
    hold_init: bool,
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
    let method = body.get("method").and_then(Value::as_str);
    let hold = (ups.hold_calls && method == Some("tools/call"))
        || (ups.hold_init && method == Some("initialize"));
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

/// What an upstream answers one request.
fn upstream_answer(url: &str, fields: &[(String, String)], body: &Value) -> Reply {
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

// ── the replay rule, as the host keeps it on the driver ticket ──────────────────────────────────

/// One kept answer: the outcome, the scalar and length, and for a read the piece and the bytes it
/// wrote.
#[derive(Clone)]
struct Kept {
    outcome: Outcome,
    value: u64,
    len: u64,
    read: Option<(ReplyPiece, Vec<u8>)>,
}

/// THE DRIVER TICKET'S KEPT ANSWERS, by the handle's issue order: a handle that answered (anything
/// but PENDING) answers the same again until the next tick starts, and the service is not made a
/// second time, whatever service the re-issue asks for (the host checks no op).
static KEPT: Mutex<BTreeMap<u32, Kept>> = Mutex::new(BTreeMap::new());

fn kept_answers() -> MutexGuard<'static, BTreeMap<u32, Kept>> {
    KEPT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `run` once per driver-ticket handle, as the host's replay rule runs a service; `read` names a
/// read's buffer and descriptor slot, which a replay writes again.
fn kept(
    handle: CompletionHandle,
    out: *mut ServiceOut,
    read: Option<(*mut u8, *mut ReplyPiece)>,
    run: impl FnOnce() -> RawOutcome,
) -> RawOutcome {
    if handle.ticket != DRIVER {
        return run();
    }
    let replay = kept_answers().get(&handle.seq).cloned();
    if let Some(k) = replay {
        if let (Some((buf, piece)), Some((p, bytes))) = (read, k.read.as_ref()) {
            // SAFETY: the SDK's buffer and descriptor slot, live for the call; a kept read's bytes
            // fit the buffer they were first read into, which every read here shares the size of.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
                piece.write(*p);
            }
        }
        return answer(out, k.outcome, k.value, k.len);
    }
    let ret = run();
    let outcome = ret.outcome();
    if outcome != Outcome::Pending {
        // SAFETY: `run` wrote the SDK's `out`.
        let o = unsafe { out.read() };
        let read = read.map(|(buf, piece)| {
            let n = usize::try_from(o.len).unwrap_or(0);
            // SAFETY: as above: the read wrote its descriptor and `n` bytes of the buffer.
            unsafe { (piece.read(), std::slice::from_raw_parts(buf, n).to_vec()) }
        });
        kept_answers().insert(
            handle.seq,
            Kept {
                outcome,
                value: o.value,
                len: o.len,
                read,
            },
        );
    }
    ret
}

extern "C" fn establish(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands an `EstablishIn`.
    let handle = unsafe { input.cast::<EstablishIn>().read() }.head.handle;
    kept(handle, out, None, || establish_now(ctx, input, out))
}

extern "C" fn write_request(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: the SDK hands a `RequestIn`.
    let handle = unsafe { input.cast::<RequestIn>().read() }.head.handle;
    kept(handle, out, None, || write_request_now(ctx, input, out))
}

extern "C" fn read_reply(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `ReplyIn`.
    let i = unsafe { input.cast::<ReplyIn>().read() };
    kept(i.head.handle, out, Some((i.buf, i.piece)), || {
        read_reply_now(ctx, input, out)
    })
}

extern "C" fn close(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `StreamIn`.
    let handle = unsafe { input.cast::<StreamIn>().read() }.head.handle;
    kept(handle, out, None, || close_now(ctx, input, out))
}

fn establish_now(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
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

fn write_request_now(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
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

fn read_reply_now(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
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

fn close_now(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
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
    unsafe { &*door().ops().cast::<Ops>() }
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
    kept_answers().clear();
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
    let i = door_facts::ROUTES
        .iter()
        .position(|&(v, t, c)| v == verb && t == "/mcp" && c == "http")
        .expect("the door routes it");
    u32::try_from(i).unwrap()
}

impl Door {
    /// The kernel's tick, on the driver ticket.
    fn tick(&self) {
        // A tick starts: the host forgets what the driver ticket kept.
        kept_answers().clear();
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

    /// `unit`'s piece re-called while it pends, the driver woken between WITHOUT a tick (one tick
    /// cycle throughout, as a driver woken by its streams' readiness runs): what it came to.
    fn steady(&self, unit: u64, given: &Given<'_>) -> Answered {
        let mut got = Answered::default();
        for _ in 0..32 {
            got = self.piece(unit, given);
            if got.outcome != Some(Outcome::Pending) {
                return got;
            }
            self.drive();
        }
        got
    }

    /// `unit`'s piece re-called while it pends, the driver turning between, at most 32 times:
    /// what it came to (still PENDING when it never stopped).
    fn settle(&self, unit: u64, given: &Given<'_>) -> Answered {
        let mut got = Answered::default();
        for _ in 0..32 {
            got = self.piece(unit, given);
            if got.outcome != Some(Outcome::Pending) {
                return got;
            }
            self.turn();
        }
        got
    }

    /// The kernel cancels the op on `unit`'s ticket.
    fn cancel(&self, unit: u64) {
        let ticket = Ticket {
            slot: u32::try_from(unit).unwrap(),
            generation: 1,
        };
        let mut records = [z::<RecordWrite>(); 8];
        let mut arena = vec![0_u8; 1 << 12];
        let i = PlaneCancelIn {
            cancel: CancelIn {
                head: head::<PlaneCancelIn>(life::CANCEL, ticket),
                ticket,
            },
            records_buf: records.as_mut_ptr(),
            records_cap: records.len(),
            arena_buf: arena.as_mut_ptr(),
            arena_cap: arena.len(),
            // The host's own cancel of a unit names the unit as arrive keyed it.
            unit,
        };
        let mut o: PlaneCancelOut = z();
        o.cancel.head = out_head::<PlaneCancelOut>();
        let f = lifecycle().cancel.expect("cancel");
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
            got.diags += o.head.envelope.diags_len;
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
    /// The diagnostics the reply's envelope carried.
    diags: usize,
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

// ── (a) and (b): the session revisions ──────────────────────────────────────────────────────────

/// A `2025-06-18` client: `initialize` answers the revision it asked for and names a session of 128
/// bits in `Mcp-Session-Id`; a request in that session is served, its answer in the session
/// revision's shape (no stateless-only members).
#[test]
fn a_2025_initialize_opens_a_session_that_serves_its_requests() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open();
    let init = initialize(&d, 1, ALICE);
    assert_eq!(init.status, 200, "{}", init.text());
    assert_eq!(init.outcome, Some(Outcome::Ready));
    assert!(init.done, "the answer is whole");
    let session = init
        .field("mcp-session-id")
        .expect("the answer names its session")
        .to_string();
    assert_eq!(session.len(), 32, "128 bits, as hex");
    assert!(session.bytes().all(|b| b.is_ascii_hexdigit()));
    let body = init.json();
    assert_eq!(body["id"], json!(1));
    assert_eq!(body["result"]["protocolVersion"], json!("2025-06-18"));
    assert!(body["result"]["capabilities"]["tools"].is_object());

    let arrived = d.arrive(
        2,
        "POST",
        "/mcp",
        INITIALIZED,
        &[ACCEPT_BOTH, ("mcp-session-id", session.as_str())],
    );
    assert_eq!(arrived.outcome, Outcome::Ready);
    let noted = d.piece(2, &Given::caller(ALICE, INITIALIZED));
    assert_eq!(noted.status, 202);

    let list = listed(&d, 3, &session, ALICE);
    assert_eq!(list.status, 200, "{}", list.text());
    let body = list.json();
    assert_eq!(body["id"], json!(2));
    let tools = body["result"]["tools"].as_array().expect("a tool list");
    assert!(!tools.is_empty(), "the caller is entitled to every tool");
    assert!(
        body["result"].get("resultType").is_none() && body["result"].get("ttlMs").is_none(),
        "lowered into the session revision: {body}"
    );
}

/// A session is bound to the owner that opened it: another caller presenting its id is told it is
/// unknown (`404`), on POST and on DELETE alike, and the owner's DELETE ends it.
#[test]
fn a_session_presented_by_another_owner_is_unknown() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open();
    let init = initialize(&d, 11, ALICE);
    let session = init
        .field("mcp-session-id")
        .expect("the answer names its session")
        .to_string();
    assert_eq!(listed(&d, 12, &session, BOB).status, 404);
    assert_eq!(listed(&d, 13, &session, ALICE).status, 200);
    assert_eq!(
        listed(&d, 14, "0123456789abcdef0123456789abcdef", ALICE).status,
        404
    );

    let delete = |unit: u64, caller: &str| {
        let arrived = d.arrive(
            unit,
            "DELETE",
            "/mcp",
            b"",
            &[("mcp-session-id", session.as_str())],
        );
        assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
        d.piece(unit, &Given::caller(caller, b""))
    };
    assert_eq!(delete(15, BOB).status, 404);
    assert_eq!(delete(16, ALICE).status, 200);
    assert_eq!(listed(&d, 17, &session, ALICE).status, 404, "ended");
}

// ── (c) and (d): the sessionless GET and DELETE ─────────────────────────────────────────────────

/// A GET that names no session and no revision is the `2024-11-05` client's: its stream opens with
/// the `endpoint` event naming the message address; a message POSTed there is accepted (`202`) and
/// answered on the stream. A GET that names a revision, or does not accept an event stream, is
/// `405`, and so is a DELETE that names no session.
#[test]
fn a_sessionless_get_is_the_legacy_stream_or_405() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open();
    let sse = ("accept", "text/event-stream");
    let named = d.arrive(
        21,
        "GET",
        "/mcp",
        b"",
        &[sse, ("mcp-protocol-version", "2025-06-18")],
    );
    assert_eq!(
        (named.outcome, named.refusal_status),
        (Outcome::Refused, 405)
    );
    let plain = d.arrive(22, "GET", "/mcp", b"", &[("accept", "application/json")]);
    assert_eq!(
        (plain.outcome, plain.refusal_status),
        (Outcome::Refused, 405)
    );
    let delete = d.arrive(23, "DELETE", "/mcp", b"", &[]);
    assert_eq!(
        (delete.outcome, delete.refusal_status),
        (Outcome::Refused, 405)
    );

    let legacy = d.arrive(24, "GET", "/mcp", b"", &[sse]);
    assert_eq!(legacy.outcome, Outcome::Ready, "{legacy:?}");
    let opened = d.piece(24, &Given::stream_open(ALICE, 24));
    assert_eq!(opened.status, 200);
    assert_eq!(opened.field("content-type"), Some("text/event-stream"));
    let text = opened.text();
    let address = text
        .strip_prefix("event: endpoint\ndata: ")
        .and_then(|rest| rest.split('\n').next())
        .unwrap_or_else(|| panic!("the stream opens with the endpoint event: {text:?}"))
        .to_string();
    let session = address
        .strip_prefix("/mcp?sessionId=")
        .expect("the message address names the session");
    assert_eq!(session.len(), 32);

    let init = br#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}"#;
    let posted = d.arrive(
        25,
        "POST",
        &address,
        init,
        &[("content-type", "application/json")],
    );
    assert_eq!(posted.outcome, Outcome::Ready, "{posted:?}");
    let accepted = d.piece(25, &Given::caller(ALICE, init));
    assert_eq!(accepted.status, 202);
    assert!(accepted.bytes.is_empty());

    let delivered = d.piece(24, &Given::collect(ALICE, 24));
    let text = delivered.text();
    let data = text
        .strip_prefix("event: message\ndata: ")
        .and_then(|rest| rest.split('\n').next())
        .unwrap_or_else(|| panic!("the answer is delivered on the stream: {text:?}"));
    let answer: Value = serde_json::from_str(data).expect("one JSON-RPC message");
    assert_eq!(answer["id"], json!(7));
    assert_eq!(answer["result"]["protocolVersion"], json!("2024-11-05"));

    // The message address is the owner's: another caller posting to it is told it is unknown.
    let foreign = d.arrive(
        26,
        "POST",
        &address,
        init,
        &[("content-type", "application/json")],
    );
    assert_eq!(foreign.outcome, Outcome::Ready);
    assert_eq!(d.piece(26, &Given::caller(BOB, init)).status, 404);
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

/// An upstream that refuses the stateless revision and requires `initialize` is reached by
/// negotiation: busbar opens a session with it, and the relayed call is answered from inside it.
/// When the upstream then forgets that session, the walk's answer (`404`) is recovered by a fresh
/// `initialize` and the call is still answered.
#[test]
fn an_upstream_that_requires_a_session_is_reached_by_negotiation() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    assert_eq!(
        d.arrive(40, "POST", "/mcp", CALL, CALL_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(40, &Given::attempt(ALICE, "fs"));
    let send = d.piece(40, &Given::caller(ALICE, CALL));
    assert!(
        send.far,
        "the call is relayed, not refused: {} {}",
        send.status,
        send.text()
    );
    let sent: Value = serde_json::from_slice(&send.bytes).expect("a JSON-RPC request");
    assert_eq!(sent["method"], json!("tools/call"));
    assert_eq!(
        send.field("mcp-session-id"),
        Some(UPSTREAM_SESSION),
        "the relayed call rides the session negotiated with the upstream: {:?}",
        send.fields
    );
    assert!(
        sent.pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .is_none(),
        "lowered into the session revision: {sent}"
    );
    let methods: Vec<String> = seen()
        .iter()
        .filter(|s| s.url.starts_with(SESSION_URL))
        .map(|s| s.body["method"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(
        methods,
        [
            "tools/list",
            "initialize",
            "notifications/initialized",
            "tools/list"
        ],
        "the verify fetch probed statelessly, was refused, and negotiated"
    );
    // A call in the session carries the session's own id, never the stateless round's `0` every
    // call shares (row 159 finding 3); the upstream answers under the id the call carried.
    assert_ne!(
        sent["id"],
        json!(0),
        "the call in the session carried the round's id: {sent}"
    );
    let far_ok = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": sent["id"],
        "result": {"content": [{"type": "text", "text": "in-session"}]},
    }))
    .expect("an answer");
    let answered = d.piece(40, &Given::far(ALICE, 200, vec![JSON_TYPE], &far_ok));
    assert_eq!(answered.status, 200, "{}", answered.text());
    let body = answered.json();
    assert_eq!(body["id"], json!(30));
    assert_eq!(body["result"]["content"][0]["text"], json!("in-session"));

    // The upstream forgot the session: the walk's answer is its 404, and busbar re-initialises.
    assert_eq!(
        d.arrive(41, "POST", "/mcp", CALL, CALL_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(41, &Given::attempt(ALICE, "fs"));
    let send = d.piece(41, &Given::caller(ALICE, CALL));
    assert!(send.far);
    let answered = d.piece(
        41,
        &Given::far(
            ALICE,
            404,
            vec![JSON_TYPE],
            br#"{"error":"unknown session"}"#,
        ),
    );
    assert_eq!(answered.status, 200, "{}", answered.text());
    let body = answered.json();
    assert_eq!(body["id"], json!(30));
    assert_eq!(body["result"]["content"][0]["text"], json!("in-session"));
}

/// An upstream that speaks the stateless revision sees exactly the request the dialect's builder
/// writes, with no handshake ahead of it.
#[test]
fn a_stateless_upstream_sees_the_stateless_request_unchanged() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    assert_eq!(
        d.arrive(50, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(50, &Given::attempt(ALICE, "st"));
    let send = d.piece(50, &Given::caller(ALICE, ST_CALL));
    assert!(send.far, "{} {}", send.status, send.text());
    assert_eq!(send.request, "POST /st");
    let sent: Value = serde_json::from_slice(&send.bytes).expect("a JSON-RPC request");
    assert_eq!(
        sent,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "progressToken": null,
                },
            },
        })
    );
    assert_eq!(
        send.fields,
        vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "accept".to_string(),
                "application/json, text/event-stream".to_string()
            ),
            ("mcp-protocol-version".to_string(), "2026-07-28".to_string()),
            ("mcp-method".to_string(), "tools/call".to_string()),
            ("mcp-name".to_string(), "read_file".to_string()),
        ]
    );
    let to_st: Vec<Seen> = seen()
        .into_iter()
        .filter(|s| s.url.starts_with(STATELESS_URL))
        .collect();
    assert_eq!(to_st.len(), 1, "one verify fetch, no handshake: {to_st:?}");
    assert_eq!(to_st[0].body["method"], json!("tools/list"));
    assert_eq!(
        field_of(&to_st[0].fields, "mcp-protocol-version"),
        Some("2026-07-28")
    );
    let far_ok = br#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"stateless"}],"resultType":"complete"}}"#;
    let answered = d.piece(50, &Given::far(ALICE, 200, vec![JSON_TYPE], far_ok));
    assert_eq!(answered.status, 200, "{}", answered.text());
    assert_eq!(
        answered.json()["result"]["content"][0]["text"],
        json!("stateless")
    );
}

// ── subscribe stays for the old revisions ───────────────────────────────────────────────────────

/// A `2025-06-18` session that subscribes to a declared resource hears the announcing server's
/// `notifications/resources/updated` on its GET stream: here the upstream announces it on the event
/// stream it answers a relayed call with.
#[test]
fn a_session_subscription_hears_the_upstreams_resource_update() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let init = initialize(&d, 60, ALICE);
    let session = init
        .field("mcp-session-id")
        .expect("the answer names its session")
        .to_string();
    assert_eq!(
        init.json()["result"]["capabilities"]["resources"]["subscribe"],
        json!(true),
        "subscribe stays for the old revisions"
    );
    let in_session = [
        ACCEPT_BOTH,
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    let subscribe =
        br#"{"jsonrpc":"2.0","id":3,"method":"resources/subscribe","params":{"uri":"file:///readme"}}"#;
    assert_eq!(
        d.arrive(61, "POST", "/mcp", subscribe, &in_session).outcome,
        Outcome::Ready
    );
    let subscribed = d.settle(61, &Given::caller(ALICE, subscribe));
    assert_eq!(subscribed.status, 200, "{}", subscribed.text());
    assert_eq!(subscribed.json()["result"], json!({}));

    let stream = [
        ("accept", "text/event-stream"),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    assert_eq!(
        d.arrive(62, "GET", "/mcp", b"", &stream).outcome,
        Outcome::Ready
    );
    let opened = d.piece(62, &Given::stream_open(ALICE, 62));
    assert_eq!(opened.status, 200);
    assert_eq!(opened.field("content-type"), Some("text/event-stream"));

    assert_eq!(
        d.arrive(63, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(63, &Given::attempt(BOB, "st"));
    assert!(d.piece(63, &Given::caller(BOB, ST_CALL)).far);
    let far = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\",\"params\":{\"uri\":\"file:///readme\"}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"content\":[],\"resultType\":\"complete\"}}\n\n";
    let answered = d.piece(
        63,
        &Given::far(BOB, 200, vec![("content-type", "text/event-stream")], far),
    );
    assert_eq!(answered.status, 200);

    let delivered = d.piece(62, &Given::collect(ALICE, 62)).text();
    assert!(
        delivered.contains(r#""method":"notifications/resources/updated""#)
            && delivered.contains("file:///readme"),
        "the subscriber hears the update: {delivered:?}"
    );
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

/// A REGISTERED SERVER THAT SPEAKS ONLY `2024-11-05` IS REACHED END TO END: busbar opens its event
/// stream, `initialize`s on it, and POSTs each call to the message address it names. Two calls of
/// ONE caller in flight at once, answered on the stream in the reverse order, each reach the call
/// that asked: correlated by the JSON-RPC id busbar gave each, never by order.
#[test]
fn a_legacy_only_server_is_reached_and_its_answers_reach_their_callers() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 70, ALICE, &a, &fields);
    assert_eq!(
        legacy_sessions().len(),
        1,
        "the verify fetch opened the held stream"
    );
    upstreams().as_mut().unwrap().hold_calls = true;
    let first = d.piece(70, &walk_refused(ALICE));
    assert_eq!(first.outcome, Some(Outcome::Pending), "{}", first.text());
    let (b, fields) = legacy_call(31, "b.txt");
    relayed(&d, 71, ALICE, &b, &fields);
    let second = d.piece(71, &walk_refused(ALICE));
    assert_eq!(second.outcome, Some(Outcome::Pending), "{}", second.text());
    let session = legacy_sessions()[0].clone();
    assert_eq!(
        legacy_calls(),
        [
            (session.clone(), "a.txt".to_string()),
            (session.clone(), "b.txt".to_string())
        ],
        "both calls POSTed in the one caller's session"
    );

    // The server answers the second call first.
    on_stream(&session, |s| {
        let held = std::mem::take(&mut s.held);
        s.events.extend(held.into_iter().rev());
    });
    d.turn();
    let answered_b = d.pump(71, &walk_refused(ALICE));
    let answered_a = d.pump(70, &walk_refused(ALICE));
    assert_eq!(answered_a.status, 200, "{}", answered_a.text());
    assert_eq!(answered_b.status, 200, "{}", answered_b.text());
    assert_eq!(
        legacy_text(&answered_a),
        (json!(30), "legacy a.txt".to_string()),
        "the first call's own answer, under its own id"
    );
    assert_eq!(
        legacy_text(&answered_b),
        (json!(31), "legacy b.txt".to_string()),
        "the second call's own answer, under its own id"
    );
    let methods: Vec<String> = seen()
        .iter()
        .filter(|s| s.url.contains(LEGACY_MESSAGES))
        .map(|s| s.body["method"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(
        methods[..2],
        ["initialize", "notifications/initialized"],
        "the stream's handshake ran first, once: {methods:?}"
    );
    assert_eq!(
        methods.iter().filter(|m| *m == "initialize").count(),
        1,
        "one handshake per stream: {methods:?}"
    );
}

/// RED (a): A REPLY WHOSE ID NO CALL WAITS FOR is dropped, never delivered to the call waiting on
/// the stream, and the next answer on that caller's stream carries one rejected
/// `mcp_upstream.reply` audit row for it.
#[test]
fn a_legacy_reply_no_call_waits_for_is_dropped_and_audited() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 72, ALICE, &a, &fields);
    upstreams().as_mut().unwrap().hold_calls = true;
    assert_eq!(
        d.piece(72, &walk_refused(ALICE)).outcome,
        Some(Outcome::Pending)
    );
    let session = legacy_sessions()[0].clone();
    // A reply under an id busbar never sent, ahead of the call's own.
    let stray = sse_event(
        "message",
        r#"{"jsonrpc":"2.0","id":999,"result":{"content":[{"type":"text","text":"stolen"}]}}"#,
    );
    on_stream(&session, |s| s.events.push_back(stray));
    d.turn();
    assert_eq!(
        d.piece(72, &walk_refused(ALICE)).outcome,
        Some(Outcome::Pending),
        "the stray reply is never the waiting call's answer"
    );
    on_stream(&session, |s| {
        let held = std::mem::take(&mut s.held);
        s.events.extend(held);
    });
    d.turn();
    let answered = d.pump(72, &walk_refused(ALICE));
    assert_eq!(
        legacy_text(&answered),
        (json!(30), "legacy a.txt".to_string())
    );
    assert!(!answered.text().contains("stolen"), "{}", answered.text());
    let dropped: Vec<&(String, String, bool)> = answered
        .audits
        .iter()
        .filter(|(action, _, _)| action == "mcp_upstream.reply")
        .collect();
    assert_eq!(
        dropped,
        [&(
            "mcp_upstream.reply".to_string(),
            "mcp_server:lg".to_string(),
            true
        )],
        "one rejected row for the one reply dropped: {:?}",
        answered.audits
    );
}

/// RED (b): THE HELD STREAM DROPPING fails every call waiting on it with the upstream-failure
/// answer every relayed call gets when its server does not complete it, and the next call opens a
/// new stream.
#[test]
fn a_legacy_stream_that_drops_fails_every_waiting_call() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    upstreams().as_mut().unwrap().hold_calls = true;
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 73, ALICE, &a, &fields);
    assert_eq!(
        d.piece(73, &walk_refused(ALICE)).outcome,
        Some(Outcome::Pending)
    );
    let (b, fields) = legacy_call(31, "b.txt");
    relayed(&d, 74, ALICE, &b, &fields);
    assert_eq!(
        d.piece(74, &walk_refused(ALICE)).outcome,
        Some(Outcome::Pending)
    );
    let session = legacy_sessions()[0].clone();
    on_stream(&session, |s| {
        s.held.clear();
        s.closed = true;
    });
    d.turn();
    for (unit, id) in [(73, 30), (74, 31)] {
        let failed = d.pump(unit, &walk_refused(ALICE));
        assert_eq!(failed.status, 200, "{}", failed.text());
        let body = failed.json();
        assert_eq!(body["id"], json!(id));
        assert_eq!(body["result"]["isError"], json!(true), "{body}");
        let text = body["result"]["content"][0]["text"].as_str().unwrap_or("");
        assert_eq!(
            text,
            "The MCP server `lg` did not complete this tool call: the MCP server's 2024-11-05 \
             event stream closed before it answered this call",
            "the upstream-failure answer, in the stream's words"
        );
    }

    upstreams().as_mut().unwrap().hold_calls = false;
    let (c, fields) = legacy_call(32, "c.txt");
    relayed(&d, 75, ALICE, &c, &fields);
    let answered = d.pump(75, &walk_refused(ALICE));
    assert_eq!(
        legacy_text(&answered),
        (json!(32), "legacy c.txt".to_string())
    );
    let fresh = legacy_sessions();
    assert!(
        fresh.len() == 1 && fresh[0] != session,
        "the next call opened a new stream: {fresh:?} after {session}"
    );
}

/// RED (c): TWO CALLERS' BINDINGS NEVER SHARE A STREAM (the H3 per-caller rule): a second caller's
/// call to the same member opens its own stream, and its POSTs go to that stream's session.
#[test]
fn two_callers_of_one_legacy_member_never_share_a_stream() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 76, ALICE, &a, &fields);
    let alice = d.pump(76, &walk_refused(ALICE));
    assert_eq!(legacy_text(&alice), (json!(30), "legacy a.txt".to_string()));
    let (b, fields) = legacy_call(30, "b.txt");
    relayed(&d, 77, BOB, &b, &fields);
    let bob = d.pump(77, &walk_refused(BOB));
    assert_eq!(legacy_text(&bob), (json!(30), "legacy b.txt".to_string()));
    let sessions = legacy_sessions();
    assert_eq!(sessions.len(), 2, "one stream per caller: {sessions:?}");
    assert_eq!(
        legacy_calls(),
        [
            (sessions[0].clone(), "a.txt".to_string()),
            (sessions[1].clone(), "b.txt".to_string())
        ],
        "each caller's call POSTed in its own stream's session"
    );
}

/// A NOTIFICATION ON THE HELD LINK FINISHES ON ITS POST: the `2024-11-05` server answers a
/// notification's POST `202` and never sends anything for it on the stream, so busbar POSTs it with
/// no id and goes on at once. The handshake's `notifications/initialized` is that notification:
/// the call after it is POSTed and answered though no event ever came for it.
#[test]
fn a_notification_on_the_held_link_finishes_on_its_post() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (a, fields) = legacy_call(40, "n.txt");
    relayed(&d, 78, ALICE, &a, &fields);
    let answered = d.pump(78, &walk_refused(ALICE));
    assert_eq!(answered.status, 200, "{}", answered.text());
    assert_eq!(
        legacy_text(&answered),
        (json!(40), "legacy n.txt".to_string())
    );
    let posted: Vec<Value> = seen()
        .into_iter()
        .filter(|s| s.url.contains(LEGACY_MESSAGES))
        .map(|s| s.body)
        .collect();
    let at = |method: &str| {
        posted
            .iter()
            .position(|b| b["method"] == json!(method))
            .unwrap_or_else(|| panic!("`{method}` was POSTed: {posted:?}"))
    };
    let note = &posted[at("notifications/initialized")];
    assert!(
        note.get("id").is_none(),
        "a notification is POSTed with no id: {note}"
    );
    assert!(
        at("notifications/initialized") < at("tools/call"),
        "the call went on after the notification's POST, with no answer for it: {posted:?}"
    );
}

// ── row 159 legacy-rung, ladder, session and subscription findings (lane q128) ──────────────────

/// The largest integer a JavaScript peer reads back exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// RED B-H1: TWO LEGACY LINKS NEVER READ EACH OTHER'S STREAM. Bob's link reads its stream in a tick
/// cycle; Alice's link, whose key sorts ahead of Bob's, opens in the same cycle. The host answers a
/// re-issued `(ticket, seq)` from what it kept, whatever the service, so a link numbered by its place
/// in the table would be handed Bob's answers. Alice's call is answered on her own stream.
#[test]
fn two_legacy_links_never_read_each_others_stream() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (b, fields) = legacy_call(30, "b.txt");
    relayed(&d, 90, BOB, &b, &fields);
    let bob = d.pump(90, &walk_refused(BOB));
    assert_eq!(legacy_text(&bob), (json!(30), "legacy b.txt".to_string()));
    let bob_session = legacy_sessions()[0].clone();
    // A new tick cycle in which Bob's link reads two events: answered, so the host keeps them.
    let note = sse_event(
        "message",
        r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"x"}}"#,
    );
    on_stream(&bob_session, |s| {
        s.events.push_back(note.clone());
        s.events.push_back(note.clone());
    });
    d.tick();
    d.drive();
    // Alice's call opens her link in the same cycle.
    let (a, fields) = legacy_call(31, "a.txt");
    assert_eq!(
        d.arrive(91, "POST", "/mcp", &a, &fields).outcome,
        Outcome::Ready
    );
    d.piece(91, &Given::attempt(ALICE, "lg"));
    let send = d.steady(91, &Given::caller(ALICE, &a));
    assert!(send.far, "{} {}", send.status, send.text());
    let answered = d.steady(91, &walk_refused(ALICE));
    let body = answered.json();
    assert_eq!(
        body.pointer("/result/content/0/text"),
        Some(&json!("legacy a.txt")),
        "Alice's call is answered on her own stream: {body}"
    );
    let sessions = legacy_sessions();
    assert_eq!(sessions.len(), 2, "one stream per caller: {sessions:?}");
    let alice_posts: Vec<String> = legacy_calls()
        .into_iter()
        .filter(|(_, path)| path == "a.txt")
        .map(|(session, _)| session)
        .collect();
    assert!(
        !alice_posts.is_empty() && alice_posts.iter().all(|s| *s != bob_session),
        "Alice's call is POSTed in her own stream's session, never Bob's: {alice_posts:?}"
    );
}

/// RED B-H2: THE `initialize` ID ROUND-TRIPS A JAVASCRIPT SERVER: on the held stream and on a session
/// upstream, the id busbar's own `initialize` carries is an integer a JavaScript peer reads back
/// exactly.
#[test]
fn busbars_own_initialize_id_round_trips_a_javascript_server() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 92, ALICE, &a, &fields);
    let d2 = open();
    assert_eq!(
        d2.arrive(93, "POST", "/mcp", CALL, CALL_FIELDS).outcome,
        Outcome::Ready
    );
    d2.piece(93, &Given::attempt(ALICE, "fs"));
    assert!(d2.piece(93, &Given::caller(ALICE, CALL)).far);
    let ids: Vec<(String, Value)> = seen()
        .into_iter()
        .filter(|s| s.body["method"] == json!("initialize"))
        .filter(|s| s.url.contains(LEGACY_MESSAGES) || s.url.starts_with(SESSION_URL))
        .map(|s| (s.url.clone(), s.body["id"].clone()))
        .collect();
    assert_eq!(
        ids.len(),
        2,
        "one legacy and one session initialize: {ids:?}"
    );
    for (url, id) in &ids {
        assert!(
            id.as_u64().is_some_and(|n| n <= MAX_SAFE_INTEGER),
            "the initialize to {url} carries id {id}, past what a JavaScript server reads back"
        );
    }
}

/// RED B-H3: A CANCELLED INITIALIZING CALL NEVER WEDGES THE STREAM: the call running the stream's
/// `initialize` is cancelled before the answer comes; the caller's next call runs it again and is
/// answered.
#[test]
fn a_cancelled_legacy_initialize_never_wedges_the_stream() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    upstreams().as_mut().unwrap().hold_init = true;
    let (a, fields) = legacy_call(30, "a.txt");
    assert_eq!(
        d.arrive(94, "POST", "/mcp", &a, &fields).outcome,
        Outcome::Ready
    );
    d.piece(94, &Given::attempt(ALICE, "lg"));
    for _ in 0..6 {
        let got = d.piece(94, &Given::caller(ALICE, &a));
        assert_eq!(got.outcome, Some(Outcome::Pending), "{}", got.text());
        d.turn();
    }
    d.cancel(94);
    upstreams().as_mut().unwrap().hold_init = false;
    let session = legacy_sessions()[0].clone();
    on_stream(&session, |s| s.held.clear());
    let (b, fields) = legacy_call(31, "b.txt");
    assert_eq!(
        d.arrive(95, "POST", "/mcp", &b, &fields).outcome,
        Outcome::Ready
    );
    d.piece(95, &Given::attempt(ALICE, "lg"));
    let send = d.settle(95, &Given::caller(ALICE, &b));
    assert_ne!(
        send.outcome,
        Some(Outcome::Pending),
        "the next call is wedged behind the cancelled initialize"
    );
    assert!(send.far, "{} {}", send.status, send.text());
    let answered = d.settle(95, &walk_refused(ALICE));
    assert_eq!(
        answered.json().pointer("/result/content/0/text"),
        Some(&json!("legacy b.txt")),
        "{}",
        answered.text()
    );
}

/// RED B-H4: A LEGACY SERVER'S OWN REQUESTS ARE ANSWERED, never left hanging: `ping` gets its empty
/// result, an ungranted `sampling/createMessage` is refused (`-32001`), a request busbar does not
/// know is `-32601`, each POSTed to the stream's message address while the call waits.
#[test]
fn a_legacy_servers_own_requests_are_answered_on_its_message_address() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 96, ALICE, &a, &fields);
    upstreams().as_mut().unwrap().hold_calls = true;
    assert_eq!(
        d.piece(96, &walk_refused(ALICE)).outcome,
        Some(Outcome::Pending)
    );
    let session = legacy_sessions()[0].clone();
    on_stream(&session, |s| {
        for data in [
            r#"{"jsonrpc":"2.0","id":"p-1","method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":"s-1","method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}}"#,
            r#"{"jsonrpc":"2.0","id":"x-1","method":"vendor/thing"}"#,
        ] {
            s.events.push_back(sse_event("message", data));
        }
    });
    d.turn();
    assert_eq!(
        d.piece(96, &walk_refused(ALICE)).outcome,
        Some(Outcome::Pending),
        "the call still waits for its own answer"
    );
    on_stream(&session, |s| {
        let held = std::mem::take(&mut s.held);
        s.events.extend(held);
    });
    d.turn();
    let answered = d.settle(96, &walk_refused(ALICE));
    let replies: Vec<Value> = seen()
        .into_iter()
        .filter(|s| s.url.contains(LEGACY_MESSAGES) && s.body.get("method").is_none())
        .map(|s| s.body)
        .collect();
    let by = |id: &str| {
        replies
            .iter()
            .find(|r| r["id"] == json!(id))
            .cloned()
            .unwrap_or(Value::Null)
    };
    assert_eq!(by("p-1")["result"], json!({}), "ping answered: {replies:?}");
    assert_eq!(
        by("s-1")["error"]["code"],
        json!(-32001),
        "the ungranted ask refused: {replies:?}"
    );
    assert_eq!(
        by("x-1")["error"]["code"],
        json!(-32601),
        "the unknown request answered -32601: {replies:?}"
    );
    assert_eq!(
        answered.json().pointer("/result/content/0/text"),
        Some(&json!("legacy a.txt")),
        "{}",
        answered.text()
    );
}

/// RED B-H5: A FLOOD OF REPLIES NO CALL WAITS FOR is audited in a small bounded number of rows on
/// the next answer, never one row per reply.
#[test]
fn a_flood_of_unawaited_legacy_replies_is_audited_in_bounded_rows() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 97, ALICE, &a, &fields);
    upstreams().as_mut().unwrap().hold_calls = true;
    assert_eq!(
        d.piece(97, &walk_refused(ALICE)).outcome,
        Some(Outcome::Pending)
    );
    let session = legacy_sessions()[0].clone();
    on_stream(&session, |s| {
        for id in 900..910 {
            s.events.push_back(sse_event(
                "message",
                &format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{}}}}"#),
            ));
        }
        let held = std::mem::take(&mut s.held);
        s.events.extend(held);
    });
    d.turn();
    let answered = d.settle(97, &walk_refused(ALICE));
    let rows = answered
        .audits
        .iter()
        .filter(|(action, _, _)| action == "mcp_upstream.reply")
        .count();
    assert!(
        (1..=4).contains(&rows),
        "ten dropped replies are audited in a bounded number of rows, not {rows}: {:?}",
        answered.audits
    );
}

/// RED B-M6: AN IDLE HELD STREAM IS LET GO: once no call has used it for the idle bound, its
/// connection is closed at the connector.
#[test]
fn an_idle_legacy_stream_is_let_go() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 98, ALICE, &a, &fields);
    let answered = d.pump(98, &walk_refused(ALICE));
    assert_eq!(
        legacy_text(&answered),
        (json!(30), "legacy a.txt".to_string())
    );
    assert_eq!(legacy_sessions().len(), 1);
    // An hour of tick clock passes with no call on the stream.
    TICKS.fetch_add(3_600_000_000_000, Ordering::Relaxed);
    d.turn();
    d.turn();
    assert!(
        legacy_sessions().is_empty(),
        "the idle stream is closed: {:?}",
        legacy_sessions()
    );
}

/// RED B-M7: ONE OWNER HOLDS A BOUNDED NUMBER OF SESSION STREAMS: past the quota the next GET is
/// refused `429`, as a subscription past its quota is.
#[test]
fn one_owner_holds_a_bounded_number_of_session_streams() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    // Five sessions (a session keeps sixteen streams), thirteen streams on each.
    let sessions: Vec<String> = (0..5)
        .map(|n| {
            initialize(&d, 190 + n, ALICE)
                .field("mcp-session-id")
                .expect("the answer names its session")
                .to_string()
        })
        .collect();
    let mut statuses = Vec::new();
    for (n, unit) in (201..=265).enumerate() {
        let stream = [
            ("accept", "text/event-stream"),
            ("mcp-session-id", sessions[n / 13].as_str()),
            ("mcp-protocol-version", "2025-06-18"),
        ];
        assert_eq!(
            d.arrive(unit, "GET", "/mcp", b"", &stream).outcome,
            Outcome::Ready
        );
        statuses.push(d.piece(unit, &Given::stream_open(ALICE, unit)).status);
    }
    assert!(
        statuses[..64].iter().all(|s| *s == 200),
        "the first 64 streams open: {statuses:?}"
    );
    assert_eq!(
        statuses[64], 429,
        "the 65th stream of one owner is refused at the quota"
    );
}

/// RED P-M5: AN UPSTREAM'S OWN ERROR IS HANDED ON, NOT RENEGOTIATED: a stateless upstream not yet
/// remembered for this caller answers `-32602` (its own words about the call); busbar sends it no
/// `initialize` and hands the caller the upstream's answer.
#[test]
fn an_upstreams_own_error_is_handed_on_not_renegotiated() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    // Alice's call verifies `st`; Bob's, inside its verify_ttl, fetches nothing, so `st` is not
    // remembered for Bob.
    assert_eq!(
        d.arrive(54, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(54, &Given::attempt(ALICE, "st"));
    assert!(d.piece(54, &Given::caller(ALICE, ST_CALL)).far);
    assert_eq!(
        d.arrive(55, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(55, &Given::attempt(BOB, "st"));
    assert!(d.piece(55, &Given::caller(BOB, ST_CALL)).far);
    let before = seen().len();
    let own =
        br#"{"jsonrpc":"2.0","id":0,"error":{"code":-32602,"message":"Unknown tool: read_file"}}"#;
    let answered = d.settle(55, &Given::far(BOB, 200, vec![JSON_TYPE], own));
    let after: Vec<Seen> = seen().into_iter().skip(before).collect();
    assert!(
        after
            .iter()
            .all(|s| s.body["method"] != json!("initialize")),
        "no initialize follows the upstream's own error: {after:?}"
    );
    let text = answered.text();
    assert!(
        text.contains("Unknown tool: read_file") && !text.contains("refused the stateless"),
        "the upstream's own error reaches the caller: {text}"
    );
}

/// RED P-M10: A `subscriptions/listen` THAT ASKED FOR A RESOURCE HEARS ITS UPDATE: the announcing
/// server's `notifications/resources/updated`, heard beside a relayed call's answer, reaches the
/// held subscription.
#[test]
fn a_listen_subscription_hears_the_upstreams_resource_update() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let listen = br#"{"jsonrpc":"2.0","id":80,"method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":["file:///readme"]},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let fields = [
        ACCEPT_BOTH,
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "subscriptions/listen"),
    ];
    let arrived = d.arrive(110, "POST", "/mcp", listen, &fields);
    assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
    let opened = d.piece(110, &Given::stream_open(ALICE, 110));
    assert!(
        opened.text().contains("acknowledged"),
        "the subscription is acknowledged: {} {}",
        opened.status,
        opened.text()
    );
    assert_eq!(
        d.arrive(111, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(111, &Given::attempt(BOB, "st"));
    assert!(d.piece(111, &Given::caller(BOB, ST_CALL)).far);
    let far = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\",\"params\":{\"uri\":\"file:///readme\"}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"content\":[],\"resultType\":\"complete\"}}\n\n";
    let answered = d.piece(
        111,
        &Given::far(BOB, 200, vec![("content-type", "text/event-stream")], far),
    );
    assert_eq!(answered.status, 200);
    let delivered = d.piece(110, &Given::collect(ALICE, 110)).text();
    assert!(
        delivered.contains(r#""method":"notifications/resources/updated""#)
            && delivered.contains("file:///readme"),
        "the subscription hears the update: {delivered:?}"
    );
}

/// RED B-L12: THE LEGACY GET CARRIES NO STATELESS MIRROR HEADERS: the stream's `GET` names no
/// `mcp-protocol-version`, `mcp-method` or `mcp-name` (a `2024-11-05` server reads none of them).
#[test]
fn the_legacy_get_carries_no_stateless_mirror_headers() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 99, ALICE, &a, &fields);
    let get = seen()
        .into_iter()
        .find(|s| s.url == LEGACY_URL && s.body.is_null())
        .expect("the stream's GET");
    for name in ["mcp-protocol-version", "mcp-method", "mcp-name"] {
        assert!(
            field_of(&get.fields, name).is_none(),
            "the GET carries `{name}`: {:?}",
            get.fields
        );
    }
}

/// RED: A SESSION REVISION'S ANSWER IS THE UPSTREAM'S OWN BYTES: a `tools/call` in a `2025-06-18`
/// session reaches its caller with the upstream's result members in the upstream's order and its
/// numbers as the upstream spelt them (`1.0`, `1e3`), only the stateless-only members cut out.
/// RED: the answer was parsed and printed again, its members sorted and `1e3` re-spelt `1000.0`.
#[test]
fn a_session_answer_is_relayed_byte_for_byte() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let init = initialize(&d, 120, ALICE);
    let session = init
        .field("mcp-session-id")
        .expect("the answer names its session")
        .to_string();
    let call = br#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"st_read_file","arguments":{}}}"#;
    let fields = [
        ACCEPT_BOTH,
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    let arrived = d.arrive(121, "POST", "/mcp", call, &fields);
    assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
    d.piece(121, &Given::attempt(ALICE, "st"));
    let send = d.pump(121, &Given::caller(ALICE, call));
    assert!(
        send.far,
        "the call is relayed: {} {}",
        send.status,
        send.text()
    );
    let far = br#"{"jsonrpc":"2.0","id":0,"result":{"zeta":1.0,"content":[{"type":"text","text":"x"}],"resultType":"complete","alpha":1e3,"ttlMs":5}}"#;
    let answered = d.settle(121, &Given::far(ALICE, 200, vec![JSON_TYPE], far));
    assert_eq!(answered.status, 200, "{}", answered.text());
    assert_eq!(
        answered.text(),
        r#"{"id":5,"jsonrpc":"2.0","result":{"zeta":1.0,"content":[{"type":"text","text":"x"}],"alpha":1e3}}"#,
        "the upstream's own bytes, only the stateless-only members cut"
    );
}

/// RED: A `2024-11-05` UPSTREAM'S ANSWER IS ITS OWN BYTES even when its log records ride ahead of
/// it: the caller reads the result's members in the upstream's order and its numbers as spelt.
/// RED: with a frame riding, the answer was parsed and printed again.
#[test]
fn a_legacy_answer_with_frames_is_relayed_byte_for_byte() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    let (a, fields) = legacy_call(30, "a.txt");
    relayed(&d, 122, ALICE, &a, &fields);
    upstreams().as_mut().unwrap().hold_calls = true;
    assert_eq!(
        d.piece(122, &walk_refused(ALICE)).outcome,
        Some(Outcome::Pending)
    );
    let session = legacy_sessions()[0].clone();
    on_stream(&session, |s| {
        let held = std::mem::take(&mut s.held);
        let text = String::from_utf8(held[0].clone()).unwrap();
        let data = text
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("the held answer");
        let id = serde_json::from_str::<Value>(data).unwrap()["id"].clone();
        s.events.push_back(sse_event(
            "message",
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"working"}}"#,
        ));
        s.events.push_back(sse_event(
            "message",
            &format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"zeta":1.0,"content":[{{"type":"text","text":"legacy a.txt"}}],"alpha":1e3}}}}"#
            ),
        ));
    });
    d.turn();
    let answered = d.pump(122, &walk_refused(ALICE));
    assert_eq!(answered.status, 200, "{}", answered.text());
    assert!(
        answered.text().contains(
            r#""zeta":1.0,"content":[{"type":"text","text":"legacy a.txt"}],"alpha":1e3}"#
        ),
        "the upstream's own bytes: {}",
        answered.text()
    );
}

/// A `tools/call` of `name` asking for progress under the caller's token `p`.
fn progress_call(name: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "progressToken": "p",
            },
        },
    }))
    .unwrap()
}

/// RED: TWO CALLS IN FLIGHT NEVER SHARE A PROGRESS TOKEN: two first-round calls to a stateless
/// upstream carry two tokens, and a call lowered into a session carries the token of the id it is
/// sent under. RED: every first round carried `busbar-0`, the round's id.
#[test]
fn calls_in_flight_never_share_a_progress_token() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let call = progress_call("st_read_file");
    let mut tokens = Vec::new();
    for unit in [130, 131] {
        assert_eq!(
            d.arrive(unit, "POST", "/mcp", &call, ST_FIELDS).outcome,
            Outcome::Ready
        );
        d.piece(unit, &Given::attempt(ALICE, "st"));
        let send = d.pump(unit, &Given::caller(ALICE, &call));
        assert!(send.far, "{} {}", send.status, send.text());
        let sent: Value = serde_json::from_slice(&send.bytes).expect("a JSON-RPC request");
        assert_eq!(sent["id"], json!(0), "the stateless round's id: {sent}");
        tokens.push(sent["params"]["_meta"]["progressToken"].clone());
    }
    assert!(
        tokens
            .iter()
            .all(|t| t.as_str().is_some_and(|t| t.starts_with("busbar-"))),
        "busbar's own tokens: {tokens:?}"
    );
    assert_ne!(tokens[0], tokens[1], "two calls in flight shared a token");

    let call = progress_call("fs_read_file");
    assert_eq!(
        d.arrive(132, "POST", "/mcp", &call, CALL_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(132, &Given::attempt(ALICE, "fs"));
    let send = d.pump(132, &Given::caller(ALICE, &call));
    assert!(send.far, "{} {}", send.status, send.text());
    let sent: Value = serde_json::from_slice(&send.bytes).expect("a JSON-RPC request");
    assert_eq!(
        send.field("mcp-session-id"),
        Some(UPSTREAM_SESSION),
        "lowered into the session"
    );
    assert_eq!(
        sent["params"]["_meta"]["progressToken"],
        json!(format!("busbar-{}", sent["id"])),
        "the token of the id the call is sent under: {sent}"
    );
    assert!(!tokens.contains(&sent["params"]["_meta"]["progressToken"]));
}

/// RED: A HELD STREAM IS NEVER ENDED TO MAKE ROOM: past the streams one session keeps, the next GET
/// is refused `429`, and the first stream still collects what its session buffers. RED: the next
/// GET dropped the first stream's cursor, and that stream ended at its next collection.
#[test]
fn a_held_stream_is_never_ended_for_another() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let session = initialize(&d, 140, ALICE)
        .field("mcp-session-id")
        .expect("the answer names its session")
        .to_string();
    let stream = [
        ("accept", "text/event-stream"),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    let mut statuses = Vec::new();
    for unit in 141..=157 {
        assert_eq!(
            d.arrive(unit, "GET", "/mcp", b"", &stream).outcome,
            Outcome::Ready
        );
        statuses.push(d.piece(unit, &Given::stream_open(ALICE, unit)).status);
    }
    assert!(
        statuses[..16].iter().all(|s| *s == 200),
        "a session keeps sixteen streams: {statuses:?}"
    );
    assert_eq!(
        statuses[16], 429,
        "the seventeenth is refused: {statuses:?}"
    );
    // The first stream is still live: a collection writes no end of stream.
    d.turn();
    let collected = d.piece(141, &Given::collect(ALICE, 141));
    assert!(
        !collected.done,
        "the first stream was ended for the seventeenth: {}",
        collected.text()
    );
}

/// Opens a `2024-11-05` stream on `unit` as `caller`: the message address its endpoint event names.
fn legacy_stream(d: &Door, unit: u64, caller: &str) -> String {
    let opened = d.arrive(unit, "GET", "/mcp", b"", &[("accept", "text/event-stream")]);
    assert_eq!(opened.outcome, Outcome::Ready, "{opened:?}");
    let text = d.piece(unit, &Given::stream_open(caller, unit)).text();
    text.strip_prefix("event: endpoint\ndata: ")
        .and_then(|rest| rest.split('\n').next())
        .unwrap_or_else(|| panic!("the stream opens with the endpoint event: {text:?}"))
        .to_string()
}

/// RED: A `2024-11-05` SESSION ENDS WITH ITS STREAM: once the caller's stream ended (or its op was
/// cancelled), a message POSTed to its address is told the session is unknown (`404`) and is not
/// run. RED: the session outlived its stream, the message ran, and it was answered `202` with its
/// answer dropped.
#[test]
fn a_legacy_session_ends_with_its_stream() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let list = br#"{"jsonrpc":"2.0","id":9,"method":"tools/list"}"#;
    let json_type = [("content-type", "application/json")];

    // The caller's side of the stream ends.
    let address = legacy_stream(&d, 150, ALICE);
    let ended = d.piece(
        150,
        &Given {
            stream: 150,
            ..Given::caller(ALICE, b"")
        },
    );
    assert!(ended.done, "the stream ends: {}", ended.text());
    assert_eq!(
        d.arrive(151, "POST", &address, list, &json_type).outcome,
        Outcome::Ready
    );
    let posted = d.piece(151, &Given::caller(ALICE, list));
    assert_eq!(posted.status, 404, "{}", posted.text());

    // The stream's op is cancelled.
    let address = legacy_stream(&d, 152, ALICE);
    d.cancel(152);
    assert_eq!(
        d.arrive(153, "POST", &address, list, &json_type).outcome,
        Outcome::Ready
    );
    let posted = d.piece(153, &Given::caller(ALICE, list));
    assert_eq!(posted.status, 404, "{}", posted.text());
}

/// THE UNGOVERNED CHAIN'S DIAGNOSTIC IS REPORTED ONCE PER INSTANCE, on its first `2024-11-05`
/// stream: that stream's reply carries it, and the latch is set only by a carried report, so the
/// next ungoverned stream carries none. A governed caller's stream never carries it.
#[test]
fn the_ungoverned_legacy_diagnostic_is_reported_once_when_carried() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let opened = |unit: u64, caller: &str| {
        let arrived = d.arrive(unit, "GET", "/mcp", b"", &[("accept", "text/event-stream")]);
        assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
        d.piece(unit, &Given::stream_open(caller, unit))
    };
    assert_eq!(
        opened(170, ALICE).diags,
        0,
        "a governed caller's stream says nothing"
    );
    let first = opened(171, "");
    assert_eq!(first.status, 200, "{}", first.text());
    assert_eq!(
        first.diags, 1,
        "the first ungoverned stream carries the diagnostic"
    );
    assert_eq!(opened(172, "").diags, 0, "latched: said once per instance");
}

// ── a subscription is recorded, never sent upstream (predev's model) ───────────────────────────

/// `initialize` as `caller` on `unit`: the session it opened.
fn open_session(d: &Door, unit: u64, caller: &str) -> String {
    initialize(d, unit, caller)
        .field("mcp-session-id")
        .expect("the answer names its session")
        .to_string()
}

/// `body` POSTed in `session` as `caller` on `unit`: its answer, on one piece (nothing pends).
fn session_post(d: &Door, unit: u64, session: &str, caller: &str, body: &[u8]) -> Answered {
    let fields = [
        ACCEPT_BOTH,
        ("mcp-session-id", session),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    assert_eq!(
        d.arrive(unit, "POST", "/mcp", body, &fields).outcome,
        Outcome::Ready
    );
    d.piece(unit, &Given::caller(caller, body))
}

/// predev's acknowledgement of a session's `resources/subscribe` or `resources/unsubscribe` with
/// JSON-RPC id `id`: `ok(json!({}))` (gh/predev crates/busbar-plane-mcp/src/door_sessions.rs
/// l.664-665, l.712 and l.729), whose envelope is `line::result` (line.rs l.50-51).
fn predev_session_ack(id: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": {} })).unwrap()
}

/// The resource subscription frames busbar sent any member over the connector.
fn subscription_frames() -> Vec<(String, String)> {
    seen()
        .into_iter()
        .filter_map(|s| {
            let method = s.body["method"].as_str()?.to_string();
            matches!(
                method.as_str(),
                "resources/subscribe" | "resources/unsubscribe"
            )
            .then(|| (s.url, method))
        })
        .collect()
}

/// RED: A SESSION'S SUBSCRIPTION IS RECORDED, NEVER SENT UPSTREAM, as predev held it
/// (gh/predev crates/busbar-plane-mcp/src/door_sessions.rs l.687-731: the uri resolved under the
/// caller's grants and recorded under the owner's quota, `{}` answered, the member sent nothing;
/// what the member announces reaches the session, `announce` l.800). Subscribe and unsubscribe are each
/// acknowledged with predev's bytes exactly, and no `resources/subscribe` or
/// `resources/unsubscribe` reaches a member. RED: busbar sent the declaring member both.
#[test]
fn a_session_subscription_sends_its_member_nothing() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let session = open_session(&d, 240, ALICE);
    let subscribe =
        br#"{"jsonrpc":"2.0","id":3,"method":"resources/subscribe","params":{"uri":"file:///readme"}}"#;
    let unsubscribe =
        br#"{"jsonrpc":"2.0","id":4,"method":"resources/unsubscribe","params":{"uri":"file:///readme"}}"#;
    let subscribed = session_post(&d, 241, &session, ALICE, subscribe);
    assert_eq!(subscribed.outcome, Some(Outcome::Ready));
    assert_eq!(subscribed.status, 200, "{}", subscribed.text());
    assert_eq!(
        subscribed.bytes,
        predev_session_ack(3),
        "predev's acknowledgement: {}",
        subscribed.text()
    );
    let dropped = session_post(&d, 242, &session, ALICE, unsubscribe);
    assert_eq!(dropped.status, 200, "{}", dropped.text());
    assert_eq!(
        dropped.bytes,
        predev_session_ack(4),
        "predev's acknowledgement: {}",
        dropped.text()
    );
    assert!(
        subscription_frames().is_empty(),
        "no subscription frame reached a member: {:?}",
        subscription_frames()
    );
}

/// RED: A `subscriptions/listen` OF A RESOURCE IS ACKNOWLEDGED AT ONCE AND SENDS NOTHING UPSTREAM,
/// as predev held it (gh/predev crates/busbar-plane-mcp/src/door_listen.rs l.182-253 opened it and
/// stepped it once, l.256-290; the acknowledgement is subscribe.rs l.231 and l.249-256 tagged
/// notification `notifications/subscriptions/acknowledged` carrying the accepted filter, l.300-307,
/// framed as one `message` event, framing.rs l.197-212; the member's announcements are relayed,
/// subscribe.rs l.328-347). The first piece answers predev's bytes exactly and no
/// `resources/subscribe` reaches a member. RED: the open pended on busbar's own
/// `resources/subscribe` to the declaring member.
#[test]
fn a_listen_subscription_sends_its_member_nothing() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let listen = br#"{"jsonrpc":"2.0","id":81,"method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":["file:///readme"]},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let fields = [
        ACCEPT_BOTH,
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "subscriptions/listen"),
    ];
    let arrived = d.arrive(250, "POST", "/mcp", listen, &fields);
    assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
    let opened = d.piece(250, &Given::stream_open(ALICE, 250));
    assert_eq!(opened.outcome, Some(Outcome::Ready), "{}", opened.text());
    assert_eq!(opened.status, 200, "{}", opened.text());
    let ack = json!({
        "jsonrpc": "2.0",
        "method": "notifications/subscriptions/acknowledged",
        "params": {
            "notifications": { "resourceSubscriptions": ["file:///readme"] },
            "_meta": { "io.modelcontextprotocol/subscriptionId": 81 },
        },
    });
    let predev = format!(
        "event: message\ndata: {}\n\n",
        serde_json::to_string(&ack).unwrap()
    );
    assert_eq!(
        opened.text(),
        predev,
        "predev's acknowledgement, on the first piece"
    );
    assert!(
        subscription_frames().is_empty(),
        "no subscription frame reached a member: {:?}",
        subscription_frames()
    );
}

/// The section with one `transport: stdio` member declaring a resource.
const STDIO_SECTION: &str = r#"{
    "io": {"transport": "stdio", "command": "/usr/bin/true", "pin": {"mechanism": "unpinned"}, "tools_allow": {"read_file": {}}, "resources_allow": {"file:///notes": {"name": "notes", "text": "hi"}}}
}"#;

/// A STDIO MEMBER'S RESOURCE SUBSCRIPTION IS ACKNOWLEDGED AND SENDS THE CHILD NOTHING, as predev
/// held it (gh/predev crates/busbar-plane-mcp/src/door_sessions.rs l.687-731, the same for every
/// transport; the child's own `notifications/resources/updated`, heard beside a relayed exchange,
/// reaches the watchers, door_program.rs l.308-310 and tool_program.rs l.378-381). Subscribe and
/// unsubscribe are acknowledged with predev's bytes exactly, and nothing is sent for them.
#[test]
fn a_stdio_members_resource_subscription_is_acknowledged() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(STDIO_SECTION);
    let session = open_session(&d, 230, ALICE);
    let subscribe =
        br#"{"jsonrpc":"2.0","id":3,"method":"resources/subscribe","params":{"uri":"file:///notes"}}"#;
    let unsubscribe =
        br#"{"jsonrpc":"2.0","id":4,"method":"resources/unsubscribe","params":{"uri":"file:///notes"}}"#;
    let subscribed = session_post(&d, 231, &session, ALICE, subscribe);
    assert_eq!(subscribed.status, 200, "{}", subscribed.text());
    assert_eq!(
        subscribed.bytes,
        predev_session_ack(3),
        "predev's acknowledgement: {}",
        subscribed.text()
    );
    let dropped = session_post(&d, 232, &session, ALICE, unsubscribe);
    assert_eq!(
        dropped.bytes,
        predev_session_ack(4),
        "predev's acknowledgement: {}",
        dropped.text()
    );
    assert!(
        seen().is_empty(),
        "nothing was sent for it: {:?}",
        subscription_frames()
    );
}

// ── a member's resource update reaches a listen subscriber once ────────────────────────────────

/// The stateless member's `notifications/resources/updated` for the readme, as the member spells
/// it: members out of the usual order and a number in an unusual spelling, so bytes handed on
/// unread could be told from bytes re-encoded.
const MEMBER_UPDATE: &str = r#"{"params":{"uri":"file:///readme","revision":1.50E+1},"method":"notifications/resources/updated","jsonrpc":"2.0"}"#;

/// The relayed call's far answer: the member's update, then the call's own answer.
fn far_with_update() -> Vec<u8> {
    format!(
        "event: message\ndata: {MEMBER_UPDATE}\n\nevent: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{{\"content\":[],\"resultType\":\"complete\"}}}}\n\n"
    )
    .into_bytes()
}

/// predev's relay of a member's update of `uri` to the subscription opened under id `id`: a
/// notification of the subscription's own, `{"uri"}` tagged with its subscription id
/// (gh/predev crates/busbar-plane-mcp/src/subscribe.rs l.328-345 and `notification` l.249-256),
/// never the member's bytes: the member's other params and its spelling are not handed on.
fn predev_relayed_update(uri: &str, id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated",
        "params": {
            "uri": uri,
            "_meta": { "io.modelcontextprotocol/subscriptionId": id },
        },
    })
}

/// A MEMBER'S RESOURCE UPDATE REACHES AN HTTP LISTEN SUBSCRIBER EXACTLY ONCE, as predev relayed it
/// (gh/predev crates/busbar-plane-mcp/src/subscribe.rs l.328-345; door_listen.rs l.256-290 frames
/// it as one `message` event, framing.rs l.197-212): the collection after the member announced it
/// carries predev's frame byte for byte (re-encoded under the subscription's id, not the member's
/// bytes), and no further tick or collection delivers it again.
#[test]
fn a_members_update_reaches_a_listen_subscriber_exactly_once() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let listen = br#"{"jsonrpc":"2.0","id":82,"method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":["file:///readme"]},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let fields = [
        ACCEPT_BOTH,
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "subscriptions/listen"),
    ];
    assert_eq!(
        d.arrive(260, "POST", "/mcp", listen, &fields).outcome,
        Outcome::Ready
    );
    let opened = d.piece(260, &Given::stream_open(ALICE, 260));
    assert!(opened.text().contains("acknowledged"), "{}", opened.text());

    assert_eq!(
        d.arrive(261, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(261, &Given::attempt(BOB, "st"));
    assert!(d.piece(261, &Given::caller(BOB, ST_CALL)).far);
    let far = far_with_update();
    let answered = d.piece(
        261,
        &Given::far(BOB, 200, vec![("content-type", "text/event-stream")], &far),
    );
    assert_eq!(answered.status, 200, "{}", answered.text());

    let delivered = d.piece(260, &Given::collect(ALICE, 260)).text();
    let predev = format!(
        "event: message\ndata: {}\n\n",
        serde_json::to_string(&predev_relayed_update("file:///readme", 82)).unwrap()
    );
    assert_eq!(delivered, predev, "predev's relay of the member's update");
    assert!(
        !delivered.contains(MEMBER_UPDATE),
        "the member's own bytes are not handed on: {delivered:?}"
    );
    for _ in 0..4 {
        d.turn();
        let again = d.piece(260, &Given::collect(ALICE, 260)).text();
        assert!(
            !again.contains("notifications/resources/updated"),
            "the update was delivered a second time: {again:?}"
        );
    }
}
