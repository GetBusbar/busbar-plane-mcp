// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TASK, RUN THROUGH THE DOOR (SEP-2663, ARCHITECT round 5 Q-L3B-TASKS (b) → (A)): a `tools/call`
//! answered with a task, its continuation nested on the task-run claim and sent to its member, its
//! verbs answered from the host's records. The door is driven over its own ABI, op by op, under a
//! host whose services are stand-ins written in this file: a clock, the kernel's entitlement and
//! trust answers (all yes), a signer, a counting `random.fill`, the work book (`work.*`), the
//! plane's own records (`records.list`, `records.claim`, and every record write the door's answers
//! carry), `unit.nest` (each nested body kept for the test to run as the kernel would), and
//! upstreams behind the connector: one that requires a session and one that speaks the stateless
//! revision.
//!
//! What it holds the task path to (row 159 mcp audit, area tasks): the continuation's call to its
//! member is the synchronous call's member-send — a `token_exchange:` member's caller down-scope
//! (C-H2), the client ladder to an upstream that requires a session and a `transport: stdio`
//! member's child (C-H3), the bound on the caller's reply to a relayed ask (C-M4); a task's result
//! is kept in the host's records whole or refused in words (P-M6); a caller cannot drive its own
//! task's continuation on the task-run claim (P-M9); and a create settles every page of its
//! caller's left-behind tasks (C-L10).

#![allow(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::host::conn::connector::{
    ConnectorSlots, EstablishIn, ReplyIn, ReplyPiece, RequestIn, RequestPiece, StreamIn,
    REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY, REQUEST_HEAD, SERVICES as CONN_SERVICES,
};
use busbar_contract::abi::host::service::{
    ClockNowIn, HostSlots, ItemSpan, RandomFillIn, RecordsClaimIn, RecordsListIn, ServiceOut,
    SignIn, UnitNestIn, WorkFindIn, WorkOpenIn, WorkResumeIn, WorkSettleIn, CLAIM_TAKEN, CLAIM_WON,
    DISTRUST_NONE, ENTITLED, SERVICES as HOST_SERVICES, TRUST_NEW, WORK_LIVE, WORK_SETTLED,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, OutHead, Outcome, RawOutcome, Span, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, OpsHead};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, Ops, OutField, PlaneOpenIn, PlaneOpenOut,
    RecordWrite, UnitCount, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
    PIECE_HAS_STATUS, PIECE_LAST, RECORD_PUT,
};
use busbar_contract::abi::transport::FrameSpan;
use busbar_plane_mcp::tool_tasks::{index_key, TaskLease, WorkRow};
use busbar_plane_mcp::{codec, door, tool_claims, tool_door, tool_tasks};
use serde_json::{json, Value};

// ── the host's services ─────────────────────────────────────────────────────────────────────────

fn answer(out: *mut ServiceOut, outcome: Outcome, value: u64, len: u64, items: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(outcome),
            _reserved: [0; 3],
            value,
            len,
            items,
            needed_bytes: 0,
            needed_items: 0,
            error: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
        });
    }
    RawOutcome::of(outcome)
}

fn ready(out: *mut ServiceOut, value: u64, len: u64, items: u64) -> RawOutcome {
    answer(out, Outcome::Ready, value, len, items)
}

fn refused(out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Refused, 0, 0, 0)
}

/// The bytes an `AbiStr` names (none for an absent one).
fn str_bytes(s: AbiStr) -> Vec<u8> {
    if s.ptr.is_null() || s.len == 0 {
        return Vec::new();
    }
    // SAFETY: the SDK's text, live for the call.
    unsafe { std::slice::from_raw_parts(s.ptr, s.len) }.to_vec()
}

/// The bytes a `Blob` names.
fn blob_bytes(b: Blob) -> Vec<u8> {
    if b.ptr.is_null() || b.len == 0 {
        return Vec::new();
    }
    // SAFETY: the SDK's bytes, live for the call.
    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
}

fn span(offset: usize, len: usize) -> Span {
    Span {
        offset: offset as u32,
        len: len as u32,
    }
}

const ABSENT_SPAN: Span = Span {
    offset: SPAN_ABSENT,
    len: 0,
};

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
    ready(out, 0, 0, 0)
}

extern "C" fn entitled(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    ready(out, ENTITLED, 0, 0)
}

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
    ready(out, 0, i.len, 0)
}

extern "C" fn serves(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    ready(out, DISTRUST_NONE, 0, 0)
}

extern "C" fn sighted(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    ready(out, TRUST_NEW, 0, 0)
}

/// A signer: key id `k`, the signature the data's digest (64 bytes), so a seal opens only as made.
extern "C" fn sign(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `SignIn` naming its live data and buffers.
    let i = unsafe { input.cast::<SignIn>().read() };
    let data = blob_bytes(i.data);
    let digest = busbar_contract::redacted::sha256_hex(&data);
    // SAFETY: the SDK's buffers, at least 65 bytes and one span.
    unsafe {
        *i.into.buf = b'k';
        std::ptr::copy_nonoverlapping(digest.as_ptr(), i.into.buf.add(1), 64);
        *i.into.spans = ItemSpan {
            key: span(0, 1),
            value: span(1, 64),
        };
    }
    ready(out, 0, 65, 1)
}

/// ONE WORK HANDLE as the stand-in book keeps it.
#[derive(Clone, Debug)]
struct Work {
    reference: String,
    live: bool,
    record: Vec<u8>,
}

/// THE STAND-IN HOST'S STATE, shared by every door the test opens (the nodes of one deployment).
#[derive(Default)]
struct Book {
    next: u64,
    works: HashMap<u64, Work>,
    /// Every settle that landed: the handle and its record.
    settles: Vec<(u64, Vec<u8>)>,
    /// Every nested unit: its target and body.
    nested: Vec<(String, Vec<u8>)>,
    claims: HashSet<(Vec<u8>, Vec<u8>)>,
    /// The plane's records of the task kind, by key.
    records: BTreeMap<Vec<u8>, Vec<u8>>,
}

static BOOK: Mutex<Option<Book>> = Mutex::new(None);

fn book() -> MutexGuard<'static, Option<Book>> {
    BOOK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn with_book<R>(f: impl FnOnce(&mut Book) -> R) -> R {
    let mut b = book();
    f(b.get_or_insert_with(Book::default))
}

/// A live handle in the book under `reference`, with `record`: its number.
fn open_work(b: &mut Book, reference: String, record: Vec<u8>) -> u64 {
    b.next += 1;
    let handle = b.next;
    b.works.insert(
        handle,
        Work {
            reference,
            live: true,
            record,
        },
    );
    handle
}

/// Write a found handle (state byte and record) into the SDK's buffers.
///
/// # Safety
///
/// `buf` names at least `cap` writable bytes and `spans` at least one span.
unsafe fn write_found(buf: *mut u8, cap: usize, spans: *mut ItemSpan, w: &Work) -> Option<u64> {
    let n = 1 + w.record.len();
    if n > cap {
        return None;
    }
    *buf = if w.live { WORK_LIVE } else { WORK_SETTLED };
    std::ptr::copy_nonoverlapping(w.record.as_ptr(), buf.add(1), w.record.len());
    *spans = ItemSpan {
        key: span(0, 1),
        value: span(1, w.record.len()),
    };
    Some(n as u64)
}

extern "C" fn work_open(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `WorkOpenIn`.
    let i = unsafe { input.cast::<WorkOpenIn>().read() };
    let record = blob_bytes(i.record);
    let (handle, reference) = with_book(|b| {
        let reference = format!("{:032x}", 0xabc0_0000_u64 + b.next + 1);
        (open_work(b, reference.clone(), record), reference)
    });
    // SAFETY: the SDK's buffers, at least 32 bytes and one span.
    unsafe {
        std::ptr::copy_nonoverlapping(reference.as_ptr(), i.into.buf, 32);
        *i.into.spans = ItemSpan {
            key: span(0, 32),
            value: ABSENT_SPAN,
        };
    }
    ready(out, handle, 32, 1)
}

extern "C" fn work_find(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `WorkFindIn`.
    let i = unsafe { input.cast::<WorkFindIn>().read() };
    let reference = String::from_utf8_lossy(&str_bytes(i.reference)).into_owned();
    let found = with_book(|b| {
        b.works
            .iter()
            .find(|(_, w)| w.reference == reference)
            .map(|(h, w)| (*h, w.clone()))
    });
    let Some((handle, w)) = found else {
        return ready(out, 0, 0, 0);
    };
    // SAFETY: the SDK's buffers.
    match unsafe { write_found(i.into.buf, i.into.cap, i.into.spans, &w) } {
        Some(n) => ready(out, handle, n, 1),
        None => refused(out),
    }
}

extern "C" fn work_resume(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `WorkResumeIn`.
    let i = unsafe { input.cast::<WorkResumeIn>().read() };
    let Some(w) = with_book(|b| b.works.get(&i.handle).cloned()) else {
        return refused(out);
    };
    // SAFETY: the SDK's buffers.
    match unsafe { write_found(i.into.buf, i.into.cap, i.into.spans, &w) } {
        Some(n) => ready(out, 0, n, 1),
        None => refused(out),
    }
}

extern "C" fn work_settle(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `WorkSettleIn`.
    let i = unsafe { input.cast::<WorkSettleIn>().read() };
    let record = blob_bytes(i.record);
    let landed = with_book(|b| match b.works.get_mut(&i.handle) {
        Some(w) if w.live => {
            w.live = false;
            w.record.clone_from(&record);
            b.settles.push((i.handle, record));
            true
        }
        _ => false,
    });
    if landed {
        ready(out, 0, 0, 0)
    } else {
        refused(out)
    }
}

extern "C" fn unit_nest(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `UnitNestIn` over its own buffers (at least one span).
    let i = unsafe { input.cast::<UnitNestIn>().read() };
    let target = String::from_utf8_lossy(&str_bytes(i.target)).into_owned();
    let body = blob_bytes(i.body);
    with_book(|b| b.nested.push((target, body)));
    // SAFETY: as above.
    unsafe {
        *i.into.spans = ItemSpan {
            key: ABSENT_SPAN,
            value: span(0, 0),
        };
    }
    ready(out, 200, 0, 1)
}

extern "C" fn records_claim(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `RecordsClaimIn`.
    let i = unsafe { input.cast::<RecordsClaimIn>().read() };
    let key = (str_bytes(i.kind), str_bytes(i.key));
    let won = with_book(|b| b.claims.insert(key));
    ready(out, if won { CLAIM_WON } else { CLAIM_TAKEN }, 0, 0)
}

extern "C" fn records_list(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `RecordsListIn` over its own buffers.
    let i = unsafe { input.cast::<RecordsListIn>().read() };
    let (prefix, after) = (str_bytes(i.prefix), str_bytes(i.after));
    let limit = if i.limit == 0 {
        usize::MAX
    } else {
        i.limit as usize
    };
    let rows: Vec<(Vec<u8>, Vec<u8>)> = with_book(|b| {
        b.records
            .iter()
            .filter(|(k, v)| k.starts_with(&prefix) && !v.is_empty())
            .filter(|(k, _)| after.is_empty() || k.as_slice() > after.as_slice())
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    });
    let bytes: usize = rows.iter().map(|(k, v)| k.len() + v.len()).sum();
    if bytes > i.into.cap || rows.len() > i.into.spans_cap {
        // SAFETY: the SDK's `out`.
        unsafe {
            out.write(ServiceOut {
                size: std::mem::size_of::<ServiceOut>() as u32,
                outcome: RawOutcome::of(Outcome::Failed),
                _reserved: [0; 3],
                value: 0,
                len: 0,
                items: 0,
                needed_bytes: bytes as u64,
                needed_items: rows.len() as u64,
                error: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
            });
        }
        return RawOutcome::of(Outcome::Failed);
    }
    let mut at = 0;
    for (n, (k, v)) in rows.iter().enumerate() {
        // SAFETY: the SDK's buffers, checked above to hold every row.
        unsafe {
            std::ptr::copy_nonoverlapping(k.as_ptr(), i.into.buf.add(at), k.len());
            std::ptr::copy_nonoverlapping(v.as_ptr(), i.into.buf.add(at + k.len()), v.len());
            *i.into.spans.add(n) = ItemSpan {
                key: span(at, k.len()),
                value: span(at + k.len(), v.len()),
            };
        }
        at += k.len() + v.len();
    }
    ready(out, 0, at as u64, rows.len() as u64)
}

static HOST_SLOTS: HostSlots = HostSlots {
    size: std::mem::size_of::<HostSlots>() as u32,
    slots: HOST_SERVICES,
    clock_now: Some(clock_now),
    records_get: None,
    records_list: Some(records_list),
    records_claim: Some(records_claim),
    dest_judge: None,
    sign: Some(sign),
    unit_nest: Some(unit_nest),
    work_open: Some(work_open),
    work_find: Some(work_find),
    work_settle: Some(work_settle),
    work_resume: Some(work_resume),
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
};

// ── the upstreams behind the connector ──────────────────────────────────────────────────────────

/// The upstream that requires a session.
const SESSION_URL: &str = "https://up.example/sess";
/// The session it names.
const UPSTREAM_SESSION: &str = "up-session-1";

/// One open exchange: where it goes, what it sent so far, and its reply once the request ended.
#[derive(Default)]
struct Wire {
    url: String,
    head: Vec<(String, String)>,
    body: Vec<u8>,
    reply: Option<(u32, Vec<(String, String)>, Vec<u8>)>,
    step: u8,
}

#[derive(Default)]
struct Upstreams {
    next: u64,
    open: HashMap<u64, Wire>,
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

/// What an upstream answers one request over the connector (the door's own fetches): the session
/// upstream requires `initialize` first; every other upstream speaks the stateless revision.
fn upstream_answer(
    url: &str,
    fields: &[(String, String)],
    body: &Value,
) -> (u32, Vec<(String, String)>, Vec<u8>) {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let tools = json!({"tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]});
    if !url.starts_with(SESSION_URL) {
        return match method {
            "tools/list" => (200, json_head(), rpc_result(&id, tools)),
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
        _ => (404, Vec::new(), Vec::new()),
    }
}

fn frame(buf: &[u8], s: FrameSpan) -> &[u8] {
    let at = usize::try_from(s.offset).unwrap();
    &buf[at..at + usize::try_from(s.len).unwrap()]
}

extern "C" fn establish(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands an `EstablishIn`.
    let i = unsafe { input.cast::<EstablishIn>().read() };
    // SAFETY: the SDK's target text, live for the call.
    let url = unsafe { std::slice::from_raw_parts(i.target.ptr, i.target.len) };
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
    answer(out, Outcome::Ready, id, 0, 0)
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
        return answer(out, Outcome::Failed, 0, 0, 0);
    };
    match piece.kind {
        REQUEST_HEAD => {
            let block = String::from_utf8_lossy(frame(bytes, piece.fields)).into_owned();
            wire.head = block
                .split("\r\n")
                .filter_map(|l| l.split_once(": "))
                .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
                .collect();
        }
        REQUEST_BODY => wire.body.extend_from_slice(bytes),
        _ => {
            let body: Value = serde_json::from_slice(&wire.body).unwrap_or(Value::Null);
            wire.reply = Some(upstream_answer(&wire.url, &wire.head, &body));
        }
    }
    answer(out, Outcome::Ready, 0, i.len as u64, 0)
}

extern "C" fn read_reply(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `ReplyIn` over its own buffer and descriptor slot.
    let i = unsafe { input.cast::<ReplyIn>().read() };
    // SAFETY: as above.
    let buf = unsafe { std::slice::from_raw_parts_mut(i.buf, i.len) };
    let mut ups = upstreams();
    let ups = ups.get_or_insert_with(Upstreams::default);
    let Some(wire) = ups.open.get_mut(&i.stream) else {
        return answer(out, Outcome::Failed, 0, 0, 0);
    };
    let Some((status, head, body)) = wire.reply.clone() else {
        return answer(out, Outcome::Failed, 0, 0, 0);
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
    answer(out, Outcome::Ready, 0, n as u64, 0)
}

extern "C" fn close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `StreamIn`.
    let i = unsafe { input.cast::<StreamIn>().read() };
    if let Some(ups) = upstreams().as_mut() {
        ups.open.remove(&i.stream);
    }
    answer(out, Outcome::Ready, 0, 0, 0)
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

/// The host, with its connector: the door's own fetches reach the upstreams above.
static TABLES: Tables = Tables(HostTables {
    size: std::mem::size_of::<HostTables>() as u32,
    _reserved: 0,
    ctx: HostCtx::NONE,
    wake: None,
    conns: &CONN_SLOTS,
    io: std::ptr::null(),
    services: &HOST_SLOTS,
});

/// The host with no connector lent: a `transport: stdio` member's child is the walk's to reach,
/// and the door fetches nothing of its own.
static UNCONNECTED: Tables = Tables(HostTables {
    size: std::mem::size_of::<HostTables>() as u32,
    _reserved: 0,
    ctx: HostCtx::NONE,
    wake: None,
    conns: std::ptr::null(),
    io: std::ptr::null(),
    services: &HOST_SLOTS,
});

/// One test at a time: the host's book and the upstreams are the process's.
static SERIAL: Mutex<()> = Mutex::new(());

/// A fresh host: an empty book and no exchange open.
fn fresh() -> MutexGuard<'static, ()> {
    let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *book() = Some(Book::default());
    *upstreams() = Some(Upstreams::default());
    serial
}

// ── the door, op by op ──────────────────────────────────────────────────────────────────────────

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { std::mem::zeroed() }
}

fn str_of(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
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

fn open_on(tables: &'static Tables, section: &Value) -> Door {
    let settings = serde_json::to_vec(section).unwrap();
    let mut i: PlaneOpenIn = z();
    i.open = OpenIn {
        head: head::<PlaneOpenIn>(life::OPEN, Ticket::NONE),
        host: &tables.0,
        settings: octets(&settings),
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
    let ret = f(
        std::ptr::null_mut(),
        std::ptr::from_ref(&i).cast(),
        std::ptr::from_mut(&mut o).cast(),
    );
    assert_eq!(ret.outcome(), Outcome::Ready, "the door opens");
    Door {
        instance: o.open.instance,
    }
}

fn open(section: &Value) -> Door {
    open_on(&TABLES, section)
}

/// What `arrive` answered.
#[derive(Debug)]
struct Arrived {
    outcome: Outcome,
}

/// The index of the claim `verb` `target` on the HTTP carrier.
fn claim(verb: &str, target: &str) -> u32 {
    let i = door::ROUTES
        .iter()
        .position(|r| r.verb == verb && r.target == target && r.carrier == "http")
        .expect("the door routes it");
    u32::try_from(i).unwrap()
}

/// One piece as the kernel pushes it.
struct Given<'a> {
    from: u32,
    flags: u32,
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
            status: 0,
            attempt: 0,
            member: "",
            caller,
            head: Vec::new(),
            bytes,
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
    fn far(caller: &'a str, status: u32, bytes: &'a [u8]) -> Self {
        Given {
            from: FROM_FAR_END,
            flags: PIECE_LAST | PIECE_HAS_STATUS,
            status,
            head: vec![JSON_TYPE],
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

impl Door {
    fn arrive_on(&self, unit: u64, claim: u32, target: &str, body: &[u8]) -> Arrived {
        let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let mirrored = codec::mirrored(&value);
        let fields: Vec<Field> = mirrored
            .iter()
            .map(|(n, v)| Field {
                name: str_of(n),
                value: str_of(v),
            })
            .collect();
        let mut i: ArriveIn = z();
        i.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
        i.unit = unit;
        i.claim = claim;
        i.target = str_of(target);
        i.method = str_of("POST");
        i.body = octets(body);
        (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
        let mut units = [z::<UnitCount>(); 8];
        (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
        let mut o: ArriveOut = z();
        o.head = out_head::<ArriveOut>();
        let f = ops().arrive.expect("arrive");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        Arrived {
            outcome: ret.outcome(),
        }
    }

    /// `body` arrives on the endpoint as unit `unit`.
    fn arrive(&self, unit: u64, body: &[u8]) -> Arrived {
        self.arrive_on(unit, claim("POST", "/mcp"), "/mcp", body)
    }

    /// `body` arrives on the task-run claim as unit `unit`: a continuation, as the kernel runs a
    /// nested unit (or as a caller posting there itself).
    fn arrive_run(&self, unit: u64, body: &[u8]) -> Arrived {
        self.arrive_on(
            unit,
            u32::try_from(door::TASK_RUN_ROUTE).unwrap(),
            tool_claims::TASK_RUN_MOUNT,
            body,
        )
    }

    /// One piece of `unit`, re-called while the door says `more`. Every record write of the task
    /// kind it carries is applied to the host's records.
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
        let mut fields = [z::<OutField>(); 32];
        let mut arena = vec![0_u8; 8 << 20];
        let mut records = vec![z::<RecordWrite>(); 2048];
        let mut units = [z::<UnitCount>(); 8];
        let mut got = Answered::default();
        let mut first = true;
        for _ in 0..64 {
            let mut i: OnPieceIn = z();
            i.head = head::<OnPieceIn>(slot::ON_PIECE, ticket);
            i.unit = unit;
            i.from = given.from;
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
            let ret = f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            );
            first = false;
            got.outcome = Some(ret.outcome());
            if o.reply_status != 0 {
                got.status = o.reply_status;
            }
            let bytes_at = |s: Span| {
                let from = s.offset as usize;
                arena[from..from + s.len as usize].to_vec()
            };
            let at = |s: Span| String::from_utf8_lossy(&bytes_at(s)).into_owned();
            got.fields.extend(
                fields[..o.fields_written as usize]
                    .iter()
                    .map(|f| (at(f.name), at(f.value))),
            );
            let writes: Vec<(Vec<u8>, Vec<u8>)> = records[..o.records_written as usize]
                .iter()
                .filter(|r| r.op == RECORD_PUT && r.kind == door::RECORD_TASK)
                .map(|r| (bytes_at(r.key), bytes_at(r.value)))
                .collect();
            with_book(|b| {
                for (k, v) in writes {
                    if v.is_empty() {
                        b.records.remove(&k);
                    } else {
                        b.records.insert(k, v);
                    }
                }
            });
            got.far |= o.flags & EMIT_TO_FAR_END != 0;
            got.bytes
                .extend_from_slice(&reply[..usize::try_from(o.emitted).unwrap()]);
            if ret.outcome() != Outcome::Ready || o.more == 0 {
                break;
            }
        }
        got
    }
}

/// The caller's opaque reference, as the kernel lends it.
const ALICE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

/// The caller's `_meta`: the revision, and the tasks extension (and elicitation) declared.
fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}},
            "elicitation": {},
        },
    })
}

/// A `tools/call` of `name` with `arguments`.
fn call(name: &str, arguments: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 30,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": meta()},
    }))
    .unwrap()
}

/// A `tasks/*` verb on task `task` with `extra` params.
fn verb(method: &str, task: &str, extra: &Value) -> Vec<u8> {
    let mut params = json!({"taskId": task, "_meta": meta()});
    if let (Some(p), Some(e)) = (params.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 40, "method": method, "params": params}))
        .unwrap()
}

/// The pin every registration here takes.
fn pin() -> Value {
    json!({"mechanism": "unpinned"})
}

/// THE SECTION: an upstream that requires a session (`fs`), a stateless one (`st`), a
/// `token_exchange:` one (`tx`) and one whose asks are relayed under a small reply bound (`ask`);
/// every tool is answered as a task.
fn section() -> Value {
    let task = json!({"read_file": {"task_support": "required"}});
    json!({
        "fs": {"url": SESSION_URL, "pin": pin(), "verify_ttl": "1h", "tools_allow": task},
        "st": {"url": "https://up.example/st", "pin": pin(), "verify_ttl": "1h", "tools_allow": task},
        "tx": {
            "url": "https://up.example/tx",
            "aud": "https://up.example/tx",
            "pin": pin(),
            "verify_ttl": "1h",
            "token_exchange": {"token_url": "https://as.example/token", "subject_token": {"env": "BUSBAR_SUBJECT"}},
            "tools_allow": task,
        },
        "ask": {
            "url": "https://up.example/ask",
            "pin": pin(),
            "verify_ttl": "1h",
            "grants": {"elicitation": true},
            "sampling_bounds": {"max_input_response_bytes": 100},
            "tools_allow": task,
        },
    })
}

/// `name` on `member` called as a task by ALICE on unit `unit`: the task's id.
fn create(d: &Door, unit: u64, member: &str, name: &str) -> String {
    let body = call(name, &json!({}));
    let arrived = d.arrive(unit, &body);
    assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
    d.piece(unit, &Given::attempt(ALICE, member));
    let created = d.piece(unit, &Given::caller(ALICE, &body));
    assert_eq!(created.status, 200, "{}", created.text());
    let v = created.json();
    v["result"]["taskId"]
        .as_str()
        .unwrap_or_else(|| panic!("a task was created: {v}"))
        .to_string()
}

/// The body of the last unit the door nested.
fn last_nested() -> Vec<u8> {
    with_book(|b| b.nested.last().cloned())
        .expect("a unit was nested")
        .1
}

/// The continuation `body` run as unit `unit` on `member`: what its call came to.
fn run(d: &Door, unit: u64, member: &str, body: &[u8]) -> Answered {
    let arrived = d.arrive_run(unit, body);
    assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
    d.piece(unit, &Given::attempt(ALICE, member));
    d.piece(unit, &Given::caller(ALICE, body))
}

/// `tasks/get` of `task` on unit `unit`: its answer.
fn get(d: &Door, unit: u64, task: &str) -> Answered {
    let body = verb("tasks/get", task, &json!({}));
    assert_eq!(d.arrive(unit, &body).outcome, Outcome::Ready);
    d.piece(unit, &Given::caller(ALICE, &body))
}

// ── C-H2: a task's call carries the caller's down-scope ─────────────────────────────────────────

/// C-H2 [HIGH]: a task's call to a `token_exchange:` member states the CALLER's down-scope, as the
/// synchronous call does (ARCHITECT round 5 Q-L3B-EXCHANGE (B), tools_config.rs `TokenExchangeCfg`:
/// the scope is derived from the inbound caller's grant, never left for the member's whole set —
/// the transitive confused deputy).
#[test]
fn a_tasks_call_to_an_exchanging_member_carries_the_callers_down_scope() {
    let _serial = fresh();
    let d = open(&section());
    create(&d, 1, "tx", "tx_read_file");
    let sent = run(&d, 2, "tx", &last_nested());
    assert!(sent.far, "the call goes to the member: {}", sent.text());
    assert_eq!(
        sent.field(busbar_contract::abi::auth::SCOPE_REQUEST_FIELD),
        Some("tx_read_file"),
        "the task's call states the caller's down-scope: {:?}",
        sent.fields
    );
}

// ── C-H3: the client ladder and a stdio member ──────────────────────────────────────────────────

/// C-H3 [HIGH], the ladder: a task's call to an upstream that requires a session rides the session
/// busbar negotiated with it for this caller (THE DESIGN section 2, the mcp bullet), as the
/// synchronous call does — never the stateless request the upstream refuses.
#[test]
fn a_tasks_call_to_a_session_upstream_rides_the_negotiated_session() {
    let _serial = fresh();
    let d = open(&section());
    create(&d, 1, "fs", "fs_read_file");
    let sent = run(&d, 2, "fs", &last_nested());
    assert!(sent.far, "the call goes to the member: {}", sent.text());
    assert_eq!(
        sent.field("mcp-session-id"),
        Some(UPSTREAM_SESSION),
        "the task's call rides the session negotiated with the upstream: {:?}",
        sent.fields
    );
}

/// C-H3 [HIGH], stdio: a task on a `transport: stdio` member is sent to the member's child, as the
/// synchronous call is (BUSBAR-1.6.0.md l.372-373: every plane supports the transports its
/// protocol's official design defines) — never failed for want of a `url:`.
#[test]
fn a_task_on_a_stdio_member_is_sent_to_its_child() {
    let _serial = fresh();
    let d = open_on(
        &UNCONNECTED,
        &json!({"io": {
            "transport": "stdio",
            "command": "/usr/bin/true",
            "pin": pin(),
            "tools_allow": {"read_file": {"task_support": "required"}},
        }}),
    );
    create(&d, 1, "io", "io_read_file");
    let sent = run(&d, 2, "io", &last_nested());
    assert!(
        sent.far,
        "the task's call is relayed to the stdio child, not failed: {} {}",
        sent.status,
        sent.text()
    );
    let line: Value = serde_json::from_slice(&sent.bytes).expect("a JSON-RPC request");
    assert_eq!(line["method"], json!("tools/call"));
    assert_eq!(line["params"]["name"], json!("read_file"));
}

// ── C-M4: the bound on the caller's reply to a relayed ask ──────────────────────────────────────

/// C-M4 [MEDIUM]: the caller's reply to an upstream's ask relayed on a task is measured against
/// the member's `sampling_bounds.max_input_response_bytes` before it is forwarded (owner ruling
/// Q22c), as the synchronous retry's is; one over the bound is refused by name and never sent.
#[test]
fn a_tasks_reply_to_a_relayed_ask_over_the_bound_is_never_forwarded() {
    let _serial = fresh();
    let d = open(&section());
    let task = create(&d, 1, "ask", "ask_read_file");
    let first = run(&d, 2, "ask", &last_nested());
    assert!(first.far, "{}", first.text());
    let sent: Value = serde_json::from_slice(&first.bytes).expect("a JSON-RPC request");
    let asked = rpc_result(
        &sent["id"],
        json!({
            "resultType": "input_required",
            "inputRequests": {"ok": {"method": "elicitation/create", "params": {
                "message": "sure?",
                "requestedSchema": {"type": "object", "properties": {}},
            }}},
            "requestState": "up-1",
        }),
    );
    d.piece(2, &Given::far(ALICE, 200, &asked));
    let parked = get(&d, 3, &task);
    assert_eq!(
        parked.json()["result"]["status"],
        json!("input_required"),
        "{}",
        parked.text()
    );
    let update = verb(
        "tasks/update",
        &task,
        &json!({"inputResponses": {"ok": {"action": "accept", "content": {"note": "x".repeat(400)}}}}),
    );
    assert_eq!(d.arrive(4, &update).outcome, Outcome::Ready);
    let acked = d.piece(4, &Given::caller(ALICE, &update));
    assert_eq!(acked.status, 200, "{}", acked.text());
    let retry = run(&d, 5, "ask", &last_nested());
    assert!(
        !retry.far,
        "a reply over `max_input_response_bytes` is never forwarded to the member"
    );
    let failed = get(&d, 6, &task).json();
    assert_eq!(failed["result"]["status"], json!("failed"), "{failed}");
    assert!(
        failed["result"]["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("max_input_response_bytes")),
        "refused by name: {failed}"
    );
}

// ── P-M6: the task store is host records ────────────────────────────────────────────────────────

/// `text` as a tool's result, answered to the continuation's request `sent`.
fn result_of(sent: &Answered, text: &str) -> Vec<u8> {
    let request: Value = serde_json::from_slice(&sent.bytes).expect("a JSON-RPC request");
    rpc_result(
        &request["id"],
        json!({"content": [{"type": "text", "text": text}], "resultType": "complete"}),
    )
}

/// P-M6 [MEDIUM]: a task's result is kept in the host's records (BUSBAR-1.6.0.md, the mcp bullet:
/// "the task store is host records"), so another node answers it — a result of 200 KB whole, and
/// one longer than the records keep as a `failed` task in words, never as a task that does not
/// exist.
#[test]
fn a_tasks_result_is_answered_from_the_host_records_on_another_node() {
    let _serial = fresh();
    let d = open(&section());
    let other = open(&section());
    let kept = create(&d, 1, "st", "st_read_file");
    let sent = run(&d, 2, "st", &last_nested());
    assert!(sent.far, "{}", sent.text());
    let text = "y".repeat(200_000);
    d.piece(2, &Given::far(ALICE, 200, &result_of(&sent, &text)));
    let read = get(&other, 3, &kept);
    assert_eq!(read.status, 200, "another node answers it: {}", read.text());
    let v = read.json();
    assert_eq!(v["result"]["status"], json!("completed"));
    assert_eq!(v["result"]["result"]["content"][0]["text"], json!(text));

    let long = create(&d, 4, "st", "st_read_file");
    let sent = run(&d, 5, "st", &last_nested());
    assert!(sent.far, "{}", sent.text());
    d.piece(
        5,
        &Given::far(ALICE, 200, &result_of(&sent, &"z".repeat(600_000))),
    );
    for door in [&d, &other] {
        let read = get(door, 6, &long);
        assert_eq!(read.status, 200, "{}", read.text());
        let v = read.json();
        assert_eq!(v["result"]["status"], json!("failed"), "{v}");
        assert!(
            v["result"]["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("bytes")),
            "refused in words: {v}"
        );
    }
}

// ── P-M9: the task-run claim is the kernel's ────────────────────────────────────────────────────

/// P-M9 [MEDIUM]: a caller posting a `resume` to its own task on the task-run claim while the task
/// runs does not run the task's call a second time (nor past the operator's rounds): only the
/// resume a `tasks/update` nested is taken.
#[test]
fn a_caller_cannot_drive_its_own_tasks_continuation() {
    let _serial = fresh();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let nested = last_nested();
    let sent = run(&d, 2, "st", &nested);
    assert!(sent.far, "the task's one run: {}", sent.text());
    let mut forged: Value = serde_json::from_slice(&nested).unwrap();
    forged["resume"] = json!(7);
    assert_eq!(forged["taskId"], json!(task));
    let forged = serde_json::to_vec(&forged).unwrap();
    let arrived = d.arrive_run(3, &forged);
    let again = arrived.outcome == Outcome::Ready && {
        d.piece(3, &Given::attempt(ALICE, "st"));
        d.piece(3, &Given::caller(ALICE, &forged)).far
    };
    assert!(
        !again,
        "a resume the caller posted itself sent the task's call a second time"
    );
}

// ── C-L10: every page of a caller's left-behind tasks ───────────────────────────────────────────

/// C-L10 [LOW]: a create settles every live task of its caller a process that is gone left behind
/// (BUSBAR-1.6.0.md §1: "Admission bounds live work; nothing evicts it"), past the first page of
/// its index rows.
#[test]
fn a_create_settles_every_page_of_its_callers_left_behind_tasks() {
    let _serial = fresh();
    let left: Vec<u64> = with_book(|b| {
        (0..70u64)
            .map(|n| {
                let reference = format!("{:032x}", 0x1eff_0000_u64 + n);
                let row = WorkRow {
                    status: tool_tasks::Status::Working,
                    created_ms: 1,
                    updated_ms: 1,
                    digest: "d".to_string(),
                };
                let lease = TaskLease {
                    until_ms: 1,
                    updated_ms: 1,
                };
                b.records
                    .insert(index_key(ALICE, &reference), lease.bytes());
                open_work(b, reference, row.bytes())
            })
            .collect()
    });
    let d = open(&section());
    create(&d, 1, "st", "st_read_file");
    let settled: HashSet<u64> = with_book(|b| b.settles.iter().map(|(h, _)| *h).collect());
    let missed: Vec<&u64> = left.iter().filter(|h| !settled.contains(h)).collect();
    assert!(
        missed.is_empty(),
        "{} of the caller's 70 left-behind tasks were not settled",
        missed.len()
    );
}
