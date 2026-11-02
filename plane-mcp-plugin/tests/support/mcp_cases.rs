// SPDX-License-Identifier: Apache-2.0
//! Direct ABI cases over the actual MCP plugin, with buffers owned through completion.
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::hook::SignalEntry;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Field, OutHead, Outcome, Span, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, GenIn, RefreshIn};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneCancelIn, PlaneCancelOut,
    PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut, RecordWrite, RefusalIn,
    RefusalOut, ServeIn, ServeOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER,
    FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED, RECORD_PUT,
    REFUSAL_GATE, ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_ONCE, ROUTE_POOL, ROUTE_SCOPE, ROUTE_SESSION,
    ROUTE_STREAM, SPAN_ABSENT, UNITS_REPORTED,
};
use serde_json::Value;

use busbar_contract::abi::mechanism::call::{InHead, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{ReleaseIn, ValidateIn};
use busbar_contract::services::{Caller, Ran, RecordsList, Stored, UNSERVED};
use busbar_plugin_loader::dispatch::kinds::plane::{OwnedSnapshot, Plane, ServedFacts};
use busbar_plugin_loader::dispatch::{
    in_head, now_ns, out_head, Called, Dispatcher, Done, Frame, InFrame, Kind, Lent, OutFrame,
    Plugin,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
#[derive(Clone, Default)]
struct McpHealthRequest {
    route: u32,
    target: Vec<u8>,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
}
fn input<T: InFrame>() -> T {
    // SAFETY: every kind's `in` is plain integers, raw pointers, `Option<fn>` and nested plain
    // structs, for which the all-zero pattern is valid; `T` leads with an `InHead`, written below.
    let mut v: T = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: InFrame` leads with an `InHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}

#[must_use]
fn output<T: OutFrame>() -> T {
    // SAFETY: as `input`, with an `OutHead` first.
    let mut v: T = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: OutFrame` leads with an `OutHead`.
    unsafe {
        std::ptr::addr_of_mut!(v)
            .cast::<OutHead>()
            .write(out_head())
    };
    v
}

#[must_use]
fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

#[must_use]
fn called(c: &Called) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} lease={} {text}", c.outcome, c.lease != 0)
}

fn on_ticket_frame<K: Kind, I: InFrame, O: OutFrame>(
    p: &Plugin<K>,
    d: &Dispatcher,
    s: u32,
    f: Frame<I, O>,
    class: DeadlineClass,
    deadline_ns: u64,
    lent: Lent,
) -> (Called, Option<Frame<I, O>>) {
    let Some(ticket) = d.mint(0) else {
        let refused = Called {
            outcome: Outcome::Refused,
            error: None,
            lease: 0,
            recall: None,
        };
        return (refused, None);
    };
    let done = submit_on(
        p,
        d,
        ticket,
        s,
        f,
        (class, deadline_ns),
        lent,
        Duration::ZERO,
    );
    d.recycle(ticket);
    (answered(&done), done.frame)
}

#[allow(clippy::too_many_arguments)]
fn submit_on<K: Kind, I: InFrame, O: OutFrame>(
    p: &Plugin<K>,
    d: &Dispatcher,
    ticket: Ticket,
    s: u32,
    f: Frame<I, O>,
    (class, deadline_ns): (DeadlineClass, u64),
    lent: Lent,
    watch: Duration,
) -> Done<I, O> {
    d.submit_watched(p, ticket, s, f, class, deadline_ns, lent, watch)
        .wait_done()
}

fn answered<I, O>(done: &Done<I, O>) -> Called {
    Called {
        outcome: done.outcome,
        error: done.error.clone(),
        lease: done.lease,
        recall: None,
    }
}

fn release<K: Kind>(p: &Plugin<K>, lease: u64) -> Called {
    let mut f: Frame<ReleaseIn, OutHead> = Frame::new(input(), output());
    f.input.lease = lease;
    p.call(life::RELEASE, &mut f)
}

fn close<K: Kind>(p: &Plugin<K>) -> Called {
    let mut f: Frame<InHead, OutHead> = Frame::new(input(), output());
    p.call(life::CLOSE, &mut f)
}

fn validate(p: &Plugin<Plane>, settings: &[u8]) -> Called {
    let mut frame: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    frame.input.settings = json(settings);
    p.call(life::VALIDATE, &mut frame)
}

struct McpServices {
    store: busbar_plugin_loader::store_v3::LoadedStore,
    kinds: Mutex<Vec<(String, bool)>>,
    sightings: Mutex<BTreeMap<(String, Option<String>), String>>,
}
fn block<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("MCP record runtime")
        .block_on(future)
}
impl McpServices {
    fn new() -> Self {
        use busbar_plugin_loader::dispatch::kinds::store::Store;
        use busbar_plugin_loader::dispatch::{Bind, ConnTable, DispatchConfig, LinkedRow, NoSink};
        let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let row =
            LinkedRow::of(busbar_store_memory::door).expect("actual MemoryStore door Statement");
        let plugin = busbar_plugin_loader::dispatch::load_linked::<Store>(
            &row,
            Bind {
                instance: Arc::from("mcp-record-store"),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: d.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("actual MemoryStore loads");
        assert_eq!(
            plugin.name(),
            "busbar-store-memory",
            "the test requires the actual memory product"
        );
        let store =
            busbar_plugin_loader::store_v3::LoadedStore::open(plugin, d, b"{}", mint_store_op)
                .expect("actual memory store opens");
        Self {
            store,
            kinds: Mutex::new(Vec::new()),
            sightings: Mutex::new(BTreeMap::new()),
        }
    }
    fn keep(&self, kind: u32, key: &[u8], value: &[u8]) {
        use busbar_contract::kinds::RecordBytes;
        use busbar_contract::store_calls::StoreCalls;
        let kinds = self.kinds.lock().unwrap();
        let (name, chained) = kinds.get(kind as usize).expect("record kind is declared");
        let key = if *chained {
            let rows = block(self.store.record_scan(name, &[], u32::MAX))
                .expect("actual chain records scan");
            if value.is_empty() {
                for (row, _) in rows {
                    if busbar_contract::services::chain_key_parts(&row)
                        .is_some_and(|(scope, _)| scope == key)
                    {
                        block(self.store.record_put(
                            name,
                            &row,
                            &RecordBytes::new(Vec::new()).unwrap(),
                        ))
                        .expect("actual chain row removes");
                    }
                }
                return;
            }
            let next = rows
                .iter()
                .filter_map(|(row, _)| busbar_contract::services::chain_key_parts(row))
                .filter(|(scope, _)| *scope == key)
                .map(|(_, seq)| seq)
                .max()
                .unwrap_or(0)
                + 1;
            busbar_contract::services::chain_key(key, next)
        } else {
            key.to_vec()
        };
        block(self.store.record_put(
            name,
            &key,
            &RecordBytes::new(value.to_vec()).expect("record bound"),
        ))
        .expect("actual store retains MCP output record");
    }
    fn sighting(&self, name: &str, item: Option<&str>, digest: &str) -> Stored {
        use busbar_contract::abi::host::service::{TRUST_DRIFTED, TRUST_NEW, TRUST_SAME};
        assert!(["fs", "child"].contains(&name), "MCP declares this subject");
        assert!(!digest.trim().is_empty() && !digest.contains('\0'));
        let before = self.sightings.lock().unwrap().insert(
            (name.to_string(), item.map(str::to_string)),
            digest.to_string(),
        );
        Stored::ready(match before {
            None => TRUST_NEW,
            Some(before) if before == digest => TRUST_SAME,
            Some(_) => TRUST_DRIFTED,
        })
    }
}
fn mint_store_op() -> busbar_contract::abi::store::OpId {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    busbar_contract::abi::store::OpId::from_parts(
        0x6d6370,
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    )
}

impl busbar_contract::services::HostServices for McpServices {
    fn now(&self) -> busbar_plugin_loader::dispatch::Reading {
        busbar_plugin_loader::dispatch::Reading {
            wall_ns: 0,
            mono_ns: 0,
        }
    }
    fn dest_judge(
        &self,
        _: &str,
        _: u32,
        _: u32,
        _: Option<busbar_plugin_loader::dispatch::Later>,
    ) -> busbar_plugin_loader::dispatch::Ran {
        busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_get(
        &self,
        _: &Caller,
        kind: &str,
        key: &[u8],
        _: busbar_contract::services::Later,
    ) -> Ran {
        use busbar_contract::abi::host::service::{ItemSpan, ABSENT, FOUND};
        use busbar_contract::store_calls::StoreCalls;
        let mut answer = Stored::ready(ABSENT);
        if let Some(value) =
            block(self.store.record_get(kind, key)).expect("actual store record reads")
        {
            answer = Stored::ready(FOUND);
            answer.bytes = value.as_slice().to_vec();
            answer.spans.push(ItemSpan {
                key: Span {
                    offset: u32::MAX,
                    len: 0,
                },
                value: Span {
                    offset: 0,
                    len: answer.bytes.len() as u32,
                },
            });
        }
        Ran::Now(answer)
    }
    fn records_list(
        &self,
        _: &Caller,
        list: RecordsList,
        _: busbar_contract::services::Later,
    ) -> Ran {
        use busbar_contract::abi::host::service::{ItemSpan, MAX_SPANS};
        use busbar_contract::store_calls::StoreCalls;
        let limit = if list.limit == 0 {
            MAX_SPANS
        } else {
            u64::from(list.limit).min(MAX_SPANS)
        } as usize;
        let rows = block(self.store.record_scan(&list.kind, &list.prefix, u32::MAX))
            .expect("actual store record scan");
        let mut answer = Stored::ready(0);
        for (key, value) in rows
            .into_iter()
            .filter(|(key, _)| list.after.as_ref().is_none_or(|after| key > after))
            .take(limit)
        {
            let key_at = answer.bytes.len();
            answer.bytes.extend_from_slice(&key);
            let value_at = answer.bytes.len();
            answer.bytes.extend_from_slice(value.as_slice());
            answer.spans.push(ItemSpan {
                key: Span {
                    offset: key_at as u32,
                    len: key.len() as u32,
                },
                value: Span {
                    offset: value_at as u32,
                    len: value.as_slice().len() as u32,
                },
            });
        }
        Ran::Now(answer)
    }
    fn records_claim(
        &self,
        _: &Caller,
        _: &str,
        _: &[u8],
        _: u64,
        _: busbar_plugin_loader::dispatch::Later,
    ) -> busbar_plugin_loader::dispatch::Ran {
        busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
    }
    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn unit_nest(
        &self,
        _: &Caller,
        _: Option<u64>,
        _: busbar_contract::services::NestAsk,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_open(
        &self,
        _: &Caller,
        _: Option<u64>,
        _: &str,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_find(
        &self,
        _: &Caller,
        _: Option<u64>,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_settle(
        &self,
        _: &Caller,
        _: Option<u64>,
        _: u64,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_resume(
        &self,
        _: &Caller,
        _: Option<u64>,
        _: u64,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_sight(
        &self,
        _: &Caller,
        name: &str,
        digest: &str,
        _: busbar_contract::services::Later,
    ) -> Ran {
        Ran::Now(self.sighting(name, None, digest))
    }
    /// The kernel's Approve as this section's approvals seed it: `read_file` approved at its
    fn trust_serves(
        &self,
        _: &Caller,
        counterparty: &str,
        item: Option<&str>,
        _: Option<&str>,
    ) -> Stored {
        use busbar_contract::abi::host::service::{
            DISTRUST_NONE, DISTRUST_UNKNOWN, DISTRUST_UNKNOWN_ITEM,
        };
        Stored::ready(if (counterparty, item) == ("fs", Some("read_file")) {
            DISTRUST_NONE
        } else if item.is_some() {
            DISTRUST_UNKNOWN_ITEM
        } else {
            DISTRUST_UNKNOWN
        })
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn entitlement_check(&self, _: &Caller, unit: Option<u64>, target: &str) -> Stored {
        Stored::ready(
            if unit.is_some() && ["mcp_server:fs", "mcp_tool:fs_read_file"].contains(&target) {
                busbar_contract::abi::host::service::ENTITLED
            } else {
                busbar_contract::abi::host::service::NOT_ENTITLED
            },
        )
    }
    fn random_fill(&self, _: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn records_secret(
        &self,
        _: &str,
        _: &str,
        _: busbar_plugin_loader::dispatch::Later,
    ) -> busbar_plugin_loader::dispatch::Ran {
        busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
    }
    fn disk_append(
        &self,
        _: &busbar_contract::services::DiskDest,
        _: Vec<u8>,
        _: busbar_plugin_loader::dispatch::Later,
    ) -> busbar_plugin_loader::dispatch::Ran {
        busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_lookup(
        &self,
        _: &Caller,
        _: &[u8],
        _: busbar_plugin_loader::dispatch::Later,
    ) -> busbar_plugin_loader::dispatch::Ran {
        busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn content_scan(
        &self,
        _: &Caller,
        _: Option<u64>,
        _: &[u8],
        _: busbar_plugin_loader::dispatch::Later,
    ) -> busbar_plugin_loader::dispatch::Ran {
        busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
    }
    fn hook_call(
        &self,
        _: &Caller,
        _: Option<u64>,
        _: busbar_contract::services::HookAsk,
        _: busbar_plugin_loader::dispatch::Later,
    ) -> busbar_plugin_loader::dispatch::Ran {
        busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
    }
    fn snapshot_read(&self, _: &Caller, _: u32) -> busbar_contract::services::Snapshot {
        busbar_contract::services::Snapshot::Refused(UNSERVED)
    }

    fn trust_unreached(
        &self,
        _caller: &busbar_contract::services::Caller,
        _counterparty: &str,
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
    }
    fn trust_sight_item(&self, _: &Caller, name: &str, item: &str, digest: &str) -> Stored {
        self.sighting(name, Some(item), digest)
    }
    fn trust_decide(
        &self,
        _caller: &busbar_contract::services::Caller,
        _key: busbar_contract::services::TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
    }
    fn trust_state(
        &self,
        _caller: &busbar_contract::services::Caller,
        _counterparty: &str,
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
    }
    fn session_emit(
        &self,
        _caller: &busbar_contract::services::Caller,
        _session: u64,
        _bytes: &[u8],
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
    }
    fn ticket_mint(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
        _ttl_secs: u64,
        _record: &[u8],
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
    }
    fn ticket_take(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
    }
}
const CAP: usize = 8;

const OP_DEADLINE: Duration = Duration::from_secs(30);

fn deadline() -> u64 {
    now_ns().saturating_add(u64::try_from(OP_DEADLINE.as_nanos()).unwrap_or(u64::MAX))
}

fn text(v: &Value, what: &str) -> Vec<u8> {
    match v {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Null => panic!("conformance.json: plane.{what} is missing"),
        other => other.to_string().into_bytes(),
    }
}

fn num(v: &Value, what: &str) -> u64 {
    v.as_u64()
        .unwrap_or_else(|| panic!("conformance.json: plane.{what} must be a number"))
}

fn num_or(v: &Value, what: &str, or: u64) -> u64 {
    if v.is_null() {
        or
    } else {
        num(v, what)
    }
}

fn small(v: u64, what: &str) -> u32 {
    u32::try_from(v).unwrap_or_else(|_| panic!("conformance.json: plane.{what} is too large"))
}

fn pairs(v: &Value, what: &str) -> Vec<(String, String)> {
    v.as_array()
        .unwrap_or_else(|| panic!("conformance.json: plane.{what} must be an array of pairs"))
        .iter()
        .map(|p| match p.as_array().map(Vec::as_slice) {
            Some([a, b]) => (
                a.as_str().map_or_else(|| a.to_string(), String::from),
                b.as_str().map_or_else(|| b.to_string(), String::from),
            ),
            _ => panic!("conformance.json: plane.{what} holds a non-pair"),
        })
        .collect()
}

fn pairs_or_none(v: &Value, what: &str) -> Vec<(String, String)> {
    if v.is_null() {
        Vec::new()
    } else {
        pairs(v, what)
    }
}

fn field_list(pairs: &[(String, String)]) -> Vec<Field> {
    pairs
        .iter()
        .map(|(n, v)| Field {
            name: abi(n.as_bytes()),
            value: abi(v.as_bytes()),
        })
        .collect()
}

fn z<T: Copy>() -> T {
    // SAFETY: called only for the plane ABI's plain C structs (`UnitCount`, `RecordWrite`,
    // `OutField`, `SignalEntry`, `MessageView`): integers, spans, pointers and unions of integers,
    // for which all-zero is valid.
    unsafe { std::mem::zeroed() }
}

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn abi(b: &[u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn read(s: AbiStr) -> String {
    if s.ptr.is_null() || s.len == 0 {
        return String::new();
    }
    // SAFETY: the kind's check admitted the answer; the plane's text is valid until the
    // instance's next call, and it is read before any.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

fn at(buf: &[u8], s: Span) -> String {
    let (from, len) = (s.offset as usize, s.len as usize);
    buf.get(from..from + len).map_or_else(
        || "<OUTSIDE>".into(),
        |b| String::from_utf8_lossy(b).into_owned(),
    )
}

fn route_class(route: u8) -> String {
    match route {
        ROUTE_POOL => "pool".into(),
        ROUTE_DIRECT => "direct".into(),
        ROUTE_LOCAL => "local".into(),
        ROUTE_SCOPE => "scope".into(),
        other => other.to_string(),
    }
}

fn route_flags(flags: u8) -> Vec<String> {
    let mut named: Vec<String> = [
        (ROUTE_ONCE, "once"),
        (ROUTE_SESSION, "session"),
        (ROUTE_STREAM, "stream"),
    ]
    .iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, name)| (*name).to_string())
    .collect();
    let other = flags & !(ROUTE_ONCE | ROUTE_SESSION | ROUTE_STREAM);
    if other != 0 {
        named.push(other.to_string());
    }
    named
}

fn snapshot(s: Option<&OwnedSnapshot>) -> String {
    s.map_or_else(
        || "snapshot=none".into(),
        |s| {
            format!(
                "gen={} claims=[{}] routes={}",
                s.generation,
                claims(
                    s.claims
                        .iter()
                        .map(|c| (c.verb.as_str(), c.target.as_str()))
                ),
                s.admin_routes.len()
            )
        },
    )
}

fn claims<'a>(c: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    c.map(|(v, t)| format!("{v} {t}"))
        .collect::<Vec<_>>()
        .join(", ")
}

struct Piece {
    reply: Vec<u8>,
    units: [UnitCount; CAP],
    records: [RecordWrite; CAP],
    fields: [OutField; CAP],
    arena: [u8; 1024],
    bytes: Vec<u8>,
    _head: Vec<(String, String)>,
    head: Vec<Field>,
    member: Vec<u8>,
    pool: Option<Vec<u8>>,
    caller_ref: Option<Vec<u8>>,
}

// SAFETY: the raw pointers in `head` point into `_head`, owned by the same `Piece`; nothing
// mutates a lent `Piece` but the plane's writes into its buffers, which the host reads only after
// the op completes.
unsafe impl Send for Piece {}
// SAFETY: as above.
unsafe impl Sync for Piece {}

/// One piece handed to the plane.
#[derive(Clone, Copy)]
struct Given<'a> {
    unit: u64,
    /// A live session's stream; `0` for a request unit.
    stream: u64,
    /// The snapshot claim the unit arrived on.
    claim: u32,
    from: u32,
    flags: u32,
    bytes: &'a [u8],
    attempt_no: u32,
    /// With `PIECE_HAS_STATUS`: the far end's status and kept head fields.
    status: u32,
    head: &'a [(String, String)],
}

struct Carried {
    member: Vec<u8>,
    pool: Option<Vec<u8>>,
    caller_ref: Option<Vec<u8>>,
    host: Option<Arc<McpServices>>,
}

impl Carried {
    fn keep(&self, piece: &Piece, c: &Called, o: &OnPieceOut) {
        use busbar_contract::abi::mechanism::call::Outcome;
        let Some(h) = &self.host else {
            return;
        };
        if c.outcome != Outcome::Ready {
            return;
        }
        let bytes = |s: Span| {
            let (from, len) = (s.offset as usize, s.len as usize);
            piece.arena.get(from..from.checked_add(len)?)
        };
        for r in &piece.records[..(o.records_written as usize).min(CAP)] {
            if let (RECORD_PUT, Some(key), Some(value)) = (r.op, bytes(r.key), bytes(r.value)) {
                h.keep(r.kind, key, value);
            }
        }
    }
}

/// The host list a SHORT answer is met with at capacity 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Buffer {
    Units,
    Fields,
}

impl Buffer {
    fn of(v: &Value, what: &str) -> Option<Self> {
        match v.as_str() {
            None if v.is_null() => None,
            Some("units") => Some(Self::Units),
            Some("fields") => Some(Self::Fields),
            _ => panic!("conformance.json: plane.{what} must be \"units\" or \"fields\""),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Units => "units",
            Self::Fields => "fields",
        }
    }

    const fn caps(self) -> (usize, usize) {
        match self {
            Self::Units => (0, CAP),
            Self::Fields => (CAP, 0),
        }
    }

    fn needed(self, o: &OnPieceOut) -> u32 {
        match self {
            Self::Units => o.units_needed,
            Self::Fields => o.fields_needed,
        }
    }
}

impl Piece {
    fn lent(
        reply_cap: usize,
        g: Given<'_>,
        (units_cap, fields_cap): (usize, usize),
        c: &Carried,
    ) -> (Arc<Self>, Frame<OnPieceIn, OnPieceOut>) {
        let mut piece = Arc::new(Self {
            reply: vec![0; reply_cap],
            units: [z(); CAP],
            records: [z(); CAP],
            fields: [z(); CAP],
            arena: [0; 1024],
            bytes: g.bytes.to_vec(),
            _head: g.head.to_vec(),
            head: Vec::new(),
            member: c.member.clone(),
            pool: c.pool.clone(),
            caller_ref: c.caller_ref.clone(),
        });
        let me = Arc::get_mut(&mut piece).expect("a piece not yet lent is unshared");
        me.head = field_list(&me._head);
        let mut i: OnPieceIn = input();
        (i.unit, i.from, i.flags, i.bytes) = (g.unit, g.from, g.flags, octets(&me.bytes));
        (i.stream, i.claim) = (g.stream, g.claim);
        (i.attempt_no, i.member) = (g.attempt_no, abi(&me.member));
        if let (Some(pool), true) = (&me.pool, g.from == FROM_KERNEL && g.attempt_no > 0) {
            i.pool = abi(pool);
        }
        if let Some(r) = &me.caller_ref {
            i.caller_ref = abi(r);
        }
        if g.flags & PIECE_HAS_STATUS != 0 {
            i.status_code = g.status;
            (i.head_fields, i.head_fields_len) = (me.head.as_ptr(), me.head.len());
        }
        (i.reply_buf, i.reply_cap) = (me.reply.as_mut_ptr(), me.reply.len());
        (i.units_buf, i.units_cap) = (me.units.as_mut_ptr(), units_cap);
        (i.records_buf, i.records_cap) = (me.records.as_mut_ptr(), me.records.len());
        (i.fields_buf, i.fields_cap) = (me.fields.as_mut_ptr(), fields_cap);
        (i.arena_buf, i.arena_cap) = (me.arena.as_mut_ptr(), me.arena.len());
        (piece, Frame::new(i, output()))
    }

    fn fields(&self, o: &OnPieceOut) -> Vec<String> {
        self.fields[..(o.fields_written as usize).min(CAP)]
            .iter()
            .map(|f| format!("{}={}", at(&self.arena, f.name), at(&self.arena, f.value)))
            .collect()
    }

    fn units(&self, o: &OnPieceOut) -> Vec<String> {
        self.units[..(o.units_written as usize).min(CAP)]
            .iter()
            .map(|u| format!("{}:{}:{}", u.class, u.amount, u.source == UNITS_REPORTED))
            .collect()
    }

    fn emitted(&self, o: &OnPieceOut) -> String {
        let n = usize::try_from(o.emitted).map_or(self.reply.len(), |n| n.min(self.reply.len()));
        String::from_utf8_lossy(&self.reply[..n]).into_owned()
    }

    fn line(&self, c: &Called, o: &OnPieceOut) -> String {
        format!(
            "{} emitted={} more={} to_far_end={} done={} status={} verb={} target={} \
             fields={:?} units={:?}",
            called(c),
            self.emitted(o),
            o.more,
            o.flags & EMIT_TO_FAR_END != 0,
            o.flags & EMIT_DONE != 0,
            o.reply_status,
            at(&self.arena, o.verb),
            at(&self.arena, o.target),
            self.fields(o),
            self.units(o),
        )
    }
}

struct Unit {
    ticket: Ticket,
    reply_cap: usize,
}

impl Unit {
    fn mint(d: &Dispatcher, reply_cap: usize) -> Self {
        Self {
            ticket: d.mint(0).expect("a unit's ticket is minted"),
            reply_cap,
        }
    }

    fn end(self, d: &Dispatcher) {
        d.recycle(self.ticket);
    }
}

struct Pieced {
    called: Called,
    short: bool,
    piece: Arc<Piece>,
    frame: Option<Frame<OnPieceIn, OnPieceOut>>,
}

impl Pieced {
    fn out(&self) -> OnPieceOut {
        self.frame.as_ref().map_or_else(output, |f| f.out)
    }

    fn line(&self, line: fn(&Piece, &Called, &OnPieceOut) -> String) -> String {
        line(&self.piece, &self.called, &self.out())
    }
}

fn on_piece(
    p: &Plugin<Plane>,
    d: &Dispatcher,
    unit: &Unit,
    g: Given<'_>,
    caps: (usize, usize),
    c: &Carried,
) -> Pieced {
    let (piece, f) = Piece::lent(unit.reply_cap, g, caps, c);
    let done = submit_on(
        p,
        d,
        unit.ticket,
        slot::ON_PIECE,
        f,
        (DeadlineClass::Stream, deadline()),
        Arc::clone(&piece) as Lent,
        Duration::ZERO,
    );
    let called = answered(&done);
    if !done.short {
        let out = done.frame.as_ref().map_or_else(output, |f| f.out);
        c.keep(&piece, &called, &out);
    }
    Pieced {
        called,
        short: done.short,
        piece,
        frame: done.frame,
    }
}

fn short_then(
    p: &Plugin<Plane>,
    d: &Dispatcher,
    unit: &Unit,
    g: Given<'_>,
    buffer: Buffer,
    c: &Carried,
    line: fn(&Piece, &Called, &OnPieceOut) -> String,
) -> String {
    let first = on_piece(p, d, unit, g, buffer.caps(), c);
    let head = format!(
        "{} {}_needed={} recall={}",
        called(&first.called),
        buffer.name(),
        buffer.needed(&first.out()),
        first.short
    );
    let (true, Some(mut f)) = (first.short, first.frame) else {
        return format!("{head} then=no-recall");
    };
    (f.input.units_cap, f.input.fields_cap) = (CAP, CAP);
    let again = submit_on(
        p,
        d,
        unit.ticket,
        slot::ON_PIECE,
        f,
        (DeadlineClass::Stream, deadline()),
        Arc::clone(&first.piece) as Lent,
        Duration::ZERO,
    );
    let out = again.frame.as_ref().map_or_else(output, |f| f.out);
    if !again.short {
        c.keep(&first.piece, &answered(&again), &out);
    }
    format!(
        "{head} then={}",
        line(&first.piece, &answered(&again), &out)
    )
}

struct Arrival {
    unit: u64,
    claim: u32,
    method: Vec<u8>,
    target: Vec<u8>,
    fields: Vec<(String, String)>,

    route: bool,
}

impl Arrival {
    fn for_unit(&self, unit: u64) -> Self {
        Self {
            unit,
            claim: self.claim,
            method: self.method.clone(),
            target: self.target.clone(),
            fields: self.fields.clone(),
            route: self.route,
        }
    }

    fn of(a: &Value, what: &str) -> Self {
        Self {
            unit: num(&a["unit"], what),
            claim: small(num_or(&a["claim"], what, 0), what),
            method: text(&a["method"], what),
            target: text(&a["target"], what),
            fields: pairs_or_none(&a["fields"], what),
            route: a["route"].is_object(),
        }
    }
}

fn arrive(p: &Plugin<Plane>, a: &Arrival, body: &[u8]) -> String {
    let mut units = [z::<UnitCount>(); 4];
    let head = field_list(&a.fields);
    let mut f: Frame<ArriveIn, ArriveOut> = Frame::new(input(), output());
    (f.input.unit, f.input.claim) = (a.unit, a.claim);
    (f.input.method, f.input.target) = (abi(&a.method), abi(&a.target));
    if !head.is_empty() {
        (f.input.fields, f.input.fields_len) = (head.as_ptr(), head.len());
    }
    f.input.body = octets(body);
    (f.input.units_buf, f.input.units_cap) = (units.as_mut_ptr(), units.len());
    let c = p.call(slot::ARRIVE, &mut f);
    arrival_line(&c, &f.out, a.route)
}

fn arrival_line(c: &Called, out: &ArriveOut, route: bool) -> String {
    use busbar_contract::abi::mechanism::call::Outcome;
    if c.outcome == Outcome::Refused {
        return format!(
            "{} refusal={} status={}",
            called(c),
            out.refusal,
            out.refusal_status
        );
    }
    if c.outcome != Outcome::Ready {
        return format!("{} UNREAD", called(c));
    }
    let line = format!(
        "{} op_class={} principal_required={} dialect={} units={} refusal={} status={}",
        called(c),
        out.op_class,
        out.principal_need == PRINCIPAL_REQUIRED,
        out.dialect,
        out.units_written,
        out.refusal,
        out.refusal_status
    );
    if route {
        format!(
            "{line} route_flags={:?} route={} entry={}",
            route_flags(out.route_flags),
            route_class(out.route),
            read(out.pool)
        )
    } else {
        line
    }
}

fn drive(p: &Plugin<Plane>, driver: Option<Ticket>) -> (Called, Vec<u64>) {
    use busbar_contract::abi::mechanism::call::Outcome;
    let answer = |outcome, error: Option<&[u8]>| Called {
        outcome,
        error: error.map(<[u8]>::to_vec),
        lease: 0,
        recall: None,
    };
    let Some(driver) = driver else {
        return (
            answer(Outcome::Refused, Some(b"no driver ticket")),
            Vec::new(),
        );
    };
    let driven = &p.inner.driven;
    let seen = driven.answers();
    busbar_plugin_loader::dispatch::ticket::host_wake(p.inner.ctx(), driver);
    match driven.answered_after(seen, OP_DEADLINE) {
        Some(outcome) => (answer(outcome, None), driven.drain()),
        None => (
            answer(Outcome::Fault, Some(b"the woken driver never answered")),
            Vec::new(),
        ),
    }
}

fn attempt(unit: u64, claim: u32) -> Given<'static> {
    Given {
        unit,
        stream: 0,
        claim,
        from: FROM_KERNEL,
        flags: 0,
        bytes: b"",
        attempt_no: 1,
        status: 0,
        head: &[],
    }
}

fn far_end<'a>(
    unit: u64,
    claim: u32,
    flags: u32,
    bytes: &'a [u8],
    (status, head): (u32, &'a [(String, String)]),
) -> Given<'a> {
    Given {
        unit,
        stream: 0,
        claim,
        from: FROM_FAR_END,
        flags,
        bytes,
        attempt_no: 0,
        status,
        head,
    }
}

fn handed(facts: &ServedFacts, settings: &[u8]) -> Vec<u8> {
    let keyed =
        facts.section == busbar_contract::section::RESERVED_POOLS_KEY || !facts.consumed.is_empty();
    if !keyed {
        return settings.to_vec();
    }
    let value = match serde_json::from_slice::<Value>(settings) {
        Ok(Value::Null) | Err(_) => return settings.to_vec(),
        Ok(value) => value,
    };
    let written_keyed = value.as_object().is_some_and(|o| {
        o.contains_key(facts.section)
            && o.keys()
                .all(|k| k == facts.section || facts.consumed.contains(&k.as_str()))
    });
    if written_keyed {
        return settings.to_vec();
    }
    serde_json::to_vec(&serde_json::json!({ facts.section: value })).expect("a keyed blob")
}

fn open(p: &Plugin<Plane>, settings: &[u8], public_url: Option<&[u8]>) -> String {
    let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
    (f.input.open.generation, f.input.open.settings) = (1, json(settings));
    if let Some(url) = public_url {
        f.input.public_url = abi(url);
    }
    let (c, snap) = p.open(&mut f);
    format!("{} {}", called(&c), snapshot(snap.as_ref()))
}

fn generation(p: &Plugin<Plane>, s: u32, generation: u64) -> String {
    let mut g: Frame<GenIn, OutHead> = Frame::new(input(), output());
    g.input.generation = generation;
    called(&p.call(s, &mut g))
}

struct ServeLend {
    request: McpHealthRequest,
    request_fields: Vec<Field>,
    reply: [u8; 512],
    arena: [u8; 256],
    fields: [OutField; 2],
}

// SAFETY: input pointers name immutable allocations owned here. Output buffers are written only by
// the crossing and read by the caller only when the dispatcher returns a joined frame.
unsafe impl Send for ServeLend {}
// SAFETY: the caller never inspects output buffers while an abandoned crossing can still run.
unsafe impl Sync for ServeLend {}

impl ServeLend {
    fn frame(request: Option<&McpHealthRequest>) -> (Arc<Self>, Frame<ServeIn, ServeOut>) {
        let mut lend = Arc::new(Self {
            request: request.cloned().unwrap_or_default(),
            request_fields: Vec::new(),
            reply: [0; 512],
            arena: [0; 256],
            fields: [z(); 2],
        });
        let me = Arc::get_mut(&mut lend).expect("unshared");
        me.request_fields = field_list(&me.request.fields);
        let mut f: Frame<ServeIn, ServeOut> = Frame::new(input(), output());
        if request.is_some() {
            f.input.route = me.request.route;
            f.input.target = abi(&me.request.target);
            (f.input.fields, f.input.fields_len) =
                (me.request_fields.as_ptr(), me.request_fields.len());
            f.input.body = octets(&me.request.body);
        }
        (f.input.reply_buf, f.input.reply_cap) = (me.reply.as_mut_ptr(), me.reply.len());
        (f.input.fields_buf, f.input.fields_cap) = (me.fields.as_mut_ptr(), me.fields.len());
        (f.input.arena_buf, f.input.arena_cap) = (me.arena.as_mut_ptr(), me.arena.len());
        (lend, f)
    }
}

fn serve(p: &Plugin<Plane>, d: &Arc<Dispatcher>, request: Option<&McpHealthRequest>) -> String {
    let (lend, f) = ServeLend::frame(request);
    let (c, f) = on_ticket_frame(
        p,
        d,
        slot::SERVE,
        f,
        DeadlineClass::Call,
        deadline(),
        lend as Lent,
    );
    let out = f.map_or_else(output, |f| f.out);
    format!(
        "{} status={} reply_written={}",
        called(&c),
        out.status,
        out.reply_written
    )
}
fn reported(v: &Value, what: &str) -> String {
    let units: Vec<String> = pairs(v, what)
        .iter()
        .map(|(class, amount)| format!("{class}:{amount}:true"))
        .collect();
    format!("units={units:?}")
}

fn release_none_contract(answer: &str) {
    assert!(
        matches!(
            answer,
            "Ready lease=false " | "Refused lease=false release: no such lease"
        ),
        "release none: {answer}"
    );
}

#[derive(Default)]
struct McpDiagnostics(Mutex<Vec<Vec<u8>>>, std::sync::atomic::AtomicBool);
impl busbar_plugin_loader::dispatch::EnvelopeSink for McpDiagnostics {
    fn metric(&self, metric: busbar_plugin_loader::dispatch::Metric<'_>) {
        self.0
            .lock()
            .unwrap()
            .extend(metric.labels.iter().map(|label| label.to_vec()));
    }
    fn diag(&self, diagnostic: busbar_plugin_loader::dispatch::Diagnostic<'_>) {
        let mut heard = self.0.lock().unwrap();
        if !diagnostic.name.is_empty() {
            heard.push(diagnostic.name.to_vec());
        }
        heard.push(diagnostic.text.to_vec());
    }
    fn dropped(&self, _: busbar_plugin_loader::dispatch::Dropped) {
        self.1.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
fn actual_mcp_cases(dropped: bool) -> BTreeMap<String, String> {
    use busbar_plugin_loader::dispatch::{
        load_dropped, load_linked, Bind, ConnTable, DispatchConfig, LinkedRow,
    };
    let configuration: Value = serde_json::from_str(super::inputs()).unwrap();
    let k = &configuration["plane"];
    assert!(
        k["sessions"].is_null() && k["serve_first"].is_null() && k["empty"].is_null(),
        "new MCP cases require explicit ordinary operations"
    );
    assert_eq!(k["member"], "fs");
    assert_eq!(k["public_url"], "https://busbar.example");
    assert_eq!(k["far_end"]["status"], 200);
    assert_eq!(k["attempt"]["to_far_end"], false);
    assert_eq!(k["narrow"]["unit"], 9);
    assert_eq!(k["narrow"]["reply_cap"], 236);
    assert_eq!(k["narrow"]["more"], 1);
    assert_eq!(k["short"]["unit"], 11);
    assert_eq!(k["refusal"]["status"], 403);
    assert_eq!(k["refusal"]["text"], "denied");
    let settings = serde_json::to_vec(&configuration["settings"]).unwrap();
    let refresh = serde_json::to_vec(&k["refresh_settings"]).unwrap();
    let bad: Vec<Vec<u8>> = k["bad_settings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::to_vec(v).unwrap())
        .collect();
    let request = text(&k["request"], "request");
    let far_bytes = text(&k["far_end"]["answer"], "far_end.answer");
    let head = pairs(&k["far_end"]["fields"], "far_end.fields");
    let answer = (200, head.as_slice());
    let claimed = Arrival::of(&k["claimed"], "claimed");
    let unclaimed = Arrival::of(&k["unclaimed"], "unclaimed");
    let claim = claimed.claim;
    let refusal = (403, b"denied".to_vec());
    let public_url = b"https://busbar.example";
    let url = Some(public_url.as_slice());
    let services = Arc::new(McpServices::new());
    let d = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        services.clone(),
    ));
    let table = super::mcp_network::host(d.conn_waker(), Some(super::mcp_network::anchors()));
    let diagnostics = Arc::new(McpDiagnostics::default());
    let bound = Bind {
        instance: Arc::from("mcp-case"),
        max_inflight_cap: 1024,
        sink: diagnostics.clone(),
        dispatcher: d.adopter(),
        conns: ConnTable::Host(table),
    };
    let row = LinkedRow::of(busbar_plane_mcp::door).unwrap();
    let p: Plugin<Plane> = if dropped {
        load_dropped(&super::plugin_path(), &row.statement, bound)
    } else {
        load_linked(&row, bound)
    }
    .expect("actual MCP door loads");
    let declaration = p.declared();
    *services.kinds.lock().unwrap() = declaration
        .record_kinds
        .iter()
        .enumerate()
        .map(|(i, k)| {
            (
                k.to_string(),
                declaration
                    .record_chains
                    .iter()
                    .any(|chain| chain.kind as usize == i),
            )
        })
        .collect();
    let carried = Carried {
        member: b"fs".to_vec(),
        pool: None,
        caller_ref: None,
        host: Some(services),
    };
    let c = &carried;
    let held = p.inner.clone();
    let resumes_before = held.resumes.load(std::sync::atomic::Ordering::SeqCst);
    let count = || {
        let resumed = held.resumes.load(std::sync::atomic::Ordering::SeqCst);
        held.crossings.load(std::sync::atomic::Ordering::SeqCst) - resumed
    };
    let mut r: BTreeMap<String, String> = BTreeMap::new();
    let before = count();
    r.insert(
        "facts".into(),
        format!(
            "{:?} {} max_inflight={}",
            p.kind(),
            p.name(),
            p.max_inflight()
        ),
    );
    assert_eq!(count() - before, 0, "facts");
    let section = p.served().section;
    let dealt = |b: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(b).expect("conformance.json settings are JSON");
        serde_json::to_vec(&serde_json::json!({ section: value })).expect("a dealt blob")
    };
    for (i, b) in bad.iter().enumerate() {
        {
            let label = (&format!("validate bad #{i}")).to_string();
            let before = count();
            let value = { called(&validate(&p, &dealt(b))) };
            assert_eq!(count() - before, 1, "{label}: exact first crossings");
            r.insert(label, value)
        };
    }
    {
        let label = ("validate").to_string();
        let before = count();
        let value = { called(&validate(&p, &dealt(&settings))) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };

    {
        let label = ("arrive unopened").to_string();
        let before = count();
        let value = { arrive(&p, &claimed, &request) };
        assert_eq!(count() - before, 0, "{label}: exact first crossings");
        r.insert(label, value)
    };
    let opened = handed(&p.served(), &settings);
    {
        let label = ("open").to_string();
        let before = count();
        let value = { open(&p, &opened, url) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };
    {
        let before = count();
        let ready = p.ready(&d, Duration::from_secs(30));
        assert!(ready.is_ok(), "actual MCP readiness: {ready:?}");
        assert_eq!(count() - before, u64::from(p.has_ready()));
        r.insert(
            "ready".to_string(),
            format!("has_ready={} {ready:?}", p.has_ready()),
        );
    }

    {
        let label = ("open again").to_string();
        let before = count();
        let value = { open(&p, &opened, url) };
        assert_eq!(count() - before, 0, "{label}: exact first crossings");
        r.insert(label, value)
    };

    let driver = d.driver(&p, 0);
    {
        let label = ("hydrate").to_string();
        let before = count();
        let value = { generation(&p, slot::HYDRATE, 1) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };
    {
        let label = ("start").to_string();
        let before = count();
        let value = { generation(&p, slot::START, 1) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };

    {
        let label = ("arrive claimed").to_string();
        let before = count();
        let value = { arrive(&p, &claimed, &request) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };
    {
        let label = ("arrive unclaimed").to_string();
        let before = count();
        let value = { arrive(&p, &unclaimed, &request) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };

    {
        let unit = claimed.unit;
        let whole = PIECE_HAS_STATUS | PIECE_LAST;
        let room = (CAP, CAP);

        let one = Unit::mint(&d, 1024);
        for (label, g) in [
            ("attempt", attempt(unit, claim)),
            (
                "body",
                Given {
                    from: FROM_CALLER,
                    flags: PIECE_LAST,
                    bytes: &request,
                    attempt_no: 0,
                    ..attempt(unit, claim)
                },
            ),
            ("far_end", far_end(unit, claim, whole, &far_bytes, answer)),
        ] {
            {
                let label = (label).to_string();
                let before = count();
                let value = { on_piece(&p, &d, &one, g, room, c).line(Piece::line) };
                assert_eq!(count() - before, 1, "{label}: exact first crossings");
                r.insert(label, value)
            };
        }
        one.end(&d);

        let (narrow_unit, cap, more) = (9_u64, 236_usize, 1_u64);
        let narrow = Unit::mint(&d, cap);

        let arrives = |r: &mut BTreeMap<String, String>, what: &str, unit: u64| {
            {
                let label = (&format!("{what} arrive")).to_string();
                let before = count();
                let value = { arrive(&p, &claimed.for_unit(unit), &request) };
                assert_eq!(count() - before, 1, "{label}: exact first crossings");
                r.insert(label, value)
            };
        };
        let sends = |r: &mut BTreeMap<String, String>, what: &str, unit: u64, on: &Unit| {
            {
                let label = (&format!("{what} body")).to_string();
                let before = count();
                let value = {
                    {
                        let g = Given {
                            from: FROM_CALLER,
                            flags: PIECE_LAST,
                            bytes: &request,
                            attempt_no: 0,
                            ..attempt(unit, claim)
                        };
                        on_piece(&p, &d, on, g, room, c).line(Piece::line)
                    }
                };
                assert_eq!(count() - before, 1, "{label}: exact first crossings");
                r.insert(label, value)
            };
        };
        arrives(&mut r, "narrow", narrow_unit);
        {
            let label = ("narrow attempt").to_string();
            let before = count();
            let value = {
                on_piece(&p, &d, &narrow, attempt(narrow_unit, claim), room, c).line(Piece::line)
            };
            assert_eq!(count() - before, 1, "{label}: exact first crossings");
            r.insert(label, value)
        };
        sends(&mut r, "narrow", narrow_unit, &narrow);
        {
            let label = ("narrow far_end").to_string();
            let before = count();
            let value = {
                let g = far_end(narrow_unit, claim, whole, &far_bytes, answer);
                on_piece(&p, &d, &narrow, g, room, c).line(Piece::line)
            };
            assert_eq!(count() - before, 1, "{label}: exact first crossings");
            r.insert(label, value)
        };
        for i in 0..more {
            {
                let label = (&format!("narrow more #{i}")).to_string();
                let before = count();
                let value = {
                    let g = far_end(narrow_unit, claim, 0, b"", answer);
                    on_piece(&p, &d, &narrow, g, room, c).line(Piece::line)
                };
                assert_eq!(count() - before, 1, "{label}: exact first crossings");
                r.insert(label, value)
            };
        }
        narrow.end(&d);

        let (short_unit, buffer) = (11_u64, Buffer::Units);
        let short = Unit::mint(&d, 1024);
        arrives(&mut r, "short", short_unit);
        {
            let label = ("short attempt").to_string();
            let before = count();
            let value =
                { on_piece(&p, &d, &short, attempt(short_unit, claim), room, c).line(Piece::line) };
            assert_eq!(count() - before, 1, "{label}: exact first crossings");
            r.insert(label, value)
        };
        sends(&mut r, "short", short_unit, &short);
        {
            let label = ("far_end short").to_string();
            let before = count();
            let value = {
                let g = far_end(short_unit, claim, whole, &far_bytes, answer);
                short_then(&p, &d, &short, g, buffer, c, Piece::line)
            };
            assert_eq!(count() - before, 2, "{label}: exact first crossings");
            r.insert(label, value)
        };
        short.end(&d);
    }

    {
        let label = ("refusal").to_string();
        let before = count();
        let value = {
            {
                let (mut reply, mut arena) = ([0_u8; 512], [0_u8; 256]);
                let mut fields = [z::<OutField>(); 2];
                let mut f: Frame<RefusalIn, RefusalOut> = Frame::new(input(), output());
                (f.input.cause, f.input.status, f.input.text) =
                    (REFUSAL_GATE, refusal.0, abi(&refusal.1));
                (f.input.reply_buf, f.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
                (f.input.fields_buf, f.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
                (f.input.arena_buf, f.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
                let c = p.call(slot::REFUSAL, &mut f);
                let written: Vec<String> = fields[..(f.out.fields_written as usize).min(2)]
                    .iter()
                    .map(|x| format!("{}={}", at(&arena, x.name), at(&arena, x.value)))
                    .collect();
                format!(
                    "{} reply={} fields={written:?} status={}",
                    called(&c),
                    String::from_utf8_lossy(
                        &reply[..(f.out.reply_written as usize).min(reply.len())]
                    ),
                    f.out.status
                )
            }
        };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };
    {
        let label = ("serve").to_string();
        let before = count();
        let value = { serve(&p, &d, None) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };
    {
        let label = ("project").to_string();
        let before = count();
        let value = {
            {
                let mut arena = [0_u8; 256];
                let mut signals = [z::<SignalEntry>(); 4];
                let mut f: Frame<ProjectIn, ProjectOut> = Frame::new(input(), output());
                (f.input.claim, f.input.target) = (claim, abi(&claimed.target));
                f.input.body = octets(&request);
                (f.input.signals_buf, f.input.signals_cap) = (signals.as_mut_ptr(), signals.len());
                (f.input.arena_buf, f.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
                let c = p.call(slot::PROJECT, &mut f);
                format!("{} signals={}", called(&c), f.out.view.signals_len)
            }
        };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };
    {
        let label = ("drive").to_string();
        let before = count();
        let value = {
            {
                let (c, named) = drive(&p, driver);
                format!("{} sessions={}", called(&c), named.len())
            }
        };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };

    {
        let label = ("release none").to_string();
        let before = count();
        let value = { called(&release(&p, 0)) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };
    {
        let label = ("tick").to_string();
        let before = count();
        let value = {
            match driver {
                Some(driver) => {
                    let done = d.tick(&p, driver, 1_000).wait_done();
                    let next = done.frame.as_ref().map_or(0, |f| f.out.next_tick_ns);
                    format!("{} next={next}", called(&answered(&done)))
                }
                None => "Refused lease=false no driver ticket next=0".to_string(),
            }
        };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };
    {
        let label = ("cancel").to_string();
        let before = count();
        let value = {
            {
                let mut f: Frame<PlaneCancelIn, PlaneCancelOut> = Frame::new(input(), output());
                let c = p.call(life::CANCEL, &mut f);
                format!("{} disposition={}", called(&c), f.out.cancel.disposition)
            }
        };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };

    let refresh = |what: &[u8]| {
        let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(input(), output());
        (f.input.generation, f.input.settings) = (2, json(what));
        let (c, snap) = p.refresh(&mut f);
        format!("{} {}", called(&c), snapshot(snap.as_ref()))
    };
    {
        let label = ("refresh").to_string();
        let before = count();
        let value = { refresh(&handed(&p.served(), &refresh)) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };
    {
        let label = ("retire").to_string();
        let before = count();
        let value = { generation(&p, life::RETIRE, 1) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };
    {
        let label = ("close").to_string();
        let before = count();
        let value = { called(&close(&p)) };
        assert_eq!(count() - before, 1, "{label}: exact first crossings");
        r.insert(label, value)
    };

    {
        let label = ("arrive after close").to_string();
        let before = count();
        let value = { arrive(&p, &claimed, &request) };
        assert_eq!(count() - before, 0, "{label}: exact first crossings");
        r.insert(label, value)
    };
    if let Some(driver) = driver {
        d.recycle(driver);
    }
    assert!(
        held.resumes.load(std::sync::atomic::Ordering::SeqCst) > resumes_before,
        "actual networked MCP {} leg must resume at least one pending operation",
        if dropped { "dropped" } else { "linked" },
    );
    let at = |label: &str| r.get(label).expect(label).as_str();
    let str_of = |v: &Value, what: &str| String::from_utf8(text(v, what)).expect("UTF-8 input");
    for (label, answer) in &r {
        if label != "arrive after close" {
            assert!(!answer.starts_with("Fault "), "{label}: {answer}");
        }
    }
    let request_unit = k["request_unit"].as_bool() != Some(false);
    let units: &[&str] = if request_unit {
        &[
            "attempt",
            "body",
            "far_end",
            "narrow attempt",
            "narrow far_end",
            "short attempt",
        ]
    } else {
        &[]
    };
    for label in units {
        assert!(at(label).starts_with("Ready "), "{label}: {}", at(label));
    }
    for label in [
        "validate",
        "open",
        "hydrate",
        "start",
        "arrive claimed",
        "refusal",
        "drive",
        "tick",
        "cancel",
        "refresh",
        "retire",
        "close",
    ] {
        assert!(at(label).starts_with("Ready "), "{label}: {}", at(label));
    }
    release_none_contract(at("release none"));
    for (i, _) in k["bad_settings"]
        .as_array()
        .expect("conformance.json: bad_settings must be an array")
        .iter()
        .enumerate()
    {
        let refused = at(&format!("validate bad #{i}"));
        assert!(
            !refused.starts_with("Ready ") && refused.len() > "Refused lease=false ".len(),
            "a refused validate names why: {refused}"
        );
    }
    assert!(
        at("arrive unopened").starts_with("Refused "),
        "{}",
        at("arrive unopened")
    );
    assert!(
        at("open again").starts_with("Refused "),
        "one open per instance: {}",
        at("open again")
    );
    assert!(
        at("arrive after close").starts_with("Fault "),
        "{}",
        at("arrive after close")
    );

    let want_claims = |what: &str| {
        let c = pairs(&k[what], what);
        claims(c.iter().map(|(v, t)| (v.as_str(), t.as_str())))
    };
    assert!(
        at("open").contains(&format!("gen=1 claims=[{}] ", want_claims("open_claims"))),
        "open: {}",
        at("open")
    );
    assert!(
        at("refresh").contains(&format!(
            "gen=2 claims=[{}] ",
            want_claims("refresh_claims")
        )),
        "refresh: {}",
        at("refresh")
    );

    if let Some(route) = k["claimed"]["route"].as_object() {
        let want = format!(
            " route={} entry={}",
            str_of(&route["class"], "claimed.route.class"),
            str_of(&route["entry"], "claimed.route.entry")
        );
        assert!(
            at("arrive claimed").ends_with(&want),
            "a claimed request routes over{want}: {}",
            at("arrive claimed")
        );
        if let Some(flags) = route["flags"].as_array() {
            let flags: Vec<String> = flags
                .iter()
                .map(|f| str_of(f, "claimed.route.flags[]"))
                .collect();
            let want = format!(" route_flags={flags:?} ");
            assert!(
                at("arrive claimed").contains(&want),
                "a claimed request states{want}: {}",
                at("arrive claimed")
            );
        }
    }
    let status = num(&k["unclaimed"]["status"], "unclaimed.status");
    let unclaimed = at("arrive unclaimed");
    assert!(
        !unclaimed.starts_with("Ready ") && unclaimed.ends_with(&format!(" status={status}")),
        "an unclaimed request is refused at {status}: {unclaimed}"
    );

    if request_unit {
        let far = false;
        for label in ["attempt", "narrow attempt", "short attempt"] {
            assert!(
                at(label).contains(&format!(" to_far_end={far} ")),
                "{label}: {}",
                at(label)
            );
        }
        let request_out = str_of(&k["request_out"], "request_out");
        for label in ["narrow arrive", "short arrive"] {
            assert!(at(label).starts_with("Ready "), "{label}: {}", at(label));
        }
        for label in ["body", "narrow body", "short body"] {
            assert!(
                at(label).contains(&format!(" emitted={request_out} more=0 to_far_end=true ")),
                "{label}: {}",
                at(label)
            );
        }

        let f = &k["far_end"];
        let answer_out = str_of(&f["answer_out"], "far_end.answer_out");
        let units = reported(&f["units"], "far_end.units");
        let fs = num(&f["status"], "far_end.status");
        let whole = at("far_end");
        assert!(
            whole.contains(&format!(
                " emitted={answer_out} more=0 to_far_end=false done=true status={fs} "
            )) && whole.ends_with(&units),
            "the far end's whole answer, relayed with its count ({units}): {whole}"
        );

        let more = num(&k["narrow"]["more"], "narrow.more");
        let mut pieces = vec![at("narrow far_end").to_string()];
        pieces.extend((0..more).map(|i| at(&format!("narrow more #{i}")).to_string()));
        let mut relayed = String::new();
        for (i, line) in pieces.iter().enumerate() {
            let last = i + 1 == pieces.len();
            let emitted = line
                .split_once(" emitted=")
                .and_then(|(_, rest)| rest.split_once(" more="))
                .map(|(e, _)| e)
                .unwrap_or_else(|| panic!("narrow piece #{i}: {line}"));
            relayed.push_str(emitted);
            let tail = if last {
                " more=0 to_far_end=false done=true "
            } else {
                " more=1 to_far_end=false done=false "
            };
            assert!(
                line.starts_with("Ready ") && line.contains(tail),
                "narrow piece #{i}: {line}"
            );
        }
        assert_eq!(
            relayed, answer_out,
            "the narrow pieces relay the whole answer"
        );
        assert!(
            pieces[0].ends_with(&units),
            "the count rides the first narrow write: {}",
            pieces[0]
        );

        let short = at("far_end short");
        let buffer = Buffer::of(&k["short"]["buffer"], "short.buffer").unwrap_or(Buffer::Units);
        assert!(
            short.starts_with("Failed ")
                && !short.contains(&format!(" {}_needed=0 ", buffer.name()))
                && short.contains(" recall=true then=Ready ")
                && short.contains(&format!(
                    " emitted={answer_out} more=0 to_far_end=false done=true "
                ))
                && short.ends_with(&units),
            "a short answer, re-called once with room: {short}"
        );

        if k["empty"].is_object() {
            let want = str_of(&k["empty"]["outcome"], "empty.outcome");
            assert!(
                at("empty").starts_with(&format!("{want} ")),
                "empty: {}",
                at("empty")
            );
        }
    }
    assert!(
        k["sessions"].is_null(),
        "new MCP sessions need explicit ordinary test cases"
    );
    if let Some(reply) = k["refusal"]["reply"].as_str() {
        assert!(
            at("refusal").contains(&format!(" reply={reply} ")),
            "refusal: {}",
            at("refusal")
        );
    }
    assert_eq!(
        d.stats().deadline_without_wake,
        0,
        "pending work wakes before its deadline"
    );
    assert!(
        !diagnostics.1.load(std::sync::atomic::Ordering::SeqCst),
        "MCP envelope capture must be complete"
    );
    for credential in configuration["credentials"].as_array().unwrap() {
        use base64::Engine as _;
        let canary = credential.as_str().unwrap().as_bytes();
        assert!(
            !canary.is_empty()
                && canary
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || *c == b'-'),
            "fixed MCP canary has no percent-escaped bytes"
        );
        let spellings = [
            canary.to_vec(),
            base64::engine::general_purpose::STANDARD
                .encode(canary)
                .trim_end_matches('=')
                .as_bytes()
                .to_vec(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(canary)
                .into_bytes(),
            canary
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .into_bytes(),
            canary
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
                .into_bytes(),
        ];
        for spelling in spellings {
            for (label, answer) in &r {
                assert!(
                    !answer
                        .as_bytes()
                        .windows(spelling.len())
                        .any(|w| w == spelling),
                    "configured credential escaped in {label}"
                );
            }
            for diagnostic in diagnostics.0.lock().unwrap().iter() {
                assert!(
                    !diagnostic.windows(spelling.len()).any(|w| w == spelling),
                    "configured child credential escaped through MCP envelope"
                );
            }
        }
    }
    let reported: BTreeSet<_> = r.values().flat_map(|line| reported_indices(line)).collect();
    for index in 0..p.served().billable_classes.len() {
        assert!(
            reported.contains(&index),
            "declared MCP billable class {index} is reported"
        );
    }
    r
}
#[test]
fn the_actual_mcp_door_preserves_every_product_case_linked_and_dropped() {
    assert_eq!(actual_mcp_cases(false), actual_mcp_cases(true));
}
fn reported_indices(line: &str) -> Vec<usize> {
    let Some(at) = line.find("units=[") else {
        return Vec::new();
    };
    let list = &line[at + "units=[".len()..];
    let list = &list[..list.find(']').unwrap_or(list.len())];
    list.split(',')
        .filter_map(|e| e.trim().trim_matches('"').split(':').next()?.parse().ok())
        .collect()
}
