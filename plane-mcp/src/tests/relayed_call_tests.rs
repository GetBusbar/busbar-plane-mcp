// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RELAYED CALL IS THE REQUEST AND THE ANSWER THE PLANE SAYS. The linked door is admitted
//! through the one loader and driven op by op, as the plugin crate's door witness drives it
//! (`plane-mcp-plugin/tests/door_witness.rs`), and its transcript is held to the plane's own
//! builders: the request bound for the member is `call::outbound`'s, the settled answers are
//! `call::settle_call`'s, the call record is `record::call_suffix`'s. Those builders are this crate's,
//! so the comparison lives here; the door is driven through the loader's own frames
//! (`busbar_plugin_loader::conformance::{input, output}`), so this module needs no raw ABI call.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_OCTETS};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
    RecordWrite, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
    PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED,
};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::services::{Caller, Stored, UNSERVED};
use busbar_plugin_loader::conformance::{input, output};
use busbar_plugin_loader::dispatch::kinds::plane::{OwnedSnapshot, Plane};
use busbar_plugin_loader::dispatch::{
    in_head, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
    Plugin,
};
use serde_json::{json, Value};

use crate::codec::{H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION, PROTOCOL_VERSION};

/// The relayed call (`tests/support/door_facts.rs`'s, which the plugin crate's witness sends).
const RELAY_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"fs_read_file","arguments":{"path":"/a"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

/// An empty element of each buffer a piece is answered into.
const OUT_FIELD: OutField = OutField {
    name: Span { offset: 0, len: 0 },
    value: Span { offset: 0, len: 0 },
};
const RECORD_WRITE: RecordWrite = RecordWrite {
    kind: 0,
    op: 0,
    key: Span { offset: 0, len: 0 },
    value: Span { offset: 0, len: 0 },
};
const UNIT_COUNT: UnitCount = UnitCount {
    class: 0,
    source: 0,
    amount: 0,
};

/// The claim of `(verb, target)` on the HTTP carrier: its row of the door's route table.
fn route_of(verb: &str, target: &str) -> u32 {
    let i = crate::door::ROUTES
        .iter()
        .position(|r| r.verb == verb && r.target == target && r.carrier == "http")
        .expect("the door routes it");
    u32::try_from(i).expect("a small table")
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        // The conformance door is driven op by op and opens nothing: bound as a probe.
        conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
    }
}

fn octets(b: &'static [u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn text(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn at(buf: &[u8], s: Span) -> String {
    String::from_utf8_lossy(&buf[s.offset as usize..(s.offset + s.len) as usize]).into_owned()
}

const fn field(name: &'static str, value: &'static str) -> Field {
    Field {
        name: abi_str(name),
        value: abi_str(value),
    }
}

/// What one op answered, read back: the outcome, the status it stated, the bytes it wrote and
/// the head fields, and anything else the op answers in its own out struct.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Step {
    what: &'static str,
    outcome: Outcome,
    status: u32,
    reply: Vec<u8>,
    fields: Vec<(String, String)>,
    detail: String,
    snapshot: Option<OwnedSnapshot>,
    /// The record writes the answers carried: `(kind, key, value)`.
    records: Vec<(u32, Vec<u8>, Vec<u8>)>,
    /// The audit rows the answers carried (`RECORD_AUDIT` writes): `(outcome, action,
    /// resource)`.
    audits: Vec<(u32, String, String)>,
    /// The last ledger lane an answer named.
    lane: Option<String>,
    /// The counts the answers reported: `(class, amount)`.
    units: Vec<(u32, u64)>,
}

impl Step {
    fn new(what: &'static str, outcome: Outcome) -> Self {
        Step {
            what,
            outcome,
            status: 0,
            reply: Vec::new(),
            fields: Vec::new(),
            detail: String::new(),
            snapshot: None,
            records: Vec::new(),
            audits: Vec::new(),
            lane: None,
            units: Vec::new(),
        }
    }
}

fn arrive(
    p: &Plugin<Plane>,
    what: &'static str,
    unit: u64,
    (verb, target): (&'static str, &'static str),
    body: &'static [u8],
    fields: &'static [Field],
) -> (Step, Option<Vec<u8>>) {
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(input(), output());
    (a.input.head, a.out.head) = (in_head(), out_head());
    a.input.unit = unit;
    a.input.claim = route_of(verb, target);
    (a.input.method, a.input.target) = (text(verb.as_bytes()), text(target.as_bytes()));
    a.input.body = octets(body);
    (a.input.fields, a.input.fields_len) = (fields.as_ptr(), fields.len());
    let c = p.call(slot::ARRIVE, &mut a);
    let mut s = Step::new(what, c.outcome);
    s.status = a.out.refusal_status;
    s.detail = format!(
        "op_class={} principal_required={} dialect={} refusal={}",
        a.out.op_class,
        a.out.principal_need == PRINCIPAL_REQUIRED,
        a.out.dialect,
        a.out.refusal
    );
    (s, c.error)
}

/// One piece as the kernel pushes it: who it is from, its flags and status, the attempt it
/// starts and the member it names, the far end's head fields and the bytes.
#[derive(Clone, Copy)]
struct Push {
    from: u32,
    flags: u32,
    status: u32,
    attempt: u32,
    member: &'static str,
    head: &'static [Field],
    bytes: &'static [u8],
}

impl Push {
    /// The caller's whole body.
    const fn caller(bytes: &'static [u8]) -> Self {
        Push {
            from: FROM_CALLER,
            flags: PIECE_LAST,
            status: 0,
            attempt: 0,
            member: "",
            head: &[],
            bytes,
        }
    }

    /// The kernel's ATTEMPT piece naming `member`.
    const fn attempt(member: &'static str) -> Self {
        Push {
            from: FROM_KERNEL,
            flags: 0,
            status: 0,
            attempt: 1,
            member,
            head: &[],
            bytes: b"",
        }
    }

    /// The far end's whole answer: its status, its kept head fields and its body.
    const fn far(status: u32, head: &'static [Field], bytes: &'static [u8]) -> Self {
        Push {
            from: FROM_FAR_END,
            flags: PIECE_LAST | PIECE_HAS_STATUS,
            status,
            attempt: 0,
            member: "",
            head,
            bytes,
        }
    }
}

/// One `on_piece` of `unit` with a reply buffer of `cap` bytes, then re-called with the same
/// `from` and zero bytes while the door answers `more = 1`. The bytes of every call, in order,
/// the head fields and the request line it wrote, and its flags.
fn push(p: &Plugin<Plane>, what: &'static str, unit: u64, given: Push, cap: usize) -> Step {
    let mut reply = vec![0_u8; cap];
    let (mut fields, mut arena) = ([OUT_FIELD; 16], vec![0_u8; 4096]);
    let mut records = [RECORD_WRITE; 16];
    let mut units = [UNIT_COUNT; 8];
    let mut out = Step::new(what, Outcome::Ready);
    let mut calls = 0;
    let mut flags = 0;
    let mut line = String::new();
    let mut first = true;
    loop {
        let mut i: OnPieceIn = input();
        i.head = in_head();
        (i.unit, i.from) = (unit, given.from);
        if first {
            (i.flags, i.bytes) = (given.flags, octets(given.bytes));
            (i.status_code, i.attempt_no) = (given.status, given.attempt);
            i.member = text(given.member.as_bytes());
            (i.head_fields, i.head_fields_len) = (given.head.as_ptr(), given.head.len());
        } else {
            i.bytes = octets(b"");
        }
        (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
        (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
        let mut o: OnPieceOut = output();
        o.head = out_head();
        let mut f = Frame::new(i, o);
        let c = p.call(slot::ON_PIECE, &mut f);
        out.units.extend(
            units[..f.out.units_written as usize]
                .iter()
                .map(|u| (u.class, u.amount)),
        );
        let span = |s: Span| {
            let at = s.offset as usize;
            arena[at..at + s.len as usize].to_vec()
        };
        for r in &records[..f.out.records_written as usize] {
            if r.op == busbar_contract::abi::plane::RECORD_AUDIT {
                out.audits
                    .push((r.kind, at(&arena, r.key), at(&arena, r.value)));
            } else {
                out.records.push((r.kind, span(r.key), span(r.value)));
            }
        }
        if f.out.lane.len != 0 {
            out.lane = Some(at(&arena, f.out.lane));
        }
        calls += 1;
        first = false;
        out.outcome = c.outcome;
        if f.out.reply_status != 0 {
            out.status = f.out.reply_status;
        }
        out.fields.extend(
            fields[..f.out.fields_written as usize]
                .iter()
                .map(|f| (at(&arena, f.name), at(&arena, f.value))),
        );
        if f.out.verb.len != 0 {
            line = format!("{} {}", at(&arena, f.out.verb), at(&arena, f.out.target));
        }
        flags |= f.out.flags;
        out.reply
            .extend_from_slice(&reply[..usize::try_from(f.out.emitted).expect("small")]);
        if c.outcome != Outcome::Ready || f.out.more == 0 || calls > 256 {
            out.detail = format!(
                "calls={calls} done={} far={} more={} request={line}",
                flags & EMIT_DONE != 0,
                flags & EMIT_TO_FAR_END != 0,
                f.out.more
            );
            return out;
        }
    }
}

fn step<'a>(t: &'a [Step], what: &str) -> &'a Step {
    t.iter()
        .find(|s| s.what == what)
        .unwrap_or_else(|| panic!("the script has no `{what}` step"))
}

fn document(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("a JSON document")
}

fn linked(d: &Dispatcher) -> Plugin<Plane> {
    let row = LinkedRow::of(crate::door).expect("the linked door states its Statement");
    load_linked(&row, bind(d)).expect("the linked door loads")
}

/// The head field of a JSON answer.
fn json_type() -> (String, String) {
    ("content-type".to_string(), "application/json".to_string())
}

/// A whole answer's stated length (the served engine's JSON answers stated theirs).
fn length_of(reply: &[u8]) -> (String, String) {
    ("content-length".to_string(), reply.len().to_string())
}

/// A HOST whose entitlement answer is a fixed table of `"<kind>:<name>"` grants, and which
/// serves nothing else: the kernel's entitlement service, as the door asks it. As the kernel's
/// (`KernelServices::entitled`), a crossing that serves no unit is entitled to nothing: the
/// loader's request lookup must hand the unit the crossing serves.
struct Grants(&'static [&'static str]);

impl busbar_plugin_loader::dispatch::HostServices for Grants {
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
        _: &str,
        _: &[u8],
        _: busbar_plugin_loader::dispatch::Later,
    ) -> busbar_plugin_loader::dispatch::Ran {
        busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_list(
        &self,
        _: &Caller,
        _: busbar_contract::services::RecordsList,
        _: busbar_plugin_loader::dispatch::Later,
    ) -> busbar_plugin_loader::dispatch::Ran {
        busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
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
        _: &str,
        _: &str,
        _: busbar_plugin_loader::dispatch::Later,
    ) -> busbar_plugin_loader::dispatch::Ran {
        busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
    }
    /// The kernel's Approve as this section's approvals seed it: `read_file` approved at its
    /// digest, `draft` allowed and pending (ARCHITECT Q3: the door renders the verdict).
    fn trust_serves(
        &self,
        _: &Caller,
        counterparty: &str,
        item: Option<&str>,
        _: Option<&str>,
    ) -> Stored {
        use busbar_contract::abi::host::service::{
            DISTRUST_NONE, DISTRUST_NOT_APPROVED, DISTRUST_UNKNOWN_ITEM,
        };
        Stored::ready(match (counterparty, item) {
            ("fs", Some("read_file")) => DISTRUST_NONE,
            ("fs", Some("draft")) => DISTRUST_NOT_APPROVED,
            _ => DISTRUST_UNKNOWN_ITEM,
        })
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn entitlement_check(&self, _: &Caller, unit: Option<u64>, target: &str) -> Stored {
        Stored::ready(if unit.is_some() && self.0.contains(&target) {
            busbar_contract::abi::host::service::ENTITLED
        } else {
            busbar_contract::abi::host::service::NOT_ENTITLED
        })
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
}

/// The deployment's public base URL the host lends `open`.
const PUBLIC_URL: &str = "https://busbar.example";

/// Every grant the relayed calls need.
const ALL: &[&str] = &[
    "mcp_server:fs",
    "mcp_tool:fs_read_file",
    "mcp_tool:fs_draft",
];

/// One server with one approved tool (its `path` argument mirrored in `Mcp-Param-Path`), one
/// tool awaiting approval, and the `roots` grant with nothing declared to disclose.
const RELAY_SECTION: &[u8] = br#"{"fs": {"url": "https://mcp.example/fs/rpc?v=1", "pin": {"mechanism": "pinned_pubkey", "key": "sha256/K="}, "grants": {"roots": true}, "tools_allow": {"read_file": {"schema_hash": "sha256:aa", "input_schema": {"type": "object", "properties": {"path": {"type": "string", "x-mcp-header": "Path"}}}}, "draft": {}}}}"#;

const RELAY_FIELDS: &[Field] = &[
    field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
    field(H_MCP_METHOD, "tools/call"),
    field(H_MCP_NAME, "fs_read_file"),
    field("mcp-param-path", "/a"),
];

const JSON_HEAD: &[Field] = &[field("content-type", "application/json")];

const SSE_HEAD: &[Field] = &[field("content-type", "text/event-stream")];

/// The far end's answers: a result, a JSON-RPC error, a result streamed after a progress
/// frame, and an ask for roots busbar holds the grant for and has nothing to disclose.
const FAR_OK: &[u8] =
    br#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"hi"}]}}"#;

const FAR_ERROR: &[u8] = br#"{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"nope"}}"#;

const FAR_SSE: &[u8] = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"busbar-0\",\"progress\":1}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"content\":[]}}\n\n";

const FAR_ASK: &[u8] = br#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}}}}"#;

fn served(grants: &'static [&'static str]) -> Dispatcher {
    Dispatcher::with_services(DispatchConfig::default(), Arc::new(Grants(grants)))
}

/// THE RELAY SCRIPT'S CALLS: each far answer a member gives one relayed call, read back.
fn relay_script(p: &Plugin<Plane>) -> Vec<Step> {
    let mut t = Vec::new();
    let mut i: PlaneOpenIn = input();
    (i.open.generation, i.open.settings) = (1, octets(RELAY_SECTION));
    i.public_url = text(PUBLIC_URL.as_bytes());
    let o: PlaneOpenOut = output();
    t.push(Step::new("open", p.open(&mut Frame::new(i, o)).0.outcome));
    let post = ("POST", "/mcp");
    let far_answers = [
        ("answer ok", FAR_OK, JSON_HEAD),
        ("answer error", FAR_ERROR, JSON_HEAD),
        ("answer stream", FAR_SSE, SSE_HEAD),
        ("answer ask", FAR_ASK, JSON_HEAD),
    ];
    for (n, (what, far, head)) in (40_u64..).zip(far_answers) {
        t.push(arrive(p, "arrive call", n, post, RELAY_CALL, RELAY_FIELDS).0);
        t.push(push(p, "attempt", n, Push::attempt("fs"), 64));
        t.push(push(p, "send", n, Push::caller(RELAY_CALL), 64));
        t.push(push(p, what, n, Push::far(200, head, far), 64));
    }
    t
}

/// What the plane's own pure functions say one relayed call answers.
fn admitted() -> crate::call::AdmittedCall {
    let section = crate::door::read_tools_section(RELAY_SECTION).expect("the section reads");
    let catalogue = crate::catalogue::Catalogue::build(1, &section);
    let params = document(RELAY_CALL)["params"].clone();
    let header = |name: &str| (name == "mcp-param-path").then(|| "/a".to_string());
    match crate::call::admit_call(
        &catalogue,
        &json!(30),
        Some(&params),
        &header,
        &|_, _| true,
        &mut |_, _| crate::ask::AskDecision::Proceed,
    ) {
        crate::call::Admission::Go(a) => a,
        other => panic!("the call is admitted: {other:?}"),
    }
}

fn settled(far: &[u8], sse: bool) -> (u32, Vec<u8>) {
    let section = crate::door::read_tools_section(RELAY_SECTION).expect("the section reads");
    match crate::call::settle_call(&admitted(), section.servers.get("fs"), 200, far, sse, 0) {
        crate::call::Settled::Answer { status, body, .. } => (status, body),
        other => panic!("an answer: {other:?}"),
    }
}

/// The relayed call: the ATTEMPT is taken, the caller's body becomes the request bound for the
/// member (the dialect's own builder, at the path of the member's URL), and the far end's
/// answer is settled as the plane's pure settle says, in JSON.
#[test]
fn a_relayed_call_is_the_request_and_the_answer_the_plane_says() {
    let t = relay_script(&linked(&served(ALL)));
    let attempt = step(&t, "attempt");
    assert_eq!((attempt.outcome, attempt.reply.len()), (Outcome::Ready, 0));
    let send = step(&t, "send");
    assert_eq!(send.outcome, Outcome::Ready);
    assert!(
        send.detail
            .ends_with("done=false far=true more=0 request=POST /fs/rpc?v=1"),
        "{}",
        send.detail
    );
    let section = crate::door::read_tools_section(RELAY_SECTION).expect("the section reads");
    let def = section.servers.get("fs").expect("registered");
    let want =
        crate::call::outbound(&admitted(), "fs", def, 0, None).expect("the member is reachable");
    assert_eq!(send.reply, want.body, "the dialect builder's body");
    assert_eq!(send.fields, want.fields, "the dialect builder's head");
    assert_eq!(document(&send.reply)["params"]["name"], json!("read_file"));

    let ok = step(&t, "answer ok");
    assert_eq!(
        (ok.outcome, ok.status),
        (Outcome::Ready, settled(FAR_OK, false).0)
    );
    assert_eq!(ok.reply, settled(FAR_OK, false).1);
    assert_eq!(document(&ok.reply)["id"], json!(30));
    assert_eq!(
        document(&ok.reply)["result"]["resultType"],
        json!("complete")
    );
    assert_eq!(ok.fields, vec![json_type(), length_of(&ok.reply)]);
    assert!(ok.detail.contains("done=true far=false"), "{}", ok.detail);
    // THE METER: a call the server answered is counted, once, as one tool call (tail class 0)
    // and the bytes of the document it answered with (tail class 1, a Response class: "the
    // length of the document it just read back"), and the success earns its fee unit (tail
    // class 2, `per_request`). The plane states its counts; the kernel prices them.
    assert_eq!(
        ok.units,
        vec![
            (crate::door::CLASS_FEE_INDEX, 1),
            (0, 1),
            (1, u64::try_from(FAR_OK.len()).expect("a small answer"))
        ],
        "the one tool call the server answered, its answer's bytes, and its fee unit"
    );
    // THE CALL LOG (RULE-CHECK 2026-09-30): the answer carries the call's one chained record,
    // keyed by the caller's chain scope (no caller reference: the ungoverned scope), its suffix
    // the plane's own fields at the host clock's reading (this HOST's clock reads 0).
    assert_eq!(
        ok.records,
        vec![(
            crate::door::RECORD_CALL,
            crate::ask::UNGOVERNED.as_bytes().to_vec(),
            crate::record::call_suffix(0, "fs", "fs_read_file", "dispatched", "", "sha256:aa", 1),
        )],
        "one call record"
    );
    // THE AUDIT ROW (SEAM-L(k)): the dispatched call's one `mcp_tool.call` row, applied, on the
    // published tool; and THE LEDGER LANE (SEAM-L(j)): the published tool, as the served engine
    // priced and ledgered a call.
    assert_eq!(
        ok.audits,
        vec![(
            busbar_contract::abi::plane::AUDIT_APPLIED,
            "mcp_tool.call".to_string(),
            "mcp_tool:fs_read_file".to_string()
        )],
        "one applied audit row"
    );
    assert_eq!(
        send.lane.as_deref(),
        Some("fs_read_file"),
        "the call's lane"
    );

    let error = step(&t, "answer error");
    assert_eq!(error.reply, settled(FAR_ERROR, false).1);
    assert_eq!(document(&error.reply)["result"]["isError"], json!(true));

    let stream = step(&t, "answer stream");
    assert_eq!(
        stream.reply,
        settled(FAR_SSE, true).1,
        "the stream's last event"
    );

    // A GRANTED ASK IS RELAYED under busbar's sealed state (Law 11); a host that signs nothing
    // cannot seal it, so the ask is refused, never answered by busbar.
    let ask = step(&t, "answer ask");
    assert_eq!(ask.status, 403);
    assert_eq!(
        document(&ask.reply)["error"]["data"]["reason"],
        json!("ask_no_sealer")
    );
}
