// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S FACTS THE DOOR-DRIVEN TESTS NAME (`tests/sessions.rs`, `tests/door_audit.rs`,
//! `tests/tasks.rs`, and the plugin crate's `tests/both_ways.rs`). Those
//! tests drive the plane only through [`door`](busbar_plane_mcp::door), the crate's one public item,
//! and need a few of its private constants to build their inputs and read its answers. They are
//! restated here, plain data, and the crate's own unit test `door_facts_tests`
//! (`src/tests/door_facts_tests.rs`) includes this same file and asserts every value equals the
//! private item it restates, so a drift is red in the crate before a door-driven test reads a stale
//! value.

/// `door::ROUTES` as `(verb, target, carrier)`, in order: a route's index is the claim an arrival
/// carries.
pub const ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/.well-known/oauth-protected-resource/mcp", "http"),
    ("POST", "/mcp", "http"),
    ("GET", "/mcp", "http"),
    ("DELETE", "/mcp", "http"),
    ("POST", "/mcp", "sse"),
    ("POST", "/mcp/tasks/run", "http"),
    ("POST", "/mcp", "stdio"),
];

/// `door::LINE_ROUTE`: the line carrier's row of [`ROUTES`].
pub const LINE_ROUTE: usize = 6;

/// `door::TASK_RUN_ROUTE`: the task-run claim's row of [`ROUTES`].
pub const TASK_RUN_ROUTE: usize = 5;

/// `tool_claims::TASK_RUN_MOUNT`: the task-run claim's target.
pub const TASK_RUN_MOUNT: &str = "/mcp/tasks/run";

/// `door::RECORD_TASK`: the record kind a task's row is written under.
pub const RECORD_TASK: u32 = 3;

/// `door::CLASS_FEE_INDEX`: the fee unit's class index in the door's tail.
pub const CLASS_FEE_INDEX: u32 = 2;

/// `codec::H_PROTOCOL_VERSION`: the revision's header.
pub const H_PROTOCOL_VERSION: &str = "mcp-protocol-version";

/// `codec::H_MCP_METHOD`: the mirrored method's header.
pub const H_MCP_METHOD: &str = "mcp-method";

/// `codec::H_MCP_NAME`: the mirrored name's header.
pub const H_MCP_NAME: &str = "mcp-name";

/// `codec::PROTOCOL_VERSION`: the revision this plane speaks.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// `tool_claims::DEFAULT_METADATA`: the protected-resource metadata path the door serves.
pub const DEFAULT_METADATA: &str = "/.well-known/oauth-protected-resource/mcp";

/// `tools_config::SECTION`: the section the door's Statement declares.
pub const TOOLS_SECTION: &str = "tools";

/// `door::ENDPOINT_SECTION`: the endpoint block the door owns beside it.
pub const ENDPOINT_SECTION: &str = "mcp";

/// `codec::CODE_REFUSED`: the one refusal family.
pub const CODE_REFUSED: i64 = -32000;

/// `codec::CODE_INTERNAL`: the internal error, which a refusal never is.
pub const CODE_INTERNAL: i64 = -32603;

/// `codec::CODE_HEADER_MISMATCH`: a mirrored header that disagrees with its body.
pub const CODE_HEADER_MISMATCH: i64 = -32020;

/// The claim (route index) of `(verb, target)` on `carrier`.
///
/// # Panics
///
/// When the door states no such route.
#[must_use]
pub fn claim(verb: &str, target: &str, carrier: &str) -> u32 {
    let i = ROUTES
        .iter()
        .position(|&(v, t, c)| v == verb && t == target && c == carrier)
        .expect("the door routes it");
    u32::try_from(i).expect("a small table")
}

/// `door::RECORD_CALL`: the record kind a call's chained record is written under.
pub const RECORD_CALL: u32 = 0;

/// `ask::UNGOVERNED`: the chain scope of a caller with no reference.
pub const UNGOVERNED: &str = "<ungoverned>";

/// `door::ROUTES`' `open` column, in the same order as [`ROUTES`]: only the discovery document is
/// served with no inbound credential.
pub const ROUTES_OPEN: &[bool] = &[true, false, false, false, false, false, false];

/// `door::ADMIN_VERBS`: the admin routes, `(verb, target)`, each stated with flags `0`.
pub const ADMIN_VERBS: &[(&str, &str)] = &[
    ("POST", "/tools/{name}/connect"),
    ("GET", "/tools/{name}/changes"),
    ("GET", "/tools/{name}/health"),
];

/// `door::op_class_index(tool_ops::OP_TOOLS_LIST)`: the op class a `tools/list` arrives as.
pub const OP_CLASS_TOOLS_LIST: u32 = 1;

/// `door::op_class_index(tool_ops::OP_NOTIFICATION)`: the op class a notification arrives as.
pub const OP_CLASS_NOTIFICATION: u32 = 16;

/// `tool_arrival::NOT_JSON`: the words a body that is not JSON is refused in.
pub const NOT_JSON: &str = "Request body is not valid JSON.";

/// `plane_door::UNSERVED`: the refusal an arrival on a route the door does not answer carries.
pub const UNSERVED: u32 = 2;

/// `door::method_not_allowed_body()`, as its `(error, error_description)`.
pub const METHOD_NOT_ALLOWED: (&str, &str) = (
    "method_not_allowed",
    "A GET or DELETE here must name an MCP session (Mcp-Session-Id). MCP 2026-07-28 is POST only; \
     2025-11-25 and 2025-06-18 open a session with a POSTed `initialize`; a 2024-11-05 client opens \
     its event stream with a GET that accepts text/event-stream and names no MCP-Protocol-Version.",
);

/// The door witness's one fronted server, the section its script opens the door on.
pub const WITNESS_SECTION: &[u8] =
    br#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;

/// The catalogue's `tools/list` answer, under id `9`, for [`WITNESS_SECTION`] to a caller entitled
/// to nothing (`Catalogue::build(1, ..).tools_list(&json!(9), ..)`).
pub const WITNESS_TOOLS_LIST_ANSWER: &[u8] = br#"{"id":9,"jsonrpc":"2.0","result":{"cacheScope":"private","resultType":"complete","tools":[],"ttlMs":0}}"#;

/// The door witness's relayed call: a `tools/call` of `fs_read_file`, its path argument mirrored.
pub const RELAY_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"fs_read_file","arguments":{"path":"/a"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

/// `IrFacts::shape(&call::invocation(RELAY_CALL)).text_chars`: the projected call's text size.
pub const RELAY_CALL_TEXT_CHARS: usize = 13;

/// `record::call_suffix`: a call record's length-prefixed suffix (`ts, server, tool, outcome,
/// reason, tool_digest, pin_generation`), each text `u64`-length-prefixed, each number as its
/// eight big-endian bytes under the same prefix.
#[must_use]
pub fn call_suffix(
    ts: u64,
    server: &str,
    tool: &str,
    outcome: &str,
    reason: &str,
    tool_digest: &str,
    pin_generation: u64,
) -> Vec<u8> {
    fn num(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&8u64.to_be_bytes());
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn text(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u64).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    let mut out = Vec::new();
    num(&mut out, ts);
    text(&mut out, server);
    text(&mut out, tool);
    text(&mut out, outcome);
    text(&mut out, reason);
    text(&mut out, tool_digest);
    num(&mut out, pin_generation);
    out
}

/// THE RELAYED-CALL SCRIPT's server (the plugin crate's `tests/relayed_call.rs`): one server with
/// one approved tool (its `path` argument mirrored in `Mcp-Param-Path`), one tool awaiting
/// approval, and the `roots` grant with nothing declared to disclose.
pub const RELAY_SECTION: &[u8] = br#"{"fs": {"url": "https://mcp.example/fs/rpc?v=1", "pin": {"mechanism": "pinned_pubkey", "key": "sha256/K="}, "grants": {"roots": true}, "tools_allow": {"read_file": {"schema_hash": "sha256:aa", "input_schema": {"type": "object", "properties": {"path": {"type": "string", "x-mcp-header": "Path"}}}}, "draft": {}}}}"#;

/// `call::outbound` of [`RELAY_CALL`] admitted over [`RELAY_SECTION`], to `fs` under request id
/// `0`: the request bound for the member, its body.
pub const RELAY_REQUEST_BODY: &[u8] = br#"{"id":0,"jsonrpc":"2.0","method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/protocolVersion":"2026-07-28","progressToken":null},"arguments":{"path":"/a"},"name":"read_file"}}"#;

/// The same request's head fields, in order.
pub const RELAY_REQUEST_FIELDS: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("accept", "application/json, text/event-stream"),
    ("mcp-protocol-version", "2026-07-28"),
    ("mcp-method", "tools/call"),
    ("mcp-name", "read_file"),
];

/// The far end's answers to the relayed call: a result, a JSON-RPC error, a result streamed after
/// a progress frame, and an ask for roots busbar holds the grant for and has nothing to disclose.
pub const RELAY_FAR_OK: &[u8] =
    br#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"hi"}]}}"#;
/// See [`RELAY_FAR_OK`].
pub const RELAY_FAR_ERROR: &[u8] =
    br#"{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"nope"}}"#;
/// See [`RELAY_FAR_OK`].
pub const RELAY_FAR_SSE: &[u8] = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"busbar-0\",\"progress\":1}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"content\":[]}}\n\n";
/// See [`RELAY_FAR_OK`].
pub const RELAY_FAR_ASK: &[u8] = br#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}}}}"#;

/// `call::settle_call_as` of each far answer (status 200), as the caller's answer: `(status, body)`.
pub const RELAY_SETTLED_OK: (u32, &[u8]) = (
    200,
    br#"{"id":30,"jsonrpc":"2.0","result":{"resultType":"complete","content":[{"type":"text","text":"hi"}]}}"#,
);
/// See [`RELAY_SETTLED_OK`].
pub const RELAY_SETTLED_ERROR: (u32, &[u8]) = (
    200,
    br#"{"id":30,"jsonrpc":"2.0","result":{"content":[{"text":"The MCP server `fs` did not complete this tool call: MCP upstream answered JSON-RPC error -32601: nope","type":"text"}],"isError":true,"resultType":"complete"}}"#,
);
/// See [`RELAY_SETTLED_OK`]: the stream's last event.
pub const RELAY_SETTLED_STREAM: (u32, &[u8]) = (
    200,
    br#"{"id":30,"jsonrpc":"2.0","result":{"resultType":"complete","content":[]}}"#,
);
