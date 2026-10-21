// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FACTS THE DOOR-ONLY SUITES SPELL, PINNED TO THE CRATE'S OWN; and the pure checks that moved
//! in from those suites.
//!
//! The suites that drive the door over its C ABI (`tests/sessions.rs`, `tests/door_audit.rs`,
//! `tests/tasks.rs`, the plugin crate's `tests/door_witness.rs`) need `unsafe` for the host they
//! stand up, so they stay integration tests and reach the crate through `door` alone (this crate
//! forbids `unsafe`, BUSBAR-1.6.0.md l.273). What they must know about the wire they spell: the
//! route table and its named rows, the header fields a client mirrors, the task rows' bytes, the
//! error codes. Each spelling is held to the crate's own table here, so a change on one side is a
//! red test, not two answers.

use serde_json::{json, Value};

use crate::door;

/// The route table the door-only suites claim against, `(verb, target, carrier)` in claim order.
const SPELLED_ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/.well-known/oauth-protected-resource/mcp", "http"),
    ("POST", "/mcp", "http"),
    ("GET", "/mcp", "http"),
    ("DELETE", "/mcp", "http"),
    ("POST", "/mcp", "sse"),
    ("POST", "/mcp/tasks/run", "http"),
    ("POST", "/mcp", "stdio"),
];

#[test]
fn the_suites_route_table_is_the_doors() {
    let routes: Vec<(&str, &str, &str)> = door::ROUTES
        .iter()
        .map(|r| (r.verb, r.target, r.carrier))
        .collect();
    assert_eq!(routes, SPELLED_ROUTES);
    assert_eq!(door::LINE_ROUTE, 6, "tests/door_audit.rs's LINE_ROUTE");
    assert_eq!(door::TASK_RUN_ROUTE, 5, "tests/tasks.rs's TASK_RUN_ROUTE");
    assert_eq!(crate::tool_claims::TASK_RUN_MOUNT, "/mcp/tasks/run");
    assert_eq!(door::RECORD_TASK, 3, "tests/tasks.rs's RECORD_TASK");
}

/// The fields `tests/tasks.rs`'s `mirrored` spells, for each of its branches, are the plane's.
#[test]
fn the_suites_mirrored_fields_are_the_planes() {
    let pair = |n: &str, v: &str| (n.to_string(), v.to_string());
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "st_read_file", "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28", "progressToken": "p"}}});
    assert_eq!(
        crate::codec::mirrored(&call),
        vec![
            pair("accept", "text/event-stream, application/json"),
            pair("mcp-method", "tools/call"),
            pair("mcp-name", "st_read_file"),
            pair("mcp-protocol-version", "2026-07-28"),
        ]
    );
    let get = json!({"jsonrpc": "2.0", "id": 2, "method": "tasks/get",
        "params": {"taskId": "a b"}});
    assert_eq!(
        crate::codec::mirrored(&get),
        vec![
            pair("accept", "application/json, text/event-stream"),
            pair("mcp-method", "tasks/get"),
            pair("mcp-name", "=?base64?YSBi?="),
        ]
    );
    let logged = json!({"jsonrpc": "2.0", "id": 3, "method": "resources/read",
        "params": {"uri": "file:///a", "_meta": {"io.busbar/loggingLevel": "info"}}});
    assert_eq!(
        crate::codec::mirrored(&logged),
        vec![
            pair("accept", "text/event-stream, application/json"),
            pair("mcp-method", "resources/read"),
            pair("mcp-name", "file:///a"),
        ]
    );
    assert_eq!(
        crate::codec::mirrored(&json!(null)),
        vec![pair("accept", "application/json, text/event-stream")]
    );
}

/// The task rows `tests/tasks.rs` seeds the host's records with are the bytes the plane writes.
#[test]
fn the_suites_task_rows_are_the_planes() {
    use crate::tool_tasks::{index_key, Status, TaskLease, WorkRow};
    let row = WorkRow {
        status: Status::Working,
        created_ms: 1,
        updated_ms: 1,
        digest: "d".to_string(),
    };
    assert_eq!(row.bytes(), b"t1|working|1|1|d");
    let lease = TaskLease {
        until_ms: 1,
        updated_ms: 1,
    };
    assert_eq!(lease.bytes(), b"l1|1|1");
    let principal = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    let owner = busbar_contract::redacted::sha256_hex(principal.as_bytes());
    assert_eq!(
        index_key(principal, "t"),
        format!("o/{}/t", &owner[..32]).into_bytes()
    );
}

/// The wire facts the plugin crate's door witness spells (`plane-mcp-plugin/tests/door_witness.rs`):
/// the header names, the revision, the metadata path, the sections, the codes it reads answers by.
#[test]
fn the_witness_spelled_wire_facts_are_the_planes() {
    assert_eq!(crate::codec::H_PROTOCOL_VERSION, "mcp-protocol-version");
    assert_eq!(crate::codec::H_MCP_METHOD, "mcp-method");
    assert_eq!(crate::codec::H_MCP_NAME, "mcp-name");
    assert_eq!(crate::codec::PROTOCOL_VERSION, "2026-07-28");
    assert_eq!(
        crate::tool_claims::DEFAULT_METADATA,
        "/.well-known/oauth-protected-resource/mcp"
    );
    assert_eq!(crate::tools_config::SECTION, "tools");
    assert_eq!(door::ENDPOINT_SECTION, "mcp");
    assert_eq!(crate::codec::CODE_REFUSED, -32000);
    assert_eq!(crate::codec::CODE_INTERNAL, -32603);
    assert_eq!(crate::codec::CODE_HEADER_MISMATCH, -32020);
    assert_eq!(door::CLASS_FEE_INDEX, 2);
}

// ── P-M11: a name the routing key cannot spell ──────────────────────────────────────────────────

/// RED P-M11: A SERVER ID OR A `tools_allow` NAME THE ROUTING KEY CANNOT SPELL IS REFUSED AT
/// VALIDATE, in words naming it; never accepted and then silently undispatchable.
#[test]
fn a_name_the_routing_key_cannot_spell_is_refused_at_validate() {
    let tool = br#"{"st": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "tools_allow": {"read file": {}}}}"#;
    let refused = crate::door::read_tools_section(tool).expect_err("a tool name with a space");
    assert!(
        refused.contains("`tools.st`") && refused.contains("read file"),
        "{refused}"
    );
    let server = br#"{"s+t": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "tools_allow": {"read_file": {}}}}"#;
    let refused = crate::door::read_tools_section(server).expect_err("a server id with a `+`");
    assert!(refused.contains("s+t"), "{refused}");
    let fine = br#"{"st": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "tools_allow": {"read_file.v2-x": {}}}}"#;
    assert!(crate::door::read_tools_section(fine).is_ok());
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
    let framing =
        crate::framing::Framing::of(Some(crate::framing::EVENT_STREAM), "tools/call", &body)
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

// ── C-H1: the answers to a task's own rounds ────────────────────────────────────────────────────

/// An ask, built the one way a `CallerAsk` can be built: from an operator-written config entry.
fn elicitation(key: &str) -> crate::ask::CallerAsk {
    crate::ask::CallerAsk::from_config(
        key,
        &crate::tools_config::AskEntryCfg {
            method: "elicitation/create".into(),
            params: Some(json!({})),
        },
    )
}

/// C-H1 [HIGH]: `tasks/update` keeps only the answers the task's current round asked for. A key
/// the round did not ask is ignored (SEP-2663: keys the task is not waiting on are not refused), so
/// an update cannot smuggle a tool argument into the call the task runs (call.rs, the synchronous
/// rule: "an answer may only supply what was asked for").
#[test]
fn an_update_keeps_only_the_keys_the_round_asked() {
    let mut t = crate::tool_tasks::Task::new("0123456789abcdef0123456789abcdef", "k", 7, "d1", 1);
    t.park(vec![elicitation("confirm")], 1);
    assert!(t.deliver(
        &serde_json::from_value(json!({"confirm": {"action": "accept"}, "path": "/etc/shadow"}))
            .unwrap(),
        2,
    ));
    assert_eq!(
        t.answers().get("confirm"),
        Some(&json!({"action": "accept"}))
    );
    assert!(
        t.answers().get("path").is_none(),
        "an answer the round never asked is kept: {:?}",
        t.answers()
    );
    let mut idle =
        crate::tool_tasks::Task::new("0123456789abcdef0123456789abcdef", "k", 7, "d1", 1);
    assert!(idle.deliver(&serde_json::from_value(json!({"path": "/x"})).unwrap(), 2));
    assert!(idle.answers().is_empty(), "{:?}", idle.answers());
}

/// C-H1 [HIGH]: the answers never rewrite an argument the call was admitted with: the hooks and the
/// argument guard judged the admitted arguments, and those are the arguments that go out.
#[test]
fn an_answer_never_rewrites_an_admitted_argument() {
    let answers: serde_json::Map<String, Value> =
        serde_json::from_value(json!({"path": "/etc/shadow", "confirm": {"action": "accept"}}))
            .unwrap();
    assert_eq!(
        crate::tool_tasks::merge_answers(&json!({ "path": "/a" }), &answers),
        json!({ "path": "/a", "confirm": {"action": "accept"} }),
        "an answer rewrote an admitted argument"
    );
}
