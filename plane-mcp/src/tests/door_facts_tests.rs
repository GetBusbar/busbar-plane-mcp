// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FACTS THE DOOR-ONLY SUITES SPELL, PINNED TO THE CRATE'S OWN; and the pure checks that moved
//! in from those suites.
//!
//! The suites that drive the door over its C ABI (`tests/sessions.rs`, `tests/door_audit.rs`,
//! `tests/tasks.rs`, the plugin crate's `tests/both_ways.rs`) need `unsafe` for the host they
//! stand up, so they stay integration tests and reach the crate through `door` alone (this crate
//! forbids `unsafe`, BUSBAR-1.6.0.md l.273). The door's private constants they need are restated in
//! `tests/support/door_facts.rs`; this module includes that same file and holds each value to the
//! item it restates. `tests/tasks.rs` also spells two readers of its own (the header fields a client
//! mirrors and the task rows' bytes), held to the crate's below.

use serde_json::{json, Value};

use crate::statement;

#[path = "../../tests/support/door_facts.rs"]
#[allow(dead_code)] // `claim` is the door-driven tests' reader, not this check's
mod stated;

#[test]
fn the_door_driven_tests_restate_the_doors_own_constants() {
    let routes: Vec<(&str, &str, &str)> = statement::ROUTES
        .iter()
        .map(|r| (r.verb, r.target, r.carrier))
        .collect();
    assert_eq!(stated::ROUTES, &routes[..]);
    assert_eq!(stated::LINE_ROUTE, statement::LINE_ROUTE);
    assert_eq!(stated::TASK_RUN_ROUTE, statement::TASK_RUN_ROUTE);
    assert_eq!(stated::TASK_RUN_MOUNT, crate::tool_claims::TASK_RUN_MOUNT);
    assert_eq!(stated::RECORD_TASK, statement::RECORD_TASK);
    assert_eq!(stated::CLASS_FEE_INDEX, statement::CLASS_FEE_INDEX);
    assert_eq!(stated::H_PROTOCOL_VERSION, crate::codec::H_PROTOCOL_VERSION);
    assert_eq!(stated::H_MCP_METHOD, crate::codec::H_MCP_METHOD);
    assert_eq!(stated::H_MCP_NAME, crate::codec::H_MCP_NAME);
    assert_eq!(stated::PROTOCOL_VERSION, crate::codec::PROTOCOL_VERSION);
    assert_eq!(
        stated::DEFAULT_METADATA,
        crate::tool_claims::DEFAULT_METADATA
    );
    assert_eq!(stated::TOOLS_SECTION, crate::tools_config::SECTION);
    assert_eq!(stated::ENDPOINT_SECTION, statement::ENDPOINT_SECTION);
    assert_eq!(stated::CODE_REFUSED, crate::codec::CODE_REFUSED);
    assert_eq!(stated::CODE_INTERNAL, crate::codec::CODE_INTERNAL);
    assert_eq!(
        stated::CODE_HEADER_MISMATCH,
        crate::codec::CODE_HEADER_MISMATCH
    );
    assert_eq!(stated::RECORD_CALL, statement::RECORD_CALL);
    assert_eq!(stated::UNGOVERNED, crate::ask::UNGOVERNED);
    let open: Vec<bool> = statement::ROUTES.iter().map(|r| r.open).collect();
    assert_eq!(stated::ROUTES_OPEN, &open[..]);
    assert_eq!(stated::ADMIN_VERBS, statement::ADMIN_VERBS);
    assert_eq!(
        Some(stated::OP_CLASS_TOOLS_LIST),
        statement::op_class_index(crate::tool_ops::OP_TOOLS_LIST)
    );
    assert_eq!(
        Some(stated::OP_CLASS_NOTIFICATION),
        statement::op_class_index(crate::tool_ops::OP_NOTIFICATION)
    );
    assert_eq!(stated::NOT_JSON, crate::tool_arrival::NOT_JSON);
    assert_eq!(stated::UNSERVED, crate::plane_door::UNSERVED);
    let (error, description) = stated::METHOD_NOT_ALLOWED;
    assert_eq!(
        statement::method_not_allowed_body(),
        serde_json::to_vec(&json!({ "error": error, "error_description": description })).unwrap()
    );
}

/// The door witness's expectations of the plane's own functions (`plane-mcp-plugin/tests/
/// both_ways.rs`, which reaches only `door`): the catalogue's answer for its section, the endpoint
/// under its public base URL, the size of its relayed call's projection, and the call record's framing.
#[test]
fn the_door_witness_restates_what_the_planes_functions_answer() {
    let section =
        statement::read_tools_section(stated::WITNESS_SECTION).expect("the section reads");
    let catalogue = crate::catalogue::Catalogue::build(1, &section);
    assert_eq!(
        catalogue.tools_list(&json!(9), &|_: &str, _: &str| false, |_| false),
        stated::WITNESS_TOOLS_LIST_ANSWER
    );
    assert_eq!(
        statement::under_public_url("https://busbar.example"),
        (
            "https://busbar.example/mcp".to_string(),
            format!("https://busbar.example{}", stated::DEFAULT_METADATA)
        ),
        "the witness's audience and metadata document under its public base URL"
    );
    let call: Value = serde_json::from_slice(stated::RELAY_CALL).expect("a document");
    let invocation = crate::call::invocation(call).expect("a call is an invocation");
    assert_eq!(
        busbar_contract::ir::facts::IrFacts::shape(&invocation).text_chars,
        stated::RELAY_CALL_TEXT_CHARS
    );
    let args = (0, "fs", "fs_read_file", "dispatched", "", "sha256:aa", 1);
    assert_eq!(
        stated::call_suffix(args.0, args.1, args.2, args.3, args.4, args.5, args.6),
        crate::record::call_suffix(args.0, args.1, args.2, args.3, args.4, args.5, args.6)
    );
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

// ── P-M11: a name the routing key cannot spell ──────────────────────────────────────────────────

/// RED P-M11: A SERVER ID OR A `tools_allow` NAME THE ROUTING KEY CANNOT SPELL IS REFUSED AT
/// VALIDATE, in words naming it; never accepted and then silently undispatchable.
#[test]
fn a_name_the_routing_key_cannot_spell_is_refused_at_validate() {
    let tool = br#"{"st": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "tools_allow": {"read file": {}}}}"#;
    let refused = crate::statement::read_tools_section(tool).expect_err("a tool name with a space");
    assert!(
        refused.contains("`tools.st`") && refused.contains("read file"),
        "{refused}"
    );
    let server = br#"{"s+t": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "tools_allow": {"read_file": {}}}}"#;
    let refused = crate::statement::read_tools_section(server).expect_err("a server id with a `+`");
    assert!(refused.contains("s+t"), "{refused}");
    let fine = br#"{"st": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "tools_allow": {"read_file.v2-x": {}}}}"#;
    assert!(crate::statement::read_tools_section(fine).is_ok());
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

/// THE RELAYED-CALL SCRIPT'S EXPECTATIONS ARE THE PLANE'S BUILDERS' (the plugin crate's
/// `tests/relayed_call.rs`, which reaches only `door`): the request bound for the member is
/// `call::outbound`'s, and each settled answer is `call::settle_call_as`'s.
#[test]
fn the_relayed_call_script_restates_what_the_planes_builders_answer() {
    let section = statement::read_tools_section(stated::RELAY_SECTION).expect("the section reads");
    let catalogue = crate::catalogue::Catalogue::build(1, &section);
    let params =
        serde_json::from_slice::<Value>(stated::RELAY_CALL).expect("a document")["params"].clone();
    let header = |name: &str| (name == "mcp-param-path").then(|| "/a".to_string());
    let admitted = match crate::call::admit_trusted(
        &catalogue,
        &json!(30),
        Some(&params),
        &header,
        &|_, _| true,
        &mut |_| crate::call::Trust::Verdict(busbar_contract::abi::host::service::DISTRUST_NONE),
        &mut |_, _| crate::ask::AskDecision::Proceed,
    ) {
        crate::call::Admission::Go(a) => a,
        other => panic!("the call is admitted: {other:?}"),
    };
    let def = section.servers.get("fs").expect("registered");
    let want = crate::call::outbound(&admitted, "fs", def, 0, None).expect("reachable");
    assert_eq!(
        want.body,
        stated::RELAY_REQUEST_BODY,
        "the dialect builder's body"
    );
    let fields: Vec<(&str, &str)> = want
        .fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        fields,
        stated::RELAY_REQUEST_FIELDS,
        "the dialect builder's head"
    );
    for (far, sse, (status, body)) in [
        (stated::RELAY_FAR_OK, false, stated::RELAY_SETTLED_OK),
        (stated::RELAY_FAR_ERROR, false, stated::RELAY_SETTLED_ERROR),
        (stated::RELAY_FAR_SSE, true, stated::RELAY_SETTLED_STREAM),
    ] {
        match crate::call::settle_call_as(
            &admitted,
            Some(def),
            200,
            far,
            sse,
            0,
            crate::client::jsonrpc::dispatch_request_id(0),
        ) {
            crate::call::Settled::Answer {
                status: s, body: b, ..
            } => {
                assert_eq!((s, b.as_slice()), (status, body));
            }
            other => panic!("an answer: {other:?}"),
        }
    }
}
