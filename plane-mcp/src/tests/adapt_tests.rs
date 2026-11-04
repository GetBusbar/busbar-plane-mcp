// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use serde_json::json;

#[test]
fn event_frames_normalize_each_sse_line_ending() {
    for data in ["one\ntwo", "one\rtwo", "one\r\ntwo"] {
        assert_eq!(
            frame(None, Some("message"), data),
            "event: message\ndata: one\ndata: two\n\n"
        );
    }
    assert_eq!(
        frame(None, None, "one\r\rthree"),
        "data: one\ndata: \ndata: three\n\n"
    );
}

#[test]
fn a_stateless_request_keeps_the_stateless_reading_whatever_else_it_carries() {
    let stateless = json!({"jsonrpc":"2.0","id":1,"method":"tools/list",
        "params":{"_meta":{META_PROTOCOL_VERSION: "2026-07-28"}}});
    assert_eq!(classify_post(&stateless, None, None), PostKind::Stateless);

    assert_eq!(
        classify_post(&stateless, Some("abc"), None),
        PostKind::Stateless
    );

    let bare = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
    assert_eq!(classify_post(&bare, None, None), PostKind::Stateless);
}

#[test]
fn initialize_session_and_message_address_posts_are_told_apart() {
    let init = json!({"jsonrpc":"2.0","id":0,"method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}});
    assert_eq!(classify_post(&init, None, None), PostKind::Initialize);
    let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
    assert_eq!(classify_post(&call, Some("s"), None), PostKind::InSession);
    assert_eq!(
        classify_post(&init, None, Some("s")),
        PostKind::EventStreamMessage
    );
}

#[test]
fn the_message_address_session_is_read_from_the_query() {
    assert_eq!(message_session_of(Some("sessionId=abc")), Some("abc"));
    assert_eq!(
        message_session_of(Some("x=1&sessionId=abc&y=2")),
        Some("abc")
    );
    assert_eq!(message_session_of(Some("sessionId=")), None);
    assert_eq!(message_session_of(Some("session=abc")), None);
    assert_eq!(message_session_of(None), None);
}

#[test]
fn red_no_stateless_only_method_reaches_a_session_client() {
    for m in [
        "server/discover",
        "subscriptions/listen",
        "tasks/get",
        "tasks/update",
        "tasks/cancel",
        "initialize",
    ] {
        assert_eq!(
            session_method(Some(m), true),
            SessionMethod::NotFound,
            "{m}"
        );
    }
    assert_eq!(
        session_method(Some("tools/call"), true),
        SessionMethod::Dispatch
    );
    assert_eq!(session_method(Some("ping"), true), SessionMethod::Ping);
    assert_eq!(
        session_method(Some(METHOD_INITIALIZED), false),
        SessionMethod::Accept
    );
    assert_eq!(session_method(None, true), SessionMethod::Accept);
    for m in [
        "resources/subscribe",
        "resources/unsubscribe",
        "logging/setLevel",
    ] {
        assert_eq!(
            session_method(Some(m), true),
            SessionMethod::Session,
            "{m}: subscribe stays for the old revisions"
        );
    }
}

#[test]
fn raising_adds_the_stateless_meta_and_mirrors_the_name() {
    let mut m = json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"echo","arguments":{},"_meta":{"progressToken":7}}});
    assert_eq!(raise(&mut m), Some(()));
    let mirror = crate::codec::mirrored(&m);
    let get = |n: &str| mirror.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    assert_eq!(get("mcp-protocol-version"), Some("2026-07-28"));
    assert_eq!(get("mcp-method"), Some("tools/call"));
    assert_eq!(get("mcp-name"), Some("echo"));
    let meta = &m["params"]["_meta"];
    assert_eq!(meta[META_PROTOCOL_VERSION], "2026-07-28");
    assert_eq!(meta[META_CLIENT_CAPABILITIES], json!({}));
    assert_eq!(meta["progressToken"], 7, "the client's own _meta survives");

    let mut bare = json!({"jsonrpc":"2.0","id":4,"method":"tools/list"});
    assert_eq!(raise(&mut bare), Some(()));
    assert!(crate::codec::mirrored(&bare)
        .iter()
        .all(|(k, _)| k != "mcp-name"));
    assert!(bare["params"]["_meta"].is_object());

    let mut bad = json!({"jsonrpc":"2.0","id":5,"method":"tools/list","params":[1]});
    assert_eq!(raise(&mut bad), None);
}

#[test]
fn lowering_strips_stateless_members_and_refuses_incomplete_results() {
    let mut r = json!({"tools":[],"resultType":"complete","cacheScope":"caller","ttlMs":1000});
    assert!(lower_result(&mut r));
    assert_eq!(r, json!({"tools":[]}));
    let mut ir = json!({"resultType":"input_required","inputRequests":{}});
    assert!(!lower_result(&mut ir));
    let mut task = json!({"resultType":"task"});
    assert!(!lower_result(&mut task));
}

#[test]
fn red_initialize_declares_no_stateless_only_capability() {
    let discovery = json!({
        "protocolVersion":"2026-07-28",
        "serverInfo":{"name":"busbar","version":"1.6.0"},
        "capabilities":{
            "tools":{"listChanged":true},"prompts":{"listChanged":true},
            "resources":{"listChanged":true,"subscribe":true},
            "completions":{},"logging":{},"extensions":{"x":{}}
        },
        "methods":["server/discover"]
    });
    let r = initialize_result(&discovery, Revision::R2025_11_25);
    assert_eq!(r["protocolVersion"], "2025-11-25");
    assert_eq!(r["serverInfo"]["name"], "busbar");
    let caps = r["capabilities"].as_object().unwrap();
    let mut keys: Vec<&str> = caps.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["completions", "logging", "prompts", "resources", "tools"]
    );
    assert_eq!(
        caps["resources"],
        json!({"listChanged": false, "subscribe": true}),
        "subscribe stays for the old revisions"
    );
    assert!(r.get("methods").is_none());

    let old = initialize_result(&discovery, Revision::R2024_11_05);
    assert!(old["capabilities"].get("completions").is_none());
    assert_eq!(old["capabilities"]["tools"], json!({"listChanged": false}));

    let none = initialize_result(&json!({"capabilities":{}}), Revision::R2025_06_18);
    assert_eq!(none["capabilities"], json!({}));
}

#[test]
fn event_stream_framing() {
    assert_eq!(
        frame(Some("0-1"), None, "{\"a\":1}"),
        "id: 0-1\ndata: {\"a\":1}\n\n"
    );
    assert_eq!(
        frame(None, Some(EVENT_MESSAGE), "a\nb"),
        "event: message\ndata: a\ndata: b\n\n"
    );
    assert_eq!(
        endpoint_event("/mcp", "0123"),
        "event: endpoint\ndata: /mcp?sessionId=0123\n\n"
    );
}

#[test]
fn the_param_mirror_names_every_annotated_string_integer_and_boolean_argument() {
    let schema = json!({"properties":{
        "region":{"type":"string","x-mcp-header":"Region"},
        "count":{"type":"integer","x-mcp-header":"Count"},
        "dry":{"type":"boolean","x-mcp-header":"Dry"},
        "ratio":{"type":"number","x-mcp-header":"Ratio"},
        "note":{"type":"string"},
        "opts":{"type":"object","properties":{"zone":{"type":"string","x-mcp-header":"Zone"}}}
    }});
    let args = json!({"region":"eu-west","count":3,"dry":false,"ratio":0.5,"note":"n",
        "opts":{"zone":"b"}});
    let mut mirror = param_mirror(Some(&schema), Some(&args));
    mirror.sort();
    assert_eq!(
        mirror,
        vec![
            ("mcp-param-count".to_string(), "3".to_string()),
            ("mcp-param-dry".to_string(), "false".to_string()),
            ("mcp-param-region".to_string(), "eu-west".to_string()),
            ("mcp-param-zone".to_string(), "b".to_string()),
        ]
    );
    assert!(param_mirror(None, Some(&args)).is_empty());
    assert!(param_mirror(Some(&schema), None).is_empty());
}

/// LOWERING CUTS ONLY THE STATELESS-ONLY MEMBERS' SPANS: an answer with nothing to lower is its own
/// bytes; one with them keeps every other member's order, spacing and number spelling, wherever
/// the cut members sit (first, between, last, all); an incomplete result is not expressible.
#[test]
fn lowering_an_answer_splices_its_own_bytes() {
    let plain = br#"{"id":1,"result":{"z":1.0,"a":1e3}}"#;
    assert_eq!(lower_answer(plain), Some(Lowered::Unchanged));
    let cases: &[(&str, &str)] = &[
        (
            r#"{"id":1,"result":{"resultType":"complete","z":1.0,"a":1e3}}"#,
            r#"{"id":1,"result":{"z":1.0,"a":1e3}}"#,
        ),
        (
            r#"{"id":1,"result":{"z":1.0,"ttlMs":5,"a":1e3}}"#,
            r#"{"id":1,"result":{"z":1.0,"a":1e3}}"#,
        ),
        (
            r#"{"id":1,"result":{"z":1.0,"ttlMs":5,"cacheScope":"x"}}"#,
            r#"{"id":1,"result":{"z":1.0}}"#,
        ),
        (
            r#"{"id":1,"result":{"ttlMs":5,"cacheScope":"x"}}"#,
            r#"{"id":1,"result":{}}"#,
        ),
        (
            "{\n  \"id\": 1,\n  \"result\": {\n    \"ttlMs\": 5,\n    \"b\": [1, 2]\n  }\n}",
            "{\n  \"id\": 1,\n  \"result\": {\n    \"b\": [1, 2]\n  }\n}",
        ),
    ];
    for (given, lowered) in cases {
        assert_eq!(
            lower_answer(given.as_bytes()),
            Some(Lowered::Spliced(lowered.as_bytes().to_vec())),
            "{given}"
        );
    }
    assert_eq!(
        lower_answer(br#"{"id":1,"result":{"resultType":"input_required"}}"#),
        Some(Lowered::Inexpressible)
    );
    assert_eq!(lower_answer(b"not json"), None);
}
/// M3-1: a bare CR is JSON whitespace, and every event-stream reader ends a line at one; a frame
/// splits on CR, LF and CRLF alike, so no `data:` line carries a CR.
#[test]
fn a_bare_cr_in_framed_data_ends_its_data_line() {
    let framed = frame(None, Some(EVENT_MESSAGE), "{\"a\":1\r,\"b\":2}");
    assert_eq!(
        framed,
        "event: message\ndata: {\"a\":1\ndata: ,\"b\":2}\n\n"
    );
    assert!(!framed.contains('\r'));
    assert_eq!(
        frame(None, None, "a\r\nb"),
        "data: a\ndata: b\n\n",
        "CRLF stays one break"
    );
}

#[test]
fn invalid_annotations_are_reported_instead_of_ignored() {
    for suffix in [
        serde_json::json!(true),
        serde_json::json!(""),
        serde_json::json!("bad name"),
    ] {
        let schema = serde_json::json!({"properties":{"a":{"x-mcp-header":suffix}}});
        assert!(validate_param_annotations(Some(&schema))
            .unwrap_err()
            .contains("field-name token"));
    }
    let duplicate =
        serde_json::json!({"properties":{"a":{"x-mcp-header":"One"},"b":{"x-mcp-header":"one"}}});
    assert!(validate_param_annotations(Some(&duplicate))
        .unwrap_err()
        .contains("repeat"));
    let mut deep = serde_json::json!({"properties":{"target":{"x-mcp-header":"Target"}}});
    for _ in 0..MAX_PARAM_DEPTH {
        deep = serde_json::json!({"properties":{"nested":deep}});
    }
    assert!(validate_param_annotations(Some(&deep))
        .unwrap_err()
        .contains("depth"));
}
