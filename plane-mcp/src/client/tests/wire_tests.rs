// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `2026-07-28` outbound wire: the mirrored headers, `params._meta`, and the un-namespacing.

use crate::client::jsonrpc::{parse_response, tools_list, RpcOutcome};
use crate::codec::{META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION};

fn tools_call(
    url: &str,
    key: &crate::identity::ToolKey,
    arguments: &serde_json::Value,
    request_id: u64,
    authorization: Option<&str>,
    advertise: crate::client::jsonrpc::AdvertisedCaps,
    continuation: Option<&serde_json::Value>,
) -> crate::client::jsonrpc::OutboundRequest {
    crate::client::jsonrpc::tools_call_id(
        url,
        key,
        arguments,
        &serde_json::Value::from(request_id),
        authorization,
        advertise,
        continuation,
    )
}

#[test]
fn an_unrequested_progress_token_is_absent_rather_than_null() {
    let request = tools_call(
        "https://u.example",
        &tkey("fs", "read"),
        &serde_json::json!({}),
        5,
        None,
        Default::default(),
        None,
    );
    let body = body_of(&request);
    assert!(body["params"]["_meta"].get("progressToken").is_none());
    assert_eq!(
        body,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {
                "name": "read", "arguments": {},
                "_meta": {
                    META_PROTOCOL_VERSION: "2026-07-28",
                    META_CLIENT_CAPABILITIES: {},
                },
            },
        })
    );
}

/// EVERY byte a request puts on the wire, concatenated: URL, each header name and value, the body.
fn wire_bytes(req: &crate::client::jsonrpc::OutboundRequest) -> Vec<u8> {
    let mut out = req.url.as_bytes().to_vec();
    for (name, value) in &req.headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out.extend_from_slice(&req.body);
    out
}

/// A routing key for a valid test server and tool.
fn tkey(server: &str, tool: &str) -> crate::identity::ToolKey {
    let server = crate::identity::ServerId::new(server).expect("test server id must be valid");
    crate::identity::ToolKey::new(server, tool).expect("test tool key must be valid")
}

fn body_of(req: &crate::client::jsonrpc::OutboundRequest) -> serde_json::Value {
    serde_json::from_slice(&req.body).expect("the body we build must be JSON")
}

fn header<'a>(req: &'a crate::client::jsonrpc::OutboundRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

#[test]
fn the_outbound_name_is_the_un_namespaced_tool() {
    let req = tools_call(
        "https://u.example/mcp",
        &tkey("filesystem", "read_file"),
        &serde_json::json!({"path": "/tmp/x"}),
        1,
        None,
        Default::default(),
        None,
    );
    let body = body_of(&req);

    assert_eq!(body["params"]["name"], "read_file");
    assert_eq!(header(&req, "mcp-name"), Some("read_file"));

    assert!(!String::from_utf8_lossy(&wire_bytes(&req)).contains("filesystem_read_file"));
}

#[test]
fn meta_lives_at_params_meta_and_not_at_the_top_level() {
    let req = tools_list("https://u.example/mcp", 1, None);
    let body = body_of(&req);
    assert!(body.get("_meta").is_none(), "no top-level `_meta`");
    assert_eq!(
        body["params"]["_meta"][META_PROTOCOL_VERSION],
        crate::codec::PROTOCOL_VERSION
    );

    assert_eq!(
        body["params"]["_meta"][META_CLIENT_CAPABILITIES],
        serde_json::json!({})
    );
}

#[test]
fn the_mirrored_headers_agree_with_the_body_they_mirror() {
    let req = tools_call(
        "https://u.example/mcp",
        &tkey("fs", "read"),
        &serde_json::json!({}),
        9,
        Some("tok"),
        Default::default(),
        None,
    );
    let body = body_of(&req);
    assert_eq!(header(&req, "mcp-method"), body["method"].as_str());
    assert_eq!(header(&req, "mcp-name"), body["params"]["name"].as_str());
    assert_eq!(
        header(&req, "mcp-protocol-version"),
        body["params"]["_meta"][META_PROTOCOL_VERSION].as_str()
    );
}

#[test]
fn tools_list_carries_no_mcp_name_because_it_has_no_target() {
    let req = tools_list("https://u.example/mcp", 1, None);
    assert_eq!(header(&req, "mcp-method"), Some("tools/list"));
    assert!(header(&req, "mcp-name").is_none());
}

#[test]
fn there_is_no_session_header_on_any_request() {
    for req in [
        tools_list("https://u.example/mcp", 1, Some("t")),
        tools_call(
            "https://u.example/mcp",
            &tkey("fs", "read"),
            &serde_json::json!({}),
            2,
            Some("t"),
            Default::default(),
            None,
        ),
    ] {
        assert!(header(&req, "mcp-session-id").is_none());
        assert!(header(&req, "last-event-id").is_none());
    }
}

#[test]
fn the_authorization_header_is_present_exactly_when_a_credential_was_planned() {
    let with = tools_list("https://u.example/mcp", 1, Some("abc"));
    assert_eq!(header(&with, "authorization"), Some("Bearer abc"));
    let without = tools_list("https://u.example/mcp", 1, None);
    assert!(header(&without, "authorization").is_none());
}

#[test]
fn a_jsonrpc_error_is_not_reported_as_a_result() {
    let out = parse_response(
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}"#,
        1,
    );
    assert_eq!(
        out,
        RpcOutcome::Error {
            code: -32601,
            message: "no such method".into()
        }
    );
}

/// An error object whose `code` is missing or not an integer is not a JSON-RPC error. It reads as
#[test]
fn an_error_without_an_integer_code_is_malformed_not_code_zero() {
    for body in [
        br#"{"jsonrpc":"2.0","id":1,"error":{"message":"no code"}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":"-32601","message":"string code"}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"fractional code"}}"#.as_slice(),
    ] {
        let out = parse_response(body, 1);
        assert!(
            matches!(out, RpcOutcome::Malformed(_)),
            "{} read as {out:?}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn a_result_is_returned_verbatim() {
    let out = parse_response(br#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#, 1);
    assert_eq!(out, RpcOutcome::Result(serde_json::json!({"content": []})));
}

#[test]
fn every_malformed_shape_is_refused_rather_than_guessed_at() {
    let bad: [&[u8]; 5] = [
        b"not json",
        br#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#,
        br#"{"jsonrpc":"1.0","id":1,"result":{}}"#,
        br#"{"jsonrpc":"2.0","id":1}"#,
        b"",
    ];
    assert_eq!(bad.len(), 5, "the malformed set must not shrink");
    for body in bad {
        assert!(
            matches!(parse_response(body, 1), RpcOutcome::Malformed(_)),
            "{:?} must be malformed",
            String::from_utf8_lossy(body)
        );
    }
}

/// M3-17: `progressToken` is `string | number` and optional in every revision's schema; `null` is
#[test]
fn a_call_that_asks_no_progress_carries_no_progress_token_member() {
    let call = |progress| {
        body_of(&tools_call(
            "https://u.example/mcp",
            &tkey("fs", "read"),
            &serde_json::json!({}),
            7,
            None,
            crate::client::jsonrpc::AdvertisedCaps {
                progress,
                ..Default::default()
            },
            None,
        ))
    };
    let quiet = call(false);
    assert!(
        quiet["params"]["_meta"].get("progressToken").is_none(),
        "no progress asked, no token member: {quiet}"
    );
    assert_eq!(call(true)["params"]["_meta"]["progressToken"], "busbar-7");
}
