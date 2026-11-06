// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::wire_json::{parse, parse_str};
use crate::client::jsonrpc::{parse_response_id, RpcOutcome};
use busbar_contract::spans::MAX_JSON_DEPTH;
use serde_json::Value;

#[test]
fn marker_object_ids_are_rejected_after_actual_wire_parse() {
    for key in [
        "$serde_json::private::Number",
        r"\u0024serde_json::private::Number",
        r"$serde_json::private::Num\u0062er",
    ] {
        let body = format!(r#"{{"jsonrpc":"2.0","id":{{"{key}":"27"}},"result":{{}}}}"#);
        let parsed = parse(body.as_bytes()).unwrap();
        assert!(parsed["id"].is_object());
        assert!(busbar_contract::jsonrpc::read_response(&parsed, &Value::from(27)).is_err());
        assert!(matches!(
            parse_response_id(body.as_bytes(), &Value::from(27)),
            RpcOutcome::Malformed(_) | RpcOutcome::Uncorrelated(_)
        ));
    }
}

#[test]
fn valid_numeric_and_string_ids_remain_exact_and_distinct() {
    for raw in [
        "27",
        "9007199254740993",
        "18446744073709551617",
        r#""27""#,
        r#""9007199254740993""#,
    ] {
        let sent = parse_str(raw).unwrap();
        assert_eq!(serde_json::to_string(&sent).unwrap(), raw);
        let body =
            format!(r#"{{"jsonrpc":"2.0","id":{raw},"result":{{"count":27.0000000000000001}}}}"#);
        let RpcOutcome::Result(result) = parse_response_id(body.as_bytes(), &sent) else {
            panic!("valid matching id {raw}")
        };
        assert_eq!(result["count"].to_string(), "27.0000000000000001");
    }
    assert!(matches!(
        parse_response_id(
            br#"{"jsonrpc":"2.0","id":"27","result":{}}"#,
            &Value::from(27)
        ),
        RpcOutcome::Uncorrelated(_)
    ));
}

#[test]
fn initialization_rejects_marker_object_id() {
    use crate::client::compat::{offered_revision, INITIALIZE_ID};
    for key in [
        "$serde_json::private::Number",
        r"\u0024serde_json::private::Number",
    ] {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{{"{key}":"{INITIALIZE_ID}"}},"result":{{"protocolVersion":"2025-06-18"}}}}"#
        );
        assert_eq!(offered_revision(body.as_bytes()), None);
    }
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":{INITIALIZE_ID},"result":{{"protocolVersion":"2025-06-18"}}}}"#
    );
    assert!(offered_revision(body.as_bytes()).is_some());
}

#[test]
fn opaque_marker_objects_and_numbers_keep_their_wire_types() {
    let body = br#"{"jsonrpc":"2.0","id":27,"result":{"nested":[{"\u0024serde_json::private::Number":"27"},1e+400,9007199254740993]}}"#;
    let RpcOutcome::Result(result) = parse_response_id(body, &Value::from(27)) else {
        panic!("valid response")
    };
    assert!(result["nested"][0].is_object());
    assert_eq!(result["nested"][0]["$serde_json::private::Number"], "27");
    assert_eq!(result["nested"][1].to_string(), "1e+400");
    assert_eq!(result["nested"][2].to_string(), "9007199254740993");
    assert!(serde_json::to_string(&result)
        .unwrap()
        .contains(r#"{"$serde_json::private::Number":"27"}"#));
}

#[test]
fn malformed_or_excessively_nested_wire_documents_are_rejected() {
    for body in ["", "[1,]", r#"{"id":27}false"#, r#"{"x":"\uD800"}"#] {
        assert!(parse_str(body).is_err());
    }
    let body = format!(
        "{}{}",
        "[".repeat(MAX_JSON_DEPTH + 1),
        "]".repeat(MAX_JSON_DEPTH + 1)
    );
    assert!(parse_str(&body).is_err());
}
