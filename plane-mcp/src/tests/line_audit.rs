// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Audit regressions for the line carrier's meanings.

use serde_json::json;

use super::*;

/// An out-of-band `notifications/elicitation/response` that carries no `params.response` (or a
/// `null` one) is a malformed answer: it fails the ask, so the caller is handed the
/// `input_required` result itself, and the upstream never sees a `null` answer the user never gave.
#[test]
fn an_elicitation_response_without_a_response_fails_the_ask() {
    for params in [
        json!({ "requestId": "busbar:3" }),
        json!({ "requestId": "busbar:3", "response": null }),
    ] {
        let line = json!({
            "jsonrpc": "2.0", "method": "notifications/elicitation/response", "params": params
        });
        assert_eq!(reply(&line), Some(Reply::Failed(3)), "{line}");
    }
    let answered = json!({
        "jsonrpc": "2.0", "method": "notifications/elicitation/response",
        "params": { "requestId": "busbar:3", "response": { "action": "cancel" } }
    });
    assert_eq!(
        reply(&answered),
        Some(Reply::Answered(3, json!({ "action": "cancel" })))
    );
}

/// The `logging/setLevel` refusal is true whatever revision the carrier session negotiated: it
/// never claims the revision has no such method, only that the line carrier does not carry it.
#[test]
fn the_set_level_refusal_does_not_deny_the_session_revision_has_it() {
    let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "logging/setLevel", "params": {} });
    let Era::Answer(refusal) = era(&req) else {
        panic!("logging/setLevel is answered here");
    };
    assert_eq!(refusal["error"]["code"], -32601);
    let message = refusal["error"]["message"].as_str().expect("a message");
    assert!(!message.contains("this revision has no"), "{message}");
    assert!(message.contains("params._meta"), "{message}");
}
