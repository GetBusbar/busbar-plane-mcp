// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The codec's tests: the fields a body implies.

use super::*;
use serde_json::json;

#[test]
fn the_mirrored_fields_are_what_the_body_states_and_nothing_else() {
    let call = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "fs_read", "_meta": { META_PROTOCOL_VERSION: "2026-07-28" } }
    });
    let fields = mirrored(&call);
    let get = |n: &str| fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    assert_eq!(get(H_MCP_METHOD), Some("tools/call"));
    assert_eq!(get(H_MCP_NAME), Some("fs_read"));
    assert_eq!(get(H_PROTOCOL_VERSION), Some("2026-07-28"));
    assert_eq!(get("accept"), Some("application/json, text/event-stream"));
    // A body that names no version states none: the body defect stays a body defect.
    let bare = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} });
    let fields = mirrored(&bare);
    assert!(fields.iter().all(|(k, _)| k != H_PROTOCOL_VERSION));
    assert!(fields.iter().all(|(k, _)| k != H_MCP_NAME));
    // A request that asked for log records prefers the stream's frames.
    let logged = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": { "_meta": { crate::framing::META_LOGGING_LEVEL: "debug" } }
    });
    assert!(mirrored(&logged)
        .iter()
        .any(|(k, v)| k == "accept" && v.starts_with("text/event-stream")));
}
