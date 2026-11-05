// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STDIO CLIENT LEG AGAINST THE METHOD INVENTORY: `tests/data/method-inventory.json`
//! (generated from rmcp's own model; it moved here from busbar's `qa/`).

use crate::client::peer::{classify, ServerMessage};
use crate::client::verb::UpstreamVerb;

/// The MCP method inventory.
fn inventory() -> String {
    include_str!("../../tests/data/method-inventory.json").to_string()
}

fn line(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).expect("the fixture is JSON")
}

/// Every `mcp|<transport>|client|client|<method>` cell the generated inventory names, over
/// both transports: the methods a client may originate.
fn inventory_methods() -> std::collections::BTreeSet<String> {
    let raw = inventory();
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("method-inventory.json parses");
    doc["cells"]
        .as_array()
        .expect("a `cells` array")
        .iter()
        .filter(|c| {
            c["protocol"] == "mcp"
                && c["role"] == "client"
                && c["originator"] == "client"
                && c["na_reason"].is_null()
        })
        .map(|c| c["method"].as_str().expect("a method").to_string())
        .filter(|m| !m.contains(' '))
        .collect()
}

/// The client-originated methods of the inventory busbar does NOT send an upstream: no
/// production site constructs them.
const NOT_ISSUED: &[&str] = &[
    "completion/complete",
    "logging/setLevel",
    "notifications/cancelled",
    "notifications/elicitation/response",
    "notifications/progress",
    "notifications/roots/list_changed",
    "ping",
    "prompts/get",
    "prompts/list",
    "resources/list",
    "resources/read",
    "resources/subscribe",
    "resources/templates/list",
    "resources/unsubscribe",
    "subscriptions/listen",
    "tasks/cancel",
    "tasks/get",
    "tasks/update",
];

/// The actual upstream verb method set accounts for the inventory column.
#[test]
fn the_issued_method_set_accounts_for_the_inventory() {
    let owed = inventory_methods();
    assert!(
        owed.len() >= 20,
        "only {} client-originated methods in the inventory. This test refuses to pass vacuously: \
         a filter that matched nothing would report a complete column of nothing.",
        owed.len()
    );
    let mut issued = std::collections::BTreeSet::new();
    for verb in UpstreamVerb::all() {
        issued.insert(verb.method().to_string());
    }
    for method in ["tools/call", "tools/list"] {
        issued.insert(method.to_string());
    }
    let invented: Vec<&String> = issued.difference(&owed).collect();
    assert!(
        invented.is_empty(),
        "busbar sends methods the generated matrix does not define: {invented:#?}\n\
         The inventory is the specification's method set; a method it lacks is not owed."
    );
    let not_issued: std::collections::BTreeSet<String> =
        owed.difference(&issued).cloned().collect();
    let named: std::collections::BTreeSet<String> =
        NOT_ISSUED.iter().map(|m| (*m).to_string()).collect();
    assert_eq!(
        not_issued, named,
        "the inventory's client methods busbar does not issue must be exactly the ones named"
    );
}

/// EVERY server-originated method in the inventory column is classified, and none of them
/// lands in an "unknown" arm.
#[test]
fn every_server_originated_method_in_the_inventory_is_classified() {
    let raw = inventory();
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parses");
    let owed: Vec<String> = doc["cells"]
        .as_array()
        .expect("cells")
        .iter()
        .filter(|c| {
            c["protocol"] == "mcp"
                && c["transport"] == "stdio"
                && c["role"] == "client"
                && c["originator"] == "server"
                && c["na_reason"].is_null()
        })
        .map(|c| c["method"].as_str().expect("method").to_string())
        .collect();
    assert!(
        owed.len() >= 12,
        "only {} server-originated stdio cells found; a filter that matched nothing would report \
         complete handling of nothing",
        owed.len()
    );
    for method in &owed {
        let as_notification = classify(&line(&format!(
            r#"{{"jsonrpc":"2.0","method":"{method}","params":{{}}}}"#
        )));
        let as_request = classify(&line(&format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"{method}","params":{{}}}}"#
        )));
        let known_notification = matches!(as_notification, Some(ServerMessage::Notification(_)));
        let known_request = matches!(as_request, Some(ServerMessage::Request { .. }));
        assert!(
            known_notification || known_request,
            "`{method}` is in the matrix as a message a server sends busbar and the classifier \
             recognises neither shape of it: {as_notification:?} / {as_request:?}"
        );
    }
}
