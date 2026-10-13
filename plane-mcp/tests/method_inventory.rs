// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STDIO CLIENT LEG AGAINST THE GENERATED METHOD INVENTORY: busbar's `qa/method-inventory.json`
//! (generated from rmcp's own model) at the pin this repo names, read from `BUSBAR_CHECKOUT` (a
//! checkout of GetBusbar/busbar at `.busbar-ref`, which plugin-ci exports). Both tests moved here
//! from `src/client/tests/{verb,peer}_tests.rs`, where they compiled the inventory in from busbar's
//! tree; the plane's source performs no input or output (tests/purity.rs), so the read is here.
//!
//! * `the_issued_set_is_exactly_the_inventory_column`: `UpstreamVerb::all` is the inventory's
//!   `mcp|stdio|client|client` column, in BOTH directions.
//! * `every_server_originated_method_in_the_inventory_is_classified`: every
//!   `mcp|stdio|client|server` method is recognised by the classifier in one of its shapes.

use busbar_plane_mcp::client::peer::{classify, ServerMessage};
use busbar_plane_mcp::client::verb::UpstreamVerb;

/// busbar's `qa/method-inventory.json` at the pin. An unset variable is a failure, never a skip.
fn inventory() -> String {
    let busbar = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the inventory is busbar's qa/method-inventory.json at .busbar-ref \
         (plugin-ci exports it)",
    );
    let path = std::path::PathBuf::from(busbar).join("qa/method-inventory.json");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the inventory {} reads: {e}", path.display()))
}

fn line(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).expect("the fixture is JSON")
}

/// Every `mcp|stdio|client|client|<method>` cell the generated inventory owes an implementation.
///
/// Read from the file rather than restated, for the reason the coverage gate itself gives: a list
/// written from knowledge of the specification is exactly how a list ends at J with nobody noticing.
fn inventory_methods() -> std::collections::BTreeSet<String> {
    let raw = inventory();
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("method-inventory.json parses");
    doc["cells"]
        .as_array()
        .expect("a `cells` array")
        .iter()
        .filter(|c| {
            c["protocol"] == "mcp"
                && c["transport"] == "stdio"
                && c["role"] == "client"
                && c["originator"] == "client"
                && c["na_reason"].is_null()
        })
        .map(|c| c["method"].as_str().expect("a method").to_string())
        .collect()
}

/// THE COLUMN IS COMPLETE, AND IT IS NOT WIDER THAN THE SPECIFICATION.
///
/// Both directions, because each catches a different mistake. A method in the inventory with no
/// variant is a cell busbar cannot serve and would be claiming. A variant with no inventory row is
/// busbar sending an upstream a method the specification does not define, which is not coverage —
/// it is a made-up verb that an upstream will answer `-32601` to.
#[test]
fn the_issued_set_is_exactly_the_inventory_column() {
    let owed = inventory_methods();
    assert!(
        owed.len() >= 20,
        "only {} issuable stdio methods in the inventory. This test refuses to pass vacuously: a \
         filter that matched nothing would report a complete column of nothing.",
        owed.len()
    );
    let built: std::collections::BTreeSet<String> = UpstreamVerb::all()
        .iter()
        .map(|v| v.method().to_string())
        .collect();
    let missing: Vec<&String> = owed.difference(&built).collect();
    let invented: Vec<&String> = built.difference(&owed).collect();
    assert!(
        missing.is_empty(),
        "the inventory owes these methods on the stdio client leg and `UpstreamVerb` has no variant \
         for them: {missing:#?}"
    );
    assert!(
        invented.is_empty(),
        "`UpstreamVerb` sends methods the generated matrix does not define: {invented:#?}\n\
         Do not edit qa/method-inventory.json — it is generated from the SDKs and will come back."
    );
}

/// EVERY server-originated method in the inventory column is classified, and none of them lands in
/// an "unknown" arm.
///
/// Read from the GENERATED matrix for the reason `verb_tests` gives: a list written from knowledge
/// of the specification is how a column silently ends early.
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
        // A NOTIFICATION-SHAPED LINE (no id) and a REQUEST-SHAPED one (with id) are BOTH tried, and
        // exactly one of them must be recognised: `ping` is only ever a request and
        // `notifications/message` is only ever a notification, so requiring both to work would be
        // requiring busbar to accept a shape the specification does not define.
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
