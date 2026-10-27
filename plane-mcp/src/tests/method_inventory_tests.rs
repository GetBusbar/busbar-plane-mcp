// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STDIO CLIENT LEG AGAINST THE GENERATED METHOD INVENTORY: busbar's `qa/method-inventory.json`
//! (generated from rmcp's own model) at the pin this repo names, read from `BUSBAR_CHECKOUT` (a
//! checkout of GetBusbar/busbar at `.busbar-ref`, which plugin-ci exports). Both tests moved here
//! from `src/client/tests/{verb,peer}_tests.rs`, where they compiled the inventory in from busbar's
//! tree; the plane's shipped source performs no input or output (tests/purity.rs), so the read is
//! in this test module (moved in from `tests/` when the crate's only public item became `door`).
//!
//! * `the_issued_set_is_what_production_constructs`: the client-originated methods busbar issues
//!   are counted at their PRODUCTION construction sites in the shipped source (never from the
//!   enum's own list), each is in the inventory's busbar-as-client column, and every method of that
//!   column production does not construct is named, so the column claims nothing the plane does not
//!   send.
//! * `every_server_originated_method_in_the_inventory_is_classified`: every
//!   `mcp|stdio|client|server` method is recognised by the classifier in one of its shapes.

use crate::client::peer::{classify, ServerMessage};
use crate::client::verb::UpstreamVerb;

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

/// Every `mcp|<transport>|client|client|<method>` cell the generated inventory names, over both
/// transports: the methods a client may originate. (The streamable-HTTP column's verb rows,
/// `GET /mcp` and `DELETE /mcp`, are no methods.)
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
                && c["role"] == "client"
                && c["originator"] == "client"
                && c["na_reason"].is_null()
        })
        .map(|c| c["method"].as_str().expect("a method").to_string())
        .filter(|m| !m.contains(' '))
        .collect()
}

/// The client-originated methods of the inventory busbar does NOT send an upstream: no production
/// site constructs them. A method issued and still named here fails, and so does one neither
/// issued nor named.
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
    "server/discover",
    "subscriptions/listen",
    "tasks/cancel",
    "tasks/get",
    "tasks/update",
];

/// The shipped source, every file under `src/` but the test modules: `(path, code)`, its `//`
/// comments stripped so a name in prose is never a construction site.
fn production_source() -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("src reads") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "tests") {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("a source file reads");
                let code: Vec<&str> = text
                    .lines()
                    .map(|l| l.split("//").next().unwrap_or(""))
                    .collect();
                out.push((path.display().to_string(), code.join("\n")));
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut out,
    );
    out
}

/// THE ISSUED SET IS WHAT PRODUCTION CONSTRUCTS, and the inventory column is accounted for.
///
/// A variant of [`UpstreamVerb`] is issued only where the shipped source outside the builder
/// constructs it (`UpstreamVerb::<Variant>`); `tools/call` and `tools/list` are issued where the
/// dispatch and verify paths call their own builders. Every variant must have such a site (a
/// variant no production path builds does not ship), every issued method must be in the inventory
/// (busbar sends no made-up verb), and the inventory's remaining methods must be exactly
/// [`NOT_ISSUED`].
#[test]
fn the_issued_set_is_what_production_constructs() {
    let owed = inventory_methods();
    assert!(
        owed.len() >= 20,
        "only {} client-originated methods in the inventory. This test refuses to pass vacuously: \
         a filter that matched nothing would report a complete column of nothing.",
        owed.len()
    );
    let source = production_source();
    assert!(source.len() >= 20, "the shipped source is read");
    let built_at = |needle: &str| {
        source
            .iter()
            .filter(|(path, code)| {
                !path.ends_with("client/verb.rs")
                    && !path.ends_with("client/jsonrpc.rs")
                    && code.contains(needle)
            })
            .count()
    };
    let mut issued = std::collections::BTreeSet::new();
    for verb in UpstreamVerb::all() {
        let debug = format!("{verb:?}");
        let variant = debug
            .split([' ', '{', '('])
            .next()
            .expect("a variant name")
            .to_string();
        assert!(
            built_at(&format!("UpstreamVerb::{variant}")) > 0,
            "`UpstreamVerb::{variant}` has no production construction site: a verb no production \
             path builds does not ship"
        );
        issued.insert(verb.method().to_string());
    }
    for (method, needle) in [
        ("tools/call", "::tools_call("),
        ("tools/list", "jsonrpc::tools_list("),
    ] {
        assert!(
            built_at(needle) > 0,
            "`{method}` has no production construction site"
        );
        issued.insert(method.to_string());
    }
    let invented: Vec<&String> = issued.difference(&owed).collect();
    assert!(
        invented.is_empty(),
        "busbar sends methods the generated matrix does not define: {invented:#?}\n\
         Do not edit qa/method-inventory.json — it is generated from the SDKs and will come back."
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
