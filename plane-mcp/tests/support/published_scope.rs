// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const ALIAS: &str = "approved_reader";

fn configured() -> String {
    st_section(json!({}), {
        let mut def = exchanged();
        def["tools_allow"] = json!({
            "read_file": {"schema_hash": "sha256:aa", "publish_as": ALIAS},
            "write_file": {"schema_hash": "sha256:bb"},
            "draft": {"publish_as": "hidden_draft"},
            "empty": {"schema_hash": "  ", "publish_as": "hidden_empty"}
        });
        def
    })
}

fn scoped_call(d: &Door, unit: u64, name: &str) -> Answered {
    let mut body: Value = serde_json::from_slice(ST_CALL).unwrap();
    body["params"]["name"] = json!(name);
    let body = serde_json::to_vec(&body).unwrap();
    let fields = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", name),
    ];
    assert_eq!(
        d.arrive(unit, "POST", "/mcp", &body, &fields).outcome,
        Outcome::Ready
    );
    d.piece(unit, &Given::attempt(ALICE, "st"));
    d.pump(unit, &Given::caller(ALICE, &body))
}

fn fetch_scopes() -> Vec<String> {
    seen()
        .iter()
        .filter(|request| request.url == STATELESS_URL && request.body["method"] == "tools/list")
        .map(|request| {
            field_of(
                &request.fields,
                busbar_contract::abi::auth::SCOPE_REQUEST_FIELD,
            )
            .expect("the registration's token exchange carries its derived scope")
            .to_string()
        })
        .collect()
}

#[test]
fn an_operator_fetch_scopes_only_approved_published_names() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(&configured());
    let result = d.connect(880, "st");
    assert_eq!(
        result.status,
        200,
        "{}",
        String::from_utf8_lossy(&result.body)
    );
    assert_eq!(fetch_scopes(), ["approved_reader st_write_file"],
        "an alias replaces the original spelling, defaults remain canonical, and pending approvals grant no fetch scope");
}

#[test]
fn an_admitted_alias_call_uses_the_alias_for_both_fetch_and_member_scope() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let _book = BookOn::on();
    let d = open_with(&configured());
    let sent = scoped_call(&d, 881, ALIAS);
    assert!(
        sent.far,
        "the approved published alias is admitted: {}",
        sent.text()
    );
    assert_eq!(
        sent.field(busbar_contract::abi::auth::SCOPE_REQUEST_FIELD),
        Some(ALIAS),
        "a wildcard grant narrows the real member send to the alias actually called"
    );
    assert_eq!(fetch_scopes(), ["approved_reader st_write_file"]);
    for (unit, hidden) in [
        (882, "st_read_file"),
        (883, "hidden_draft"),
        (884, "hidden_empty"),
    ] {
        let refused = scoped_call(&d, unit, hidden);
        assert!(
            !refused.far,
            "{hidden} must not become callable beside the approved alias"
        );
    }
    assert!(fetch_scopes()
        .iter()
        .all(|scope| scope == "approved_reader st_write_file"));
}

#[test]
fn a_default_published_name_keeps_its_existing_fetch_and_member_scope() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let _book = BookOn::on();
    let mut def = exchanged();
    def["tools_allow"] = json!({"read_file": {"schema_hash": "sha256:aa"}});
    let d = open_with(&st_section(json!({}), def));
    let sent = scoped_call(&d, 885, "st_read_file");
    assert!(sent.far, "{}", sent.text());
    assert_eq!(
        sent.field(busbar_contract::abi::auth::SCOPE_REQUEST_FIELD),
        Some("st_read_file")
    );
    assert_eq!(fetch_scopes(), ["st_read_file"]);
}
