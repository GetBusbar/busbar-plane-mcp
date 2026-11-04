// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Audit regressions for the argument guard's schema expansion: a URL-ish `format` reached through
//! `$ref`, a conditional, `dependentSchemas` or `unevaluatedProperties`, or declared as
//! `iri-reference`, is judged exactly as the same format written inline.

use super::{guard, ArgWhy};
use busbar_contract::abi::host::service::{DEST_ALLOWED, DEST_METADATA};
use serde_json::{json, Value};

/// The cloud-metadata address every case plants.
const METADATA: &str = "169.254.169.254";

/// A judge that knows one metadata host and allows everything else.
fn judge(host: &str) -> Option<u64> {
    if host == METADATA {
        Some(DEST_METADATA)
    } else {
        Some(DEST_ALLOWED)
    }
}

/// The refusal `schema` gives `arguments`, asserting it is the metadata one.
fn refused_as_metadata(schema: &Value, arguments: &Value) -> Option<String> {
    let refusal = guard(schema, arguments, judge).expect_err("the metadata host must be refused");
    assert_eq!(refusal.why, ArgWhy::CloudMetadata(METADATA.to_string()));
    refusal.declared_format
}

#[test]
fn a_hostname_format_behind_a_defs_ref_is_judged() {
    let schema = json!({
        "type": "object",
        "properties": {"target": {"$ref": "#/$defs/Host"}},
        "$defs": {"Host": {"type": "string", "format": "hostname"}}
    });
    let format = refused_as_metadata(&schema, &json!({"target": METADATA}));
    assert_eq!(format.as_deref(), Some("hostname"));

    let scan = guard(&schema, &json!({"target": "example.com"}), judge)
        .expect("a public host behind the same ref is admitted");
    assert_eq!(scan.declared_judged, 1);
}

#[test]
fn draft7_definitions_chains_encoded_pointers_and_anchors_resolve() {
    let schema = json!({
        "type": "object",
        "properties": {
            "chained": {"$ref": "#/definitions/Alias"},
            "encoded": {"$ref": "#/definitions/With%20Space"},
            "anchored": {"$ref": "#host-anchor"},
            "by_id": {"$ref": "urn:example:host#/inner"}
        },
        "definitions": {
            "Alias": {"$ref": "#/definitions/Address"},
            "Address": {"type": "string", "format": "ipv4"},
            "With Space": {"type": "string", "format": "ipv4"},
            "Anchored": {"$anchor": "host-anchor", "format": "hostname"},
            "Resource": {"$id": "urn:example:host", "inner": {"format": "ipv4"}}
        }
    });
    for key in ["chained", "encoded", "anchored", "by_id"] {
        assert!(
            refused_as_metadata(&schema, &json!({key: METADATA})).is_some(),
            "`{key}` must be judged as declared"
        );
    }
}

#[test]
fn a_recursive_ref_to_the_root_is_followed_at_every_depth() {
    let schema = json!({
        "type": "object",
        "properties": {
            "host": {"type": "string", "format": "hostname"},
            "child": {"$ref": "#"}
        }
    });
    let arguments = json!({"child": {"child": {"host": METADATA}}});
    let refusal = guard(&schema, &arguments, judge).expect_err("the nested host must be judged");
    assert_eq!(refusal.pointer, "/child/child/host");
}

#[test]
fn conditional_and_dependent_schema_formats_are_judged() {
    let conditional = json!({
        "type": "object",
        "if": {"properties": {"kind": {"const": "host"}}},
        "then": {"properties": {"target": {"format": "hostname"}}},
        "else": {"properties": {"fallback": {"format": "ipv4"}}}
    });
    refused_as_metadata(&conditional, &json!({"kind": "host", "target": METADATA}));
    refused_as_metadata(&conditional, &json!({"fallback": METADATA}));

    let dependent = json!({
        "type": "object",
        "dependentSchemas": {"mode": {"properties": {"target": {"format": "hostname"}}}}
    });
    refused_as_metadata(&dependent, &json!({"mode": "x", "target": METADATA}));

    let unevaluated = json!({
        "type": "object",
        "properties": {"note": {"type": "string"}},
        "unevaluatedProperties": {"type": "string", "format": "hostname"}
    });
    refused_as_metadata(&unevaluated, &json!({"note": "n", "other": METADATA}));
}

#[test]
fn an_iri_reference_network_path_is_judged_like_a_uri_reference() {
    for format in ["uri-reference", "iri-reference"] {
        let schema = json!({
            "type": "object",
            "properties": {"path": {"type": "string", "format": format}}
        });
        let declared = refused_as_metadata(
            &schema,
            &json!({"path": "//169.254.169.254/latest/meta-data/"}),
        );
        assert_eq!(declared.as_deref(), Some(format));
        guard(&schema, &json!({"path": "relative/path"}), judge)
            .expect("a relative reference names no host and is admitted");
    }
}

#[test]
fn an_unresolvable_ref_refuses_instead_of_hiding_its_declaration() {
    let schema = json!({
        "type": "object",
        "properties": {"target": {"$ref": "https://schemas.example/host.json"}}
    });
    let refusal = guard(&schema, &json!({"target": METADATA}), judge)
        .expect_err("a reference the guard cannot read must not pass the value unjudged");
    assert_eq!(refusal.pointer, "/target");
    assert_eq!(
        refusal.why,
        ArgWhy::SchemaRef("https://schemas.example/host.json".to_string())
    );
    assert!(refusal.to_string().contains("does not resolve"));

    guard(&schema, &json!({"other": "plain text"}), judge)
        .expect("a position the reference does not govern is walked as before");
}

#[test]
fn a_reference_cycle_ends_without_spending_the_budget() {
    let schema = json!({
        "type": "object",
        "properties": {"target": {"$ref": "#/$defs/a"}},
        "$defs": {
            "a": {"$ref": "#/$defs/b"},
            "b": {"$ref": "#/$defs/a", "format": "hostname"}
        }
    });
    let scan = guard(&schema, &json!({"target": "example.com"}), judge)
        .expect("a cycle of references is read once, not refused as too deep");
    assert_eq!(scan.declared_judged, 1);
    refused_as_metadata(&schema, &json!({"target": METADATA}));
}

#[test]
fn schema_and_argument_cross_product_is_bounded_before_judging() {
    let branches: Vec<Value> = (0..2000).map(|_| json!({"type":"object"})).collect();
    let schema = json!({"allOf": branches});
    let args = Value::Array(vec![json!("https://example.com"); 1000]);
    let refusal = guard(&schema, &args, |_| panic!("budget checked first")).unwrap_err();
    assert_eq!(refusal.why, ArgWhy::WorkExceeded);
}

#[test]
fn offending_strings_are_bounded_in_diagnostics() {
    let refusal = guard(&json!({"format":"uri"}), &json!("x".repeat(10_000)), judge).unwrap_err();
    assert!(matches!(&refusal.why, ArgWhy::Scheme(s) if s.len() <= 259));
    assert!(refusal.to_string().len() < 1024);
}

#[test]
fn repeated_destinations_use_one_host_verdict_per_walk() {
    let mut calls = 0;
    let args = json!(["https://example.com/a", "https://example.com/b"]);
    let scan = guard(&Value::Null, &args, |_| {
        calls += 1;
        Some(DEST_ALLOWED)
    })
    .unwrap();
    assert_eq!(scan.undeclared_judged, 2);
    assert_eq!(calls, 1);
}
