// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{guard, public, ArgWhy};
use serde_json::json;

#[test]
fn pattern_declared_hosts_and_network_references_reach_the_destination_judge() {
    for (format, refused, accepted) in [
        ("hostname", "169.254.169.254", "api.example.com"),
        (
            "uri-reference",
            "//169.254.169.254/x",
            "//api.example.com/x",
        ),
    ] {
        let schema = json!({
            "type": "object",
            "patternProperties": {"^target_": {"type": "string", "format": format}}
        });
        let error = guard(&schema, &json!({"target_a": refused}), public())
            .expect_err("a standard property pattern must not hide a declared destination");
        assert_eq!(error.pointer, "/target_a");
        assert_eq!(error.declared_format.as_deref(), Some(format));
        assert_eq!(error.why, ArgWhy::CloudMetadata("169.254.169.254".into()));
        let scan = guard(&schema, &json!({"target_a": accepted}), public())
            .expect("the same field still admits public destinations");
        assert_eq!(scan.declared_judged, 1);
        assert_eq!(scan.undeclared_judged, 0);
        assert_eq!(scan.strings_seen, 1);
    }
}

#[test]
fn property_patterns_use_unanchored_ecma_matching_with_lookaround_and_backreferences() {
    for (pattern, key) in [
        ("target", "prefix_target_suffix"),
        (r"target(?=_)", "target_host"),
        (r"(?<=target_)host$", "target_host"),
        (r"^(target)_\1$", "target_target"),
        (r"^target\u005f", "target_host"),
    ] {
        let schema = json!({"patternProperties": {pattern: {"format": "hostname"}}});
        let error = guard(&schema, &json!({key: "169.254.169.254"}), public())
            .expect_err("the JSON Schema pattern applies to this property name");
        assert_eq!(error.pointer, format!("/{key}"));
        assert_eq!(error.why, ArgWhy::CloudMetadata("169.254.169.254".into()));
    }
}

#[test]
fn ecma_character_classes_do_not_turn_nonmatching_names_into_host_fields() {
    for (pattern, key) in [(r"^\d+$", "١"), (r"^\w+$", "café")] {
        let schema = json!({"patternProperties": {pattern: {"format": "hostname"}}});
        let scan = guard(&schema, &json!({key: "169.254.169.254"}), public())
            .expect("ECMA digit and word classes do not have Rust regex's Unicode expansion");
        assert_eq!(scan.declared_judged, 0);
        assert_eq!(scan.undeclared_judged, 0);
        assert_eq!(scan.strings_seen, 1);
    }
}

#[test]
fn every_overlapping_pattern_and_named_property_keeps_its_declared_format() {
    for schema in [
        json!({
            "properties": {"target_host": {"format": "uri-reference"}},
            "patternProperties": {"^target_": {"format": "hostname"}}
        }),
        json!({"patternProperties": {
            ".*": {"format": "uri-reference"},
            "^target_": {"format": "hostname"}
        }}),
    ] {
        let error = guard(
            &schema,
            &json!({"target_host": "169.254.169.254"}),
            public(),
        )
        .expect_err("a reference declaration must not mask the overlapping host declaration");
        assert_eq!(error.declared_format.as_deref(), Some("hostname"));
        assert_eq!(error.why, ArgWhy::CloudMetadata("169.254.169.254".into()));
        let scan = guard(
            &schema,
            &json!({"target_host": "api.example.com"}),
            public(),
        )
        .expect("a public hostname also remains a valid relative reference");
        assert_eq!(
            scan.declared_judged, 1,
            "one string, despite two declarations"
        );
        assert_eq!(scan.strings_seen, 1);
    }
}

#[test]
fn additional_properties_apply_only_after_named_and_pattern_properties_miss() {
    let schema = json!({
        "properties": {"note": {"type": "string"}},
        "patternProperties": {"^note_": {"type": "string"}},
        "additionalProperties": {"format": "hostname"}
    });
    let scan = guard(
        &schema,
        &json!({"note": "169.254.169.254", "note_other": "169.254.169.254"}),
        public(),
    )
    .expect("covered free-text fields do not inherit the additionalProperties host format");
    assert_eq!(scan.strings_seen, 2);
    assert_eq!(scan.declared_judged, 0);
    let error = guard(&schema, &json!({"other": "169.254.169.254"}), public())
        .expect_err("an unmatched property still receives additionalProperties");
    assert_eq!(error.pointer, "/other");
    assert_eq!(error.why, ArgWhy::CloudMetadata("169.254.169.254".into()));
}

#[test]
fn patterns_keep_nested_schemas_and_pointer_escaping() {
    let schema = json!({"patternProperties": {"^delivery/": {
        "properties": {"host": {"format": "hostname"}}
    }}});
    let error = guard(
        &schema,
        &json!({"delivery/~": {"host": "169.254.169.254"}}),
        public(),
    )
    .expect_err("a pattern-selected nested schema is carried into the value walk");
    assert_eq!(error.pointer, "/delivery~1~0/host");
    assert_eq!(error.why, ArgWhy::CloudMetadata("169.254.169.254".into()));
}

#[test]
fn nonmatching_patterns_preserve_ordinary_strings_and_undeclared_url_detection() {
    let schema = json!({"patternProperties": {"^target_": {"format": "hostname"}}});
    let scan = guard(&schema, &json!({"note": "169.254.169.254"}), public())
        .expect("a bare host in an undeclared free-text field remains ordinary text");
    assert_eq!(scan.declared_judged, 0);
    assert_eq!(scan.undeclared_judged, 0);
    let error = guard(
        &schema,
        &json!({"note": "http://169.254.169.254/x"}),
        public(),
    )
    .expect_err("whole undeclared URLs still reach the existing destination guard");
    assert_eq!(error.declared_format, None);
    assert_eq!(error.why, ArgWhy::CloudMetadata("169.254.169.254".into()));
}

#[test]
fn an_unreadable_property_pattern_is_refused_instead_of_treated_as_a_nonmatch() {
    let schema = json!({"patternProperties": {"(": {"format": "hostname"}}});
    let error = guard(&schema, &json!({"target": "169.254.169.254"}), public())
        .expect_err("an unreadable pattern cannot prove the destination is undeclared");
    assert_eq!(error.pointer, "/target");
    assert!(error.to_string().contains("patternProperties"));
}
