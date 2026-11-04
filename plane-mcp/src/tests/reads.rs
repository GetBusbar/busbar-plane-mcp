// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `prompts/get` and `resources/read` answer from the section as the served engine does.

use serde_json::{json, Value};

use super::*;
use crate::tests::everyone;

const SECTION: &[u8] = br#"{
  "fs": {
    "url": "https://mcp.example/fs",
    "pin": {"mechanism": "unpinned"},
    "prompts_allow": {
      "greet": {"description": "Greets.", "template": "Hello {who}<script>x</script> {missing}"},
      "typed": {"messages": [
        {"role": "assistant", "content": {"type": "text", "text": "Hi {who}"}},
        {"content": {"type": "image", "data": "aGk=", "mime_type": "image/png"}}
      ]}
    },
    "resources_allow": {"file:///shared": {"text": "fs copy"}},
    "resource_templates_allow": {"file:///logs/{date}": {"text": "log for {date}", "mime_type": "text/plain"}}
  },
  "db": {
    "url": "https://mcp.example/db",
    "pin": {"mechanism": "unpinned"},
    "resources_allow": {"file:///shared": {"blob": "YmluYXJ5"}},
    "resource_templates_allow": {"file:///logs/{day}": {"text": "db log {day}"}}
  }
}"#;

fn catalogue() -> Catalogue {
    Catalogue::build(
        1,
        &crate::statement::test_support::read_tools_section(SECTION).expect("the section reads"),
    )
}

fn only_fs(kind: &str, name: &str) -> bool {
    (kind == "mcp_server" && name == "fs") || (kind == "mcp_tool" && name.starts_with("fs_"))
}

fn read(bytes: Vec<u8>) -> Value {
    serde_json::from_slice(&bytes).expect("a document")
}

#[test]
fn a_template_substitutes_once_then_normalises_and_keeps_unknown_placeholders() {
    let c = catalogue();
    let params = json!({"name": "fs_greet", "arguments": {"who": "{missing}"}});
    let prompt = prompt_named(&c, &json!(1), Some(&params), &everyone).expect("found");
    let v = read(prompts_get(prompt, &json!(1), Some(&params)).unwrap());
    assert_eq!(v["result"]["resultType"], "complete");
    assert_eq!(v["result"]["description"], "Greets.");
    let text = v["result"]["messages"][0]["content"]["text"]
        .as_str()
        .expect("text");
    assert!(text.starts_with("Hello {missing}"), "{text}");
    assert!(!text.contains("<script>"), "{text}");
    assert_eq!(v["result"]["messages"][0]["role"], "user");
}

#[test]
fn a_typed_prompt_renders_each_message_and_leaves_media_untouched() {
    let c = catalogue();
    let params = json!({"name": "fs_typed", "arguments": {"who": "Ann"}});
    let prompt = prompt_named(&c, &json!(1), Some(&params), &everyone).expect("found");
    let v = read(prompts_get(prompt, &json!(1), Some(&params)).unwrap());
    assert_eq!(
        v["result"]["messages"],
        json!([
            {"role": "assistant", "content": {"type": "text", "text": "Hi Ann"}},
            {"role": "user", "content": {"type": "image", "data": "aGk=", "mimeType": "image/png"}}
        ])
    );
    assert!(v["result"].get("description").is_none());
}

#[test]
fn an_ungranted_prompt_answers_exactly_like_a_nonexistent_one() {
    let c = catalogue();
    let none = |_: &str, _: &str| false;
    let hidden =
        prompt_named(&c, &json!(1), Some(&json!({"name": "fs_greet"})), &none).expect_err("hidden");
    let absent = prompt_named(&c, &json!(1), Some(&json!({"name": "fs_nope"})), &everyone)
        .expect_err("absent");
    assert_eq!((hidden.status, hidden.code), (404, -32602));
    assert_eq!((absent.status, absent.code), (404, -32602));
    assert_eq!(
        hidden.data, absent.data,
        "the refusal carries no grant-only data"
    );
    assert_eq!(
        hidden.message.replace("fs_greet", "fs_nope"),
        absent.message
    );
    assert_eq!(
        hidden.message,
        "`fs_greet` is not a prompt this server exposes."
    );
    let missing = prompt_named(&c, &json!(1), Some(&json!({})), &everyone).expect_err("missing");
    assert_eq!((missing.status, missing.code), (400, -32602));
}

#[test]
fn a_resource_is_read_by_its_own_uri_and_two_reachable_approvals_are_named() {
    let c = catalogue();
    let params = json!({"uri": "file:///shared"});
    let fs = read(resources_read(&c, &json!(1), Some(&params), &only_fs).expect("one"));
    assert_eq!(
        fs["result"]["contents"],
        json!([{"uri": "file:///shared", "text": "fs copy"}])
    );
    assert_eq!(fs["result"]["cacheScope"], "private");
    let both = resources_read(&c, &json!(1), Some(&params), &everyone).expect_err("two");
    assert_eq!((both.status, both.code), (409, -32000));
    assert_eq!(
        both.data,
        Some(json!({"reason": "resource_ambiguous", "candidates": ["db", "fs"]}))
    );
}

#[test]
fn a_template_answers_after_the_concrete_approvals_and_contends_like_one() {
    let c = catalogue();
    let params = json!({"uri": "file:///logs/2026-09-30"});
    let fs = read(resources_read(&c, &json!(1), Some(&params), &only_fs).expect("one"));
    assert_eq!(
        fs["result"]["contents"],
        json!([{"uri": "file:///logs/2026-09-30", "mimeType": "text/plain", "text": "log for 2026-09-30"}])
    );
    let both = resources_read(&c, &json!(1), Some(&params), &everyone).expect_err("two");
    assert_eq!(both.status, 409);
    assert_eq!(
        both.data.expect("data")["candidates"],
        json!(["db_file:///logs/{day}", "fs_file:///logs/{date}"])
    );
}

#[test]
fn nothing_reachable_is_not_found_and_a_missing_uri_is_invalid() {
    let c = catalogue();
    let none = |_: &str, _: &str| false;
    let r = resources_read(
        &c,
        &json!(1),
        Some(&json!({"uri": "file:///shared"})),
        &none,
    )
    .expect_err("hidden");
    assert_eq!((r.status, r.code), (404, -32602));
    assert_eq!(
        r.message,
        "`file:///shared` is not a resource this server exposes."
    );
    let absent = resources_read(
        &c,
        &json!(1),
        Some(&json!({"uri":"file:///absent"})),
        &everyone,
    )
    .expect_err("absent");
    assert_eq!((r.status, r.code), (absent.status, absent.code));
    assert_eq!(
        r.message.replace("file:///shared", "file:///absent"),
        absent.message
    );
    assert_eq!(
        r.data.as_ref().and_then(|d| d.get("uri")),
        Some(&json!("file:///shared"))
    );
    assert_eq!(
        absent.data.as_ref().and_then(|d| d.get("uri")),
        Some(&json!("file:///absent"))
    );
    assert_eq!(
        r.data.as_ref().unwrap().as_object().unwrap().len(),
        absent.data.as_ref().unwrap().as_object().unwrap().len()
    );
    let r = resources_read(&c, &json!(1), None, &everyone).expect_err("missing");
    assert_eq!((r.status, r.code), (400, -32602));
}

/// A binding is non-empty and holds no `/`: one template approves one shape, never a subtree.
#[test]
fn a_template_binds_one_segment_and_never_a_subtree() {
    let t = "file:///t/{id}/data";
    assert_eq!(
        crate::catalogue::match_uri_template(t, "file:///t/7/data").map(|b| b["id"].clone()),
        Some("7".to_string())
    );
    assert_eq!(
        crate::catalogue::match_uri_template(t, "file:///t//data"),
        None
    );
    assert_eq!(
        crate::catalogue::match_uri_template(t, "file:///t/a/b/data"),
        None
    );
    assert_eq!(
        crate::catalogue::match_uri_template(t, "file:///t/7/data/x"),
        None
    );
}

/// A template is substituted once; a bound value spelling another placeholder stays literal.
#[test]
fn a_bound_value_spelling_a_placeholder_is_not_substituted_again() {
    let bindings: std::collections::BTreeMap<String, String> = [
        ("a".to_string(), "{b}".to_string()),
        ("b".to_string(), "x".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        super::substitute("{a}-{b}-{c}-{", &bindings).unwrap(),
        "{b}-x-{c}-{"
    );
}

#[test]
fn prompt_arguments_substitute_inside_literal_json_braces_without_recursing_values() {
    let params = json!({"arguments": {"city": "Paris", "value": "{city}", "number": 3}});
    for (template, expected) in [
        ("{{city}}", "{Paris}"),
        (
            r#"Reply as JSON: {"city": "{city}"}"#,
            r#"Reply as JSON: {"city": "Paris"}"#,
        ),
        ("{value} {missing} {number}", "{city} {missing} {number}"),
    ] {
        assert_eq!(
            substitute_arguments(template, Some(&params)).unwrap(),
            expected
        );
    }
}

#[test]
fn absent_and_ungranted_resources_use_current_invalid_params_and_echo_only_requested_uri() {
    let c = catalogue();
    for uri in ["file:///missing", "file:///shared"] {
        let refused = resources_read(&c, &json!(7), Some(&json!({"uri": uri})), &|_, _| false)
            .expect_err("not exposed");
        assert_eq!((refused.status, refused.code), (404, -32602));
        assert_eq!(refused.data, Some(json!({"uri": uri})));

        assert_eq!(
            crate::adapt::lower_answer(&refused.body()),
            Some(crate::adapt::Lowered::Unchanged),
        );
    }
}

#[test]
fn hidden_and_absent_resource_answers_are_identical_for_the_same_requested_uri() {
    let populated = catalogue();
    let empty = Catalogue::build(
        1,
        &crate::statement::test_support::read_tools_section(b"{}").expect("empty section"),
    );
    let params = json!({"uri": "file:///shared"});
    let hidden =
        resources_read(&populated, &json!(7), Some(&params), &|_, _| false).expect_err("hidden");
    let absent = resources_read(&empty, &json!(7), Some(&params), &everyone).expect_err("absent");
    assert_eq!(hidden.status, absent.status);
    assert_eq!(hidden.body(), absent.body());
    assert_eq!(read(hidden.body())["error"]["data"], params);
}

#[test]
fn caller_substitution_is_bounded_before_amplification() {
    let params = json!({"arguments":{"x":"x".repeat(MAX_RENDER_BYTES / 2 + 1)}});
    assert!(substitute_arguments("{x}{x}", Some(&params)).is_err());
    assert_eq!(
        substitute_arguments("{x}", Some(&json!({"arguments":{"x":"ok"}}))).unwrap(),
        "ok"
    );
}

#[test]
fn unknown_prompt_is_invalid_params_and_oversized_selectors_are_not_echoed() {
    let c = catalogue();
    let refusal =
        prompt_named(&c, &json!(1), Some(&json!({"name":"missing"})), &everyone).unwrap_err();
    assert_eq!(read(refusal.body())["error"]["code"], CODE_INVALID_PARAMS);
    let long = "x".repeat(MAX_READ_SELECTOR_BYTES + 1);
    let refusal = prompt_named(&c, &json!(1), Some(&json!({"name":long})), &everyone).unwrap_err();
    assert!(refusal.body().len() < 1024);
    let refusal = resources_read(&c, &json!(1), Some(&json!({"uri":long})), &everyone).unwrap_err();
    assert!(refusal.body().len() < 1024);
}
