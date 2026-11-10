// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const ORIGINAL: &str = "ui://dashboard/index.html";
const PUBLISHED: &str = "ui://gateway/member/dashboard";

fn config(ui: Value, digest: Option<String>) -> AppsCfg {
    AppsCfg {
        enabled: true,
        resources: BTreeMap::from([(ORIGINAL.into(), ResourcePolicy { digest, ui })]),
        ..AppsCfg::default()
    }
}

fn html(text: &str, ui: Value) -> Value {
    json!({"contents": [{"uri": ORIGINAL, "mimeType": MIME, "text": text,
        "_meta": {"ui": ui, "upstream": "preserved"}}]})
}

#[test]
fn capability_negotiation_intersects_operator_and_session_support() {
    let caps = json!({"extensions": {EXTENSION: {"mimeTypes": [MIME, "image/png", MIME]}}});
    let offered = Profile::parse(Some(&caps)).unwrap();
    let cfg = config(json!({}), None);
    let effective = offered.effective(&cfg);
    assert!(effective.enabled());
    assert_eq!(
        effective.capabilities(),
        json!({"extensions": {EXTENSION: {"mimeTypes": [MIME]}}})
    );
    assert!(!offered.effective(&AppsCfg::default()).enabled());
    assert!(!Profile::parse(None).unwrap().effective(&cfg).enabled());
    assert!(!Profile::parse(Some(&json!({}))).unwrap().enabled());
    let other = json!({"extensions": {EXTENSION: {"mimeTypes": ["image/png"]}}});
    assert_eq!(
        Profile::parse(Some(&other))
            .unwrap()
            .effective(&cfg)
            .capabilities(),
        json!({})
    );
}

#[test]
fn malformed_capabilities_are_rejected() {
    for extension in [
        json!(null),
        json!({}),
        json!({"mimeTypes": null}),
        json!({"mimeTypes": MIME}),
        json!({"mimeTypes": [1]}),
        json!({"mimeTypes": [""]}),
        json!({"mimeTypes": ["x".repeat(129)]}),
        json!({"mimeTypes": vec![MIME; 17]}),
    ] {
        assert!(
            Profile::parse(Some(&json!({"extensions": {EXTENSION: extension}}))).is_err(),
            "{extension}"
        );
    }
}

#[test]
fn visibility_defaults_to_model_and_app_and_app_only_is_hidden() {
    let default = json!({"ui": {"resourceUri": ORIGINAL}});
    assert_eq!(
        tool_meta(Some(&default), false).unwrap().unwrap()["visibility"],
        json!(["app", "model"])
    );
    assert!(model_visible(Some(&default), false));
    assert!(model_visible(None, false));
    assert!(!model_visible(
        Some(&json!({"ui": {"visibility": ["app"]}})),
        false
    ));
    assert!(!model_visible(
        Some(&json!({"ui": {"visibility": []}})),
        false
    ));
    for visibility in [
        json!(null),
        json!("model"),
        json!(["unknown"]),
        json!(["app", "app"]),
        json!([false]),
    ] {
        let meta = json!({"ui": {"visibility": visibility}});
        assert!(tool_meta(Some(&meta), false).is_err());
        assert!(!model_visible(Some(&meta), false));
    }
}

#[test]
fn apps_approval_digest_binds_resource_visibility_and_security_metadata() {
    let schema = json!({"type": "object"});
    let base = json!({"ui": {"resourceUri": ORIGINAL, "visibility": ["model", "app"]}});
    let approved = digest("tool", "description", &schema, Some(&base), false).unwrap();
    for meta in [
        json!({"ui": {"resourceUri": "ui://dashboard/changed.html", "visibility": ["model", "app"]}}),
        json!({"ui": {"resourceUri": ORIGINAL, "visibility": ["app"]}}),
        json!({"ui": {"resourceUri": ORIGINAL, "visibility": ["model", "app"], "csp": {"connectDomains": ["https://api.example"]}}}),
        json!({"ui": {"resourceUri": ORIGINAL, "visibility": ["model", "app"], "permissions": {"camera": {}}}}),
    ] {
        assert_ne!(
            approved,
            digest("tool", "description", &schema, Some(&meta), false).unwrap()
        );
    }
    let legacy = crate::trust::tool_digest("tool", "description", &schema);
    assert_eq!(
        digest("tool", "description", &schema, None, false).unwrap(),
        legacy
    );
    assert_eq!(
        digest(
            "tool",
            "description",
            &schema,
            Some(&json!({"ordinary": "metadata"})),
            false
        )
        .unwrap(),
        legacy
    );
}

#[test]
fn deprecated_resource_metadata_requires_explicit_adapter() {
    let flat = json!({"ui/resourceUri": ORIGINAL});
    assert!(tool_meta(Some(&flat), false).is_err());
    assert_eq!(
        tool_meta(Some(&flat), true).unwrap().unwrap()["resourceUri"],
        ORIGINAL
    );
    assert!(tool_meta(
        Some(&json!({"ui/resourceUri": ORIGINAL, "ui": {"resourceUri": "ui://other/resource"}})),
        true
    )
    .is_err());
}

#[test]
fn resources_preserve_html_bytes_and_blob_encoding_while_rewriting_only_envelope() {
    let text = "<!doctype html>\r\n<script>const uri='ui://dashboard/index.html';</script>雪\n";
    let cfg = config(json!({}), None);
    let mut result = html(text, json!({}));
    resource_result(&mut result, ORIGINAL, PUBLISHED, &cfg).unwrap();
    assert_eq!(
        result["contents"][0]["text"].as_str().unwrap().as_bytes(),
        text.as_bytes()
    );
    assert_eq!(result["contents"][0]["uri"], PUBLISHED);
    assert_eq!(result["contents"][0]["_meta"]["upstream"], "preserved");
    assert_eq!(result["contents"][0]["_meta"]["io.busbar/mutable"], true);
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let mut blob = json!({"contents": [{"uri": ORIGINAL, "mimeType": MIME, "blob": encoded}]});
    resource_result(&mut blob, ORIGINAL, PUBLISHED, &cfg).unwrap();
    assert_eq!(blob["contents"][0]["blob"], encoded);
    assert!(blob["contents"][0].get("text").is_none());
}

#[test]
fn resources_require_one_correct_uri_mime_and_bounded_utf8_payload() {
    let mut cfg = config(json!({}), None);
    cfg.max_resource_bytes = 4;
    let valid = html("html", json!({}));
    let mut malformed = vec![
        json!({}),
        json!({"contents": []}),
        json!({"contents": [valid["contents"][0].clone(), valid["contents"][0].clone()]}),
        html("12345", json!({})),
        html("雪雪", json!({})),
    ];
    for (key, value) in [
        ("mimeType", json!("text/html")),
        ("uri", json!("ui://other/index.html")),
        ("text", json!(null)),
        ("blob", json!("aHRtbA==")),
        ("_meta", json!(false)),
    ] {
        let mut result = valid.clone();
        result["contents"][0][key] = value;
        malformed.push(result);
    }
    for blob in ["!!!", "////", "MTIzNDU="] {
        malformed.push(json!({"contents": [{"uri": ORIGINAL, "mimeType": MIME, "blob": blob}]}));
    }
    for mut result in malformed {
        assert!(
            resource_result(&mut result, ORIGINAL, PUBLISHED, &cfg).is_err(),
            "{result}"
        );
    }
    assert!(resource_result(
        &mut valid.clone(),
        "ui://unapproved/index.html",
        PUBLISHED,
        &cfg
    )
    .is_err());
}

#[test]
fn resource_csp_drift_and_unsafe_security_metadata_are_refused() {
    let approved = json!({"csp": {"connectDomains": ["https://api.example"]}, "permissions": {"clipboardWrite": {}}});
    let cfg = config(approved.clone(), None);
    resource_result(&mut html("html", approved), ORIGINAL, PUBLISHED, &cfg).unwrap();
    for ui in [
        json!({}),
        json!({"csp": {"connectDomains": ["https://evil.example"]}}),
        json!({"csp": {"connectDomains": ["https://*.example"]}}),
        json!({"csp": {"connectDomains": ["http://api.example"]}}),
        json!({"csp": {"scriptSrc": ["https://api.example"]}}),
        json!({"permissions": {"camera": true}}),
        json!({"unknown": true}),
        json!(null),
    ] {
        assert!(resource_result(&mut html("html", ui), ORIGINAL, PUBLISHED, &cfg).is_err());
    }
}

#[test]
fn immutable_resources_pin_decoded_bytes_and_override_mutability_claims() {
    let text = "<html>approved</html>";
    let pin = format!(
        "sha256:{}",
        busbar_contract::redacted::sha256_hex(text.as_bytes())
    );
    let cfg = config(json!({}), Some(pin));
    cfg.validate().unwrap();
    let mut result = html(text, json!({}));
    result["contents"][0]["_meta"]["io.busbar/mutable"] = json!(true);
    resource_result(&mut result, ORIGINAL, PUBLISHED, &cfg).unwrap();
    assert_eq!(result["contents"][0]["_meta"]["io.busbar/mutable"], false);
    assert!(resource_result(
        &mut html("<html>changed</html>", json!({})),
        ORIGINAL,
        PUBLISHED,
        &cfg
    )
    .is_err());
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let mut blob = json!({"contents": [{"uri": ORIGINAL, "mimeType": MIME, "blob": encoded}]});
    resource_result(&mut blob, ORIGINAL, PUBLISHED, &cfg).unwrap();
    assert_eq!(blob["contents"][0]["_meta"]["io.busbar/mutable"], false);
}

#[test]
fn scalar_ui_with_legacy_alias_is_refused_without_indexing_it() {
    for ui in [json!(null), json!(1), json!([]), json!("x")] {
        assert!(tool_meta(Some(&json!({"ui":ui,"ui/resourceUri":ORIGINAL})), true).is_err());
    }
}

#[test]
fn apps_settings_require_explicit_metadata_approval_and_dynamic_resource_policy() {
    let meta = json!({"ui":{"resourceUri":ORIGINAL,"visibility":["app"]}});
    let schema = json!({"type":"object"});
    let hash = digest("refresh", "", &schema, Some(&meta), false).unwrap();
    let cfg = json!({"s":{
        "url":"https://upstream.test/mcp", "pin":{"mechanism":"unpinned"}, "upstream_credentials":"connection",
        "oauth":{"issuer":"https://issuer.test", "resource":"https://upstream.test/mcp", "client_id":"public", "redirect_uri":"https://client.test/cb", "authorization_endpoint":"https://issuer.test/authorize", "token_endpoint":"https://issuer.test/token"},
        "apps":{"enabled":true,"resources":{ORIGINAL:{"ui":{}}}},
        "tools_allow":{"refresh":{"schema_hash":hash,"input_schema":schema,"meta":meta}}
    }});
    assert!(serde_json::from_value::<crate::tools_config::ToolsCfg>(cfg.clone()).is_ok());
    let mut legacy_hash = cfg.clone();
    legacy_hash["s"]["tools_allow"]["refresh"]["schema_hash"] =
        crate::trust::tool_digest("refresh", "", &schema).into();
    assert!(serde_json::from_value::<crate::tools_config::ToolsCfg>(legacy_hash).is_err());
    let mut no_policy = cfg.clone();
    no_policy["s"]["apps"]["resources"] = json!({});
    assert!(serde_json::from_value::<crate::tools_config::ToolsCfg>(no_policy).is_err());
    let mut disabled = cfg;
    disabled["s"]["apps"]["enabled"] = false.into();
    assert!(serde_json::from_value::<crate::tools_config::ToolsCfg>(disabled).is_err());
}

#[test]
fn apps_digest_normalizes_effective_visibility_and_opted_in_legacy_metadata() {
    let schema = json!({});
    let current = json!({"ui":{"resourceUri":ORIGINAL}});
    let explicit = json!({"ui":{"resourceUri":ORIGINAL,"visibility":["app","model"]}});
    let legacy = json!({"ui/resourceUri":ORIGINAL});
    let expected = digest("view", "", &schema, Some(&current), false).unwrap();
    assert_eq!(
        expected,
        digest("view", "", &schema, Some(&explicit), false).unwrap()
    );
    assert_eq!(
        expected,
        digest("view", "", &schema, Some(&legacy), true).unwrap()
    );
    assert!(digest("view", "", &schema, Some(&legacy), false).is_err());
}
