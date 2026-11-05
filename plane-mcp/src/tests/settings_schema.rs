use super::*;

#[path = "../../../testing/settings/integer_token.rs"]
mod settings_profile;

#[test]
fn settings_schema_matches_lifecycle_grammar() {
    assert_eq!(STATEMENT.settings_schema.ptr, SETTINGS_SCHEMA.as_ptr());
    assert_eq!(STATEMENT.settings_schema.len, SETTINGS_SCHEMA.len());
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    assert_eq!(
        schema["$defs"]["secret"],
        busbar_contract::secret_ref::oneof_schema()
    );
    let validator = settings_profile::validator(&schema).unwrap();
    for (source, accepted) in [
        (r#"{}"#, true),
        (
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"}}}"#,
            true,
        ),
        (
            r#"{"s":{"transport":"stdio","command":"/bin/tool","pin":{"mechanism":"unpinned"},"env":{"TOKEN":{"env":"TOKEN"}}}}"#,
            true,
        ),
        (
            r#"{"s":{"transport":"stdio","command":"/bin/tool","cwd":"/tmp","pin":{"mechanism":"local_program","key":"/bin/tool"}}}"#,
            true,
        ),
        (
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"tools_allow":{"read_file":{"task_support":"optional","task_ask_caller":[{"confirm":{"method":"elicitation/create","params":{"message":"Continue?"}}}]}},"prompts_allow":{"hello":{"messages":[{"content":{"type":"text","text":"Hello"}}]}},"sampling_bounds":{"max_messages":1}}}"#,
            true,
        ),
        (
            r#"{"pools":{"p":{"members":["s"],"repeatable":["read_file"]}}}"#,
            true,
        ),
        (r#"{"s":{"url":"https://server.example/mcp"}}"#, false),
        (
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"pinned_pubkey"}}}"#,
            false,
        ),
        (
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"mtls"}}}"#,
            false,
        ),
        (
            r#"{"s":{"transport":"stdio","command":"relative","pin":{"mechanism":"unpinned"}}}"#,
            false,
        ),
        (
            r#"{"s":{"url":"https://server.example/mcp","command":"/bin/tool","pin":{"mechanism":"unpinned"}}}"#,
            false,
        ),
        (r#"{"upstream_credentials":"passthrough"}"#, false),
        (
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"sampling_bounds":{"max_messages":0}}}"#,
            false,
        ),
        (
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"tools_allow":{"t":{"ask_caller":[{"x":{"method":"unknown"}}]}}}}"#,
            false,
        ),
        (
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"tools_allow":{"t":{"task_ask_caller":[{"x":{"method":"roots/list"}}]}}}}"#,
            false,
        ),
        (
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"resources_allow":{"file:test":{"text":"a","blob":"Yg=="}}}}"#,
            false,
        ),
        (
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"grants":{"samplng":true}}}"#,
            false,
        ),
        (
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"token_exchange":{"token_url":"https://issuer.example/token","subject_token":{"env":"TOKEN"}}}}"#,
            false,
        ),
        (r#"{"pools":{"p":{"members":[1]}}}"#, false),
    ] {
        let value: serde_json::Value = serde_json::from_str(source).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            statement::read_open(&bytes).is_ok(),
            accepted,
            "lifecycle: {source}"
        );
        assert_eq!(validator.is_valid(&value), accepted, "schema: {source}");
    }
}

#[test]
fn settings_schema_matches_dealt_endpoint_grammar() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let validator = settings_profile::validator(&schema).unwrap();
    for (source, accepted) in [
        (r#"{"tools":null}"#, true),
        (
            r#"{"tools":{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"}}}}"#,
            true,
        ),
        (
            r#"{"mcp":{"canonical_uri":"https://gateway.example/mcp","authorization_servers":["https://issuer.example"]}}"#,
            true,
        ),
        (
            r#"{"tools":{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"typo":true}}}"#,
            false,
        ),
        (
            r#"{"mcp":{"canonical_uri":"https://gateway.example/mcp","authorization_servers":[]}}"#,
            false,
        ),
        (
            r#"{"mcp":{"canonical_uri":"https://gateway.example/other","authorization_servers":["https://issuer.example"]}}"#,
            false,
        ),
        (r#"{"mcp":null}"#, false),
    ] {
        let value: serde_json::Value = serde_json::from_str(source).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            statement::read_dealt_tools(&bytes).is_ok(),
            accepted,
            "lifecycle: {source}"
        );
        assert_eq!(validator.is_valid(&value), accepted, "schema: {source}");
    }
}

#[test]
fn settings_schema_integer_tokens_match_native_parser() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let profile = settings_profile::validator(&schema).unwrap();
    let standard = jsonschema::validator_for(&schema).unwrap();
    assert_eq!(schema["x-busbar-settings-profile"], "integer-token-v1");
    for (pointer, template, integer, kind) in [
        (
            r#"/$defs/server/properties/max_input_required_rounds/anyOf/0"#,
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"max_input_required_rounds":TOKEN}}"#,
            "1",
            "unsigned",
        ),
        (
            r#"/$defs/server/properties/max_caller_ask_rounds/anyOf/0"#,
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"max_caller_ask_rounds":TOKEN}}"#,
            "1",
            "unsigned",
        ),
        (
            r#"/$defs/server/properties/sampling_bounds/properties/max_messages"#,
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"sampling_bounds":{"max_messages":TOKEN}}}"#,
            "1",
            "unsigned",
        ),
        (
            r#"/$defs/server/properties/sampling_bounds/properties/max_prompt_bytes"#,
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"sampling_bounds":{"max_prompt_bytes":TOKEN}}}"#,
            "1",
            "unsigned",
        ),
        (
            r#"/$defs/server/properties/sampling_bounds/properties/max_stop_sequences"#,
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"sampling_bounds":{"max_stop_sequences":TOKEN}}}"#,
            "1",
            "unsigned",
        ),
        (
            r#"/$defs/server/properties/sampling_bounds/properties/max_stop_sequence_bytes"#,
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"sampling_bounds":{"max_stop_sequence_bytes":TOKEN}}}"#,
            "1",
            "unsigned",
        ),
        (
            r#"/$defs/server/properties/sampling_bounds/properties/temperature_min_milli"#,
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"sampling_bounds":{"temperature_min_milli":TOKEN}}}"#,
            "1",
            "unsigned",
        ),
        (
            r#"/$defs/server/properties/sampling_bounds/properties/temperature_max_milli"#,
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"sampling_bounds":{"temperature_max_milli":TOKEN}}}"#,
            "1",
            "unsigned",
        ),
        (
            r#"/$defs/server/properties/sampling_bounds/properties/max_input_response_bytes"#,
            r#"{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"sampling_bounds":{"max_input_response_bytes":TOKEN}}}"#,
            "1",
            "unsigned",
        ),
    ] {
        assert_eq!(
            schema.pointer(pointer).unwrap()["x-busbar-integer-token"],
            kind
        );
        for (token, accepted) in [
            (integer.to_string(), true),
            (format!("{integer}.0"), false),
            (format!("{integer}e0"), false),
            (format!("{integer}E+0"), false),
        ] {
            let text = template.replace("TOKEN", &token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                standard.is_valid(&value),
                "standard mathematical integer: {text}"
            );
            assert_eq!(profile.is_valid(&value), accepted, "profile: {text}");
            assert_eq!(
                statement::read_open(text.as_bytes()).is_ok(),
                accepted,
                "native: {text}"
            );
        }
        // Do not infer signed negative-zero behavior from a regular expression:
        // the profile must agree with the actual lifecycle parser.
        for token in [
            "null",
            "0",
            "-0",
            "-0.0",
            "0e0",
            "-1",
            "18446744073709551616",
        ] {
            let text = template.replace("TOKEN", token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                profile.is_valid(&value),
                statement::read_open(text.as_bytes()).is_ok(),
                "native sign/range: {text}"
            );
        }
    }
}
