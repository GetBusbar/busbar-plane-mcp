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
            r#"{"s":{"transport":"stdio","command":"/bin/tool","pin":{"mechanism":"unpinned"},"env":{"TOKEN":{"module":"test-secret","settings":{"name":"TOKEN"}}}}}"#,
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

#[test]
fn authored_configuration_profile_uses_actual_raw_tools_and_endpoint_parsers() {
    let document: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let profile = &document["x-busbar-user-configuration"];
    assert_eq!(profile["version"], 1);
    assert_eq!(profile["context"], "raw_user_configuration");
    let schema = serde_json::json!({"$schema":"https://json-schema.org/draft/2020-12/schema","x-busbar-settings-profile":"integer-token-v1","$defs":document["$defs"],"$ref":profile["schema_ref"]});
    let validator = settings_profile::validator(&schema).unwrap();
    for (source, accepted) in [
        (r#"{}"#, true),
        (r#"{"tools":null,"mcp":null}"#, true),
        (
            r#"{"tools":{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"unpinned"},"tools_allow":{"read":{"input_schema":{"type":"object"},"output_schema":{"type":"string"},"task_support":"optional"}},"sampling_bounds":{"max_messages":1}}},"mcp":{"canonical_uri":"https://gateway.example/mcp","authorization_servers":["https://issuer.example"]}}"#,
            true,
        ),
        (
            r#"{"tools":{"s":{"transport":"stdio","command":"/bin/tool","cwd":"/tmp","pin":{"mechanism":"local_program","key":"/bin/tool"},"env":{"TOKEN":{"module":"test-secret","settings":{"name":"TOKEN"}}}}}}"#,
            true,
        ),
        (
            r#"{"tools":{"s":{"transport":"stdio","command":"/bin/tool","pin":{"mechanism":"local_program","key":"/bin/tool"},"env":{"TOKEN":{"module":"test-secret","settings":{"name":"TOKEN"}}}}}}"#,
            false,
        ),
        (
            r#"{"tools":{"s":{"url":"https://server.example/mcp"}}}"#,
            false,
        ),
        (
            r#"{"tools":{"s":{"url":"https://server.example/mcp","pin":{"mechanism":"pinned_pubkey"}}}}"#,
            false,
        ),
        (r#"{"tools":{"pools":{"p":{"members":["s"]}}}}"#, false),
        (
            r#"{"mcp":{"canonical_uri":"https://gateway.example/mcp","authorization_servers":[]}}"#,
            false,
        ),
    ] {
        let value: serde_json::Value = serde_json::from_str(source).unwrap();
        let mut host_dealt = value.clone();
        if let Some(map) = host_dealt.as_object_mut() {
            map.retain(|_, value| !value.is_null());
        }
        let parsed = statement::read_dealt_tools(&serde_json::to_vec(&host_dealt).unwrap());
        assert_eq!(
            parsed.is_ok(),
            accepted,
            "parser: {source}; refusal: {:?}",
            parsed.as_ref().err()
        );
        if value
            .pointer("/tools/s/pin/mechanism")
            .is_some_and(|mode| mode == "local_program")
            && value.pointer("/tools/s/cwd").is_none()
        {
            let reason = parsed
                .as_ref()
                .expect_err("local_program without cwd must be refused");
            assert!(
                reason.contains("needs an explicit absolute `cwd:`"),
                "actual refusal: {reason}"
            );
        }
        assert_eq!(validator.is_valid(&value), accepted, "schema: {source}");
    }
    // `pools` is host-reserved even when its value looks like a valid registration.
    // Standalone plane parsers do not replace the host's reserved-name boundary.
    let reserved: serde_json::Value = serde_json::from_str(r#"{"tools":{"pools":{"url":"https://example.test/endpoint","pin":{"mechanism":"unpinned"}}}}"#).unwrap();
    assert!(
        !validator.is_valid(&reserved),
        "raw authoring must not offer the runtime pool projection as a registration"
    );
    assert!(
        document["$defs"]["section"]["properties"]
            .get("pools")
            .is_some(),
        "existing lifecycle pool projection stays intact"
    );
}
