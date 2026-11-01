use super::*;

#[test]
fn a_present_arguments_member_must_be_an_object_before_any_ask() {
    for arguments in [
        json!(null),
        json!("wrong"),
        json!([1]),
        json!(true),
        json!(7),
    ] {
        let mut asked = false;
        let admission = admit_call(
            &catalogue(),
            &json!(4),
            Some(&params("fs_read_file", arguments)),
            &no_header,
            &everyone,
            &mut |_, _| {
                asked = true;
                crate::ask::AskDecision::Proceed
            },
        );
        let (refusal, _) = refused(admission);
        assert_eq!(
            (refusal.status, refusal.code),
            (400, crate::codec::CODE_INVALID_PARAMS)
        );
        assert!(refusal.message.contains("arguments"));
        assert!(
            !asked,
            "invalid arguments never reach the confirmation or upstream path"
        );
    }
    let admission = admit_call(
        &catalogue(),
        &json!(4),
        Some(&json!({"name":"fs_read_file"})),
        &no_header,
        &everyone,
        &mut proceed,
    );
    assert_eq!(go(admission).arguments, json!({}));
}

#[test]
fn malformed_sampling_fields_are_not_measured_as_empty() {
    for params in [
        json!(null),
        json!({"messages":"large"}),
        json!({"messages":["large"]}),
        json!({"systemPrompt":{"text":"large"}}),
        json!({"stopSequences":"large"}),
        json!({"stopSequences":[{"text":"large"}]}),
    ] {
        let request = json!({"method":"sampling/createMessage","params":params});
        assert!(
            matches!(
                judge_sampling_bounds("fs", &SamplingBoundsCfg::default(), [&request]),
                Err(AskRefusal::Malformed { .. })
            ),
            "{request}"
        );
    }
    let valid = json!({"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"systemPrompt":"hello","stopSequences":["stop"]}});
    assert!(judge_sampling_bounds("fs", &SamplingBoundsCfg::default(), [&valid]).is_ok());
}

#[test]
fn a_streams_correlated_response_survives_later_notifications_and_other_ids() {
    let admitted = admitted();
    for suffix in [
        r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"later"}}"#,
        r#"{"jsonrpc":"2.0","id":99,"result":{"other":true}}"#,
    ] {
        let response =
            r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"ours"}]}}"#;
        let stream = format!("data: {response}\r\n\r\ndata: {suffix}\r\n\r\n");
        let (_, body, line) = answer_of(settle_call(
            &admitted,
            None,
            200,
            stream.as_bytes(),
            true,
            0,
        ));
        assert_eq!(body["result"]["content"][0]["text"], "ours");
        assert!(line.reason.is_empty(), "{line:?}");
    }
}

#[test]
fn an_http_target_never_carries_the_url_fragment() {
    for (url, target) in [
        ("https://up.example/mcp?x=1#private", "/mcp?x=1"),
        ("https://up.example#private", "/"),
        ("https://up.example?x=1#private", "/?x=1"),
    ] {
        assert_eq!(path_of(url), target);
    }
}

#[test]
fn a_resolved_distrust_keeps_its_server_and_digest_in_the_call_log() {
    for code in [DISTRUST_UNKNOWN_ITEM, DISTRUST_NOT_APPROVED] {
        let params = params("fs_read_file", json!({}));
        let (_, line) = refused(admit_trusted(
            &catalogue(),
            &json!(4),
            Some(&params),
            &no_header,
            &everyone,
            &mut |_| Trust::Verdict(code),
            &mut proceed,
        ));
        let line = line.expect("the refusal is logged");
        assert_eq!(line.server, "fs");
        assert_eq!(line.tool_digest, "sha256:aa");
    }
}

#[test]
fn invalid_custom_header_suffixes_are_refused_before_any_header_is_emitted() {
    let mut entry = catalogue().tool("fs_read_file").unwrap().clone();
    for suffix in ["", "bad name", "bad:header", "a\r\nX-Injected: 1"] {
        entry.input_schema = Some(json!({"properties":{"value":{"x-mcp-header":suffix}}}));
        assert!(
            custom_param_mismatch(&entry, &json!({"value":"text"}), &|_| Some("text".into()))
                .is_some()
        );
        assert!(crate::adapt::param_mirror(
            entry.input_schema.as_ref(),
            Some(&json!({"value":"text"}))
        )
        .is_empty());
    }
    entry.input_schema =
        Some(json!({"properties":{"a":{"x-mcp-header":"Same"},"b":{"x-mcp-header":"same"}}}));
    assert!(
        custom_param_mismatch(&entry, &json!({"a":"text","b":"text"}), &|_| Some(
            "text".into()
        ))
        .is_some()
    );
    entry.input_schema = Some(json!({"properties":{"value":{"x-mcp-header":"Route"}}}));
    assert!(
        custom_param_mismatch(&entry, &json!({"value":"text"}), &|_| Some("text".into())).is_none()
    );
    assert_eq!(
        crate::adapt::param_mirror(entry.input_schema.as_ref(), Some(&json!({"value":"text"}))),
        vec![("mcp-param-route".into(), "text".into())]
    );
}
