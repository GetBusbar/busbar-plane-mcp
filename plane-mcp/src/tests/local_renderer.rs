// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};

use super::{normalise_spans, Local, RopeCursor, Span};
use crate::plane_door::Held;
use crate::revision::Revision;

fn normalised(sources: &[&str], sequence: &[usize]) -> String {
    let pieces: Vec<_> = sequence
        .iter()
        .map(|&source| Span {
            source,
            start: 0,
            end: sources[source].len(),
        })
        .collect();
    let ropes = normalise_spans(
        &pieces,
        &vec![true; sources.len()],
        &mut HashMap::new(),
        &|index| sources[index],
    )
    .expect("physical source spans fit");
    let mut bytes = Vec::new();
    for rope in ropes {
        let mut cursor = RopeCursor::new(rope, false);
        while let Some(span) = cursor.load() {
            bytes.extend_from_slice(&sources[span.source].as_bytes()[span.start..span.end]);
            cursor.advance(span.len());
        }
    }
    String::from_utf8(bytes).expect("normalisation preserves UTF-8")
}

#[test]
fn all_short_bracket_inputs_match_the_existing_global_normaliser_at_every_seam() {
    const ALPHABET: [&str; 6] = ["<", ">", "/", "a", " ", "é"];
    for length in 0..=5 {
        for value in 0..ALPHABET.len().pow(length) {
            let mut rest = value;
            let mut input = String::new();
            for _ in 0..length {
                input.push_str(ALPHABET[rest % ALPHABET.len()]);
                rest /= ALPHABET.len();
            }
            let expected = crate::sanitize::normalise(&input);
            assert_eq!(normalised(&[&input], &[0]), expected, "{input:?}");
            for seam in input
                .char_indices()
                .map(|(at, _)| at)
                .chain(std::iter::once(input.len()))
            {
                let (left, right) = input.split_at(seam);
                assert_eq!(
                    normalised(&[left, right], &[0, 1]),
                    expected,
                    "{left:?} + {right:?}"
                );
            }
        }
    }
}

#[test]
fn repeated_binary_opener_patterns_and_tag_delimiters_match_whole_string_normalisation() {
    for argument in [
        "</<<//</<<a>a>",
        "<<<a>a>a>",
        "a</<b>",
        "/name>body</x>",
        "<b>text",
        "<<a>中文a>😀",
        "<script without a delimiter",
        "<</<a>/a>a>",
    ] {
        let prefix = "<<";
        let suffix = "a>a>末尾<system";
        let mut sequence = vec![0];
        sequence.extend(std::iter::repeat_n(1, 37));
        sequence.push(2);
        let expanded = format!("{prefix}{}{suffix}", argument.repeat(37));
        assert_eq!(
            normalised(&[prefix, argument, suffix], &sequence),
            crate::sanitize::normalise(&expanded),
            "{argument:?}"
        );
    }
    for pieces in [
        ["<a", "<b>text", ">"],
        ["<", "/", "name>"],
        ["</", "<a>", "name>"],
        ["<<<a>", "a>", "a>"],
        ["<a", "<b>c>", ""],
    ] {
        assert_eq!(
            normalised(&pieces, &[0, 1, 2]),
            crate::sanitize::normalise(&pieces.concat())
        );
    }
}

#[test]
fn leading_slash_extends_only_an_incoming_bare_opener_across_every_source_seam() {
    for input in [
        "<<a>/<a>b>",
        "<<a>/<b>name>",
        "</<a>/<b>name>",
        "<<a>//<b>name>",
        "<<a>/ <b>name>",
        "<<a>/<<b>name>tail>",
        "<<a>/</<b>name>tail>",
        "<<<a>/<b>/name>tail>",
    ] {
        let expected = crate::sanitize::normalise(input);
        assert_eq!(normalised(&[input], &[0]), expected, "{input:?}");
        for first in 0..=input.len() {
            for second in first..=input.len() {
                let pieces = [&input[..first], &input[first..second], &input[second..]];
                assert_eq!(normalised(&pieces, &[0, 1, 2]), expected, "{pieces:?}");
            }
        }
    }
    assert_eq!(normalised(&["<<a>/<a>b>"], &[0]), "");
    let mut prefixes = vec![String::new()];
    for length in 0..=4 {
        for bits in 0..(1usize << length) {
            let mut prefix = String::new();
            for bit in 0..length {
                prefix.push_str(if bits & (1 << bit) == 0 { "<" } else { "</" });
            }
            prefix.push_str("<a>");
            prefixes.push(prefix);
        }
    }
    for fragment in [
        "/<a>b>",
        "/<b>name>",
        "/<b>",
        "/</<b>name>",
        "//<a>b>",
        "/ <a>b>",
    ] {
        for prefix in &prefixes {
            let mut sequence = vec![0];
            sequence.extend(std::iter::repeat_n(1, 29));
            sequence.push(2);
            let expanded = format!("{prefix}{}name>", fragment.repeat(29));
            assert_eq!(
                normalised(&[prefix.as_str(), fragment, "name>"], &sequence),
                crate::sanitize::normalise(&expanded),
                "{prefix:?} + repeated {fragment:?}"
            );
        }
    }
}

#[test]
fn deep_reconstitution_and_its_source_summary_drop_use_no_recursive_demand_chain() {
    let depth = super::MAX_NORMALISE_OPERATIONS - 1;
    let input = format!("{}a{}", "<".repeat(depth), ">a".repeat(depth));
    assert_eq!(
        normalised(&[&input], &[0]),
        crate::sanitize::normalise(&input)
    );
}

fn held(section: Value) -> Arc<Held> {
    let bytes = serde_json::to_vec(&section).expect("section JSON");
    Arc::new(Held::of(
        7,
        crate::statement::test_support::read_tools_section(&bytes).expect("section reads"),
    ))
}

fn collect(mut local: Local, room: usize) -> Vec<u8> {
    let expected_len = local.len();
    let mut result = Vec::new();
    let mut output = vec![0; room];
    while !local.done() {
        assert_eq!(local.write(&mut []), 0);
        let written = local.write(&mut output);
        assert!(written != 0 || local.done());
        result.extend_from_slice(&output[..written]);
    }
    assert_eq!(result.len(), expected_len);
    assert_eq!(local.write(&mut output), 0);
    result
}

fn legacy(bytes: Vec<u8>, session: bool) -> Vec<u8> {
    if !session {
        return bytes;
    }
    match crate::adapt::lower_answer(&bytes).expect("complete JSON") {
        crate::adapt::Lowered::Spliced(bytes) => bytes,
        crate::adapt::Lowered::Unchanged => bytes,
        crate::adapt::Lowered::Inexpressible => panic!("local reads are complete"),
    }
}

#[test]
fn every_prompt_content_form_and_legacy_schema_match_the_old_api_byte_for_byte() {
    let held = held(json!({"s": {
        "url":"https://mcp.example/s", "pin":{"mechanism":"unpinned"},
        "prompts_allow": {
            "plain":{"description":"<<b>b>中文", "template":"{{a}} {a}{b} {unknown} {number} {empty}"},
            "typed":{"messages":[
                {"role":"assistant","content":{"type":"text","text":"<a{a}>{b}"}},
                {"content":{"type":"image","data":"YQ==","mime_type":"image/png"}},
                {"content":{"type":"audio","data":"Yg==","mime_type":"audio/wav"}},
                {"content":{"type":"resource","resource":{"uri":"urn:{a}","mime_type":"text/plain","text":"{a}{b}"}}},
                {"content":{"type":"resource","resource":{"uri":"urn:blob","blob":"Yw=="}}}
            ]}
        }
    }}));
    let controls: String = (0..=31u8)
        .map(char::from)
        .chain("\"\\é中文😀".chars())
        .collect();
    for name in ["s_plain", "s_typed"] {
        for (a, b) in [
            ("<a", "<b>c>"),
            ("<<<a>", "a>a>"),
            ("{b}", controls.as_str()),
            ("</</", "<a>a>a>"),
            ("<<a>/", "<a>b>"),
            ("<<a>/", "<b>name>"),
            ("</<a>/", "<b>name>"),
            ("<<a>//", "<b>name>"),
            ("<<a>/ ", "<b>name>"),
            ("<b>text", ""),
        ] {
            let params = json!({"name":name, "arguments":{"a":a,"b":b,"number":"3","empty":""}});
            let id = json!("quote\"\\\n中文");
            let prompt =
                crate::reads::prompt_named(&held.catalogue, &id, Some(&params), &|_, _| true)
                    .expect("prompt");
            let expected = crate::reads::prompts_get(prompt, &id, Some(&params)).unwrap();
            for session in [false, true] {
                for room in [1, 2, 7, 257] {
                    let local = Local::prompt(
                        held.clone(),
                        name.to_string(),
                        id.clone(),
                        Some(params.clone()),
                        if session {
                            Revision::R2025_11_25
                        } else {
                            Revision::R2026_07_28
                        },
                    )
                    .expect("local prompt");
                    assert_eq!(
                        collect(local, room),
                        legacy(expected.clone(), session),
                        "{name}, {a:?}, {b:?}, legacy={session}, room={room}"
                    );
                }
            }
        }
    }
}

#[test]
fn concrete_and_template_resources_and_refusals_match_the_old_api() {
    let held = held(json!({"s": {
        "url":"https://mcp.example/s", "pin":{"mechanism":"unpinned"},
        "resources_allow": {
            "urn:text":{"text":"<<a>a>中文\n", "mime_type":"text/plain"},
            "urn:blob":{"blob":"YQ==", "mime_type":"application/octet-stream"}
        },
        "resource_templates_allow":{"urn:example:{a}:{b}":{"text":"{a}{b} {missing}","mime_type":"text/plain"}}
    }, "other": {
        "url":"https://mcp.example/other", "pin":{"mechanism":"unpinned"},
        "resources_allow":{"urn:blob":{"text":"another"}}
    }}));
    for uri in [
        "urn:text",
        "urn:blob",
        "urn:example:{b}:x",
        "urn:example:<<<a>:a>a>",
        "urn:missing",
    ] {
        let params = json!({"uri":uri});
        for grant_all in [false, true] {
            let admit = |kind: &str, name: &str| grant_all || kind != "mcp_server" || name == "s";
            let old =
                crate::reads::resources_read(&held.catalogue, &json!(9), Some(&params), &admit);
            for session in [false, true] {
                let new = Local::resource(
                    held.clone(),
                    json!(9),
                    Some(params.clone()),
                    &admit,
                    if session {
                        Revision::R2025_11_25
                    } else {
                        Revision::R2026_07_28
                    },
                );
                match (&old, new) {
                    (Ok(bytes), Ok(local)) => {
                        assert_eq!(collect(local, 1), legacy(bytes.clone(), session))
                    }
                    (Err(old), Err(new)) => {
                        assert_eq!(new.status, old.status);
                        let mut expected: Value = serde_json::from_slice(&old.body()).unwrap();
                        if session && new.status == 404 {
                            expected["error"]["code"] = json!(-32002);
                        }
                        assert_eq!(
                            serde_json::from_slice::<Value>(&new.body()).unwrap(),
                            expected
                        );
                    }
                    _ => panic!("resource lookup outcomes differ for {uri}"),
                }
            }
        }
    }
    for params in [None, Some(json!({})), Some(json!({"uri":1}))] {
        let old =
            crate::reads::resources_read(&held.catalogue, &json!(9), params.as_ref(), &|_, _| true)
                .expect_err("invalid URI");
        let Err(new) = Local::resource(
            held.clone(),
            json!(9),
            params,
            &|_, _| true,
            Revision::R2026_07_28,
        ) else {
            panic!("invalid URI accepted")
        };
        assert_eq!(old.status, new.status);
        assert_eq!(old.body(), new.body());
    }
}

#[test]
fn replay_and_abandonment_keep_the_original_arguments_and_generation_until_last_cursor_drops() {
    let held = held(json!({"s": {
        "url":"https://mcp.example/s", "pin":{"mechanism":"unpinned"},
        "prompts_allow":{"p":{"template":"{value}".repeat(128)}}
    }}));
    let params = json!({"name":"s_p", "arguments":{"value":"中文\n".repeat(1024)}});
    let allocation = params["arguments"]["value"]
        .as_str()
        .expect("original argument")
        .as_ptr();
    let generation = Arc::downgrade(&held);
    let mut local = Local::prompt(
        held.clone(),
        "s_p".to_string(),
        json!(4),
        Some(params),
        Revision::R2026_07_28,
    )
    .expect("local prompt");
    assert!(local
        .input
        .arguments
        .iter()
        .any(|value| value.as_ptr() == allocation));
    let original = Arc::downgrade(&local.input);
    assert!(local.input.params.is_none());
    drop(held);
    let mut output = [0u8; 11];
    assert_eq!(local.write(&mut output), output.len());
    assert!(!local.done());
    let replay = local.fresh_clone();
    let expected = collect(replay.fresh_clone(), 113);
    let mut resumed = local.clone();
    resumed.rewind();
    assert_eq!(collect(resumed, 1), expected);
    drop(local);
    assert!(original.upgrade().is_some());
    assert!(generation.upgrade().is_some());
    assert_eq!(collect(replay, 7), expected);
    assert!(original.upgrade().is_none());
    assert!(generation.upgrade().is_none());
}

impl Local {
    pub(crate) fn rewind(&mut self) {
        self.cursor = super::Delivery::default();
    }
    pub(crate) fn fresh_clone(&self) -> Self {
        Self {
            input: self.input.clone(),
            plan: self.plan.clone(),
            cursor: super::Delivery::default(),
        }
    }
    pub(crate) fn write(&mut self, output: &mut [u8]) -> usize {
        let mut at = 0;
        self.write_with(|bytes| {
            let copied = bytes.len().min(output.len() - at);
            output[at..at + copied].copy_from_slice(&bytes[..copied]);
            at += copied;
            copied
        })
    }
}

#[test]
fn audit_renderer_work_budgets_and_invalid_arguments() {
    let text = ">".repeat(super::MAX_NORMALISE_OPERATIONS + 1);
    assert!(super::compile_summary(
        Span {
            source: 0,
            start: 0,
            end: text.len()
        },
        &|_| text.as_str()
    )
    .is_err());
    assert_eq!(
        super::add_rendered(Some(super::MAX_RENDERED_BYTES), 1),
        None
    );
    let config =
        held(json!({"s":{"url":"https://up.test", "prompts_allow":{"p":{"template":"{value}"}}}}));
    assert!(Local::prompt(
        config,
        "s_p".into(),
        json!(1),
        Some(json!({"arguments":{"value":42}})),
        Revision::R2026_07_28
    )
    .is_err());
}

#[test]
fn audit_audio_is_refused_only_for_2024_and_resource_not_found_is_revision_specific() {
    let config = held(
        json!({"s":{"url":"https://up.test", "prompts_allow":{"p":{"messages":[
            {"content":{"type":"audio", "data":"YQ==", "mime_type":"audio/wav"}}
        ]}}}}),
    );
    assert!(Local::prompt(
        config.clone(),
        "s_p".into(),
        json!(1),
        None,
        Revision::R2024_11_05
    )
    .is_err());
    assert!(Local::prompt(
        config.clone(),
        "s_p".into(),
        json!(1),
        None,
        Revision::R2025_11_25
    )
    .is_ok());
    for revision in [
        Revision::R2024_11_05,
        Revision::R2025_06_18,
        Revision::R2025_11_25,
        Revision::R2026_07_28,
    ] {
        let error = Local::resource(
            config.clone(),
            json!(1),
            Some(json!({"uri":"urn:missing"})),
            &|_, _| true,
            revision,
        )
        .unwrap_err();
        let body: Value = serde_json::from_slice(&error.body()).unwrap();
        assert_eq!(
            body["error"]["code"],
            if revision.has_sessions() {
                -32002
            } else {
                -32602
            }
        );
    }
}

#[test]
fn audit_virtual_expansion_is_refused_before_rendering() {
    let config = held(json!({"s":{"url":"https://up.test", "prompts_allow":{"p":{
        "template":"{value}".repeat(8193)
    }}}}));
    assert!(Local::prompt(
        config,
        "s_p".into(),
        json!(1),
        Some(json!({"arguments":{"value":"x".repeat(8192)}})),
        Revision::R2026_07_28
    )
    .is_err());
}

#[test]
fn served_resource_rejects_oversized_selector_before_lookup_or_echo() {
    let config = held(json!({"s":{"url":"https://up.test","resources_allow":{
        "urn:example":{"text":"ok"}
    }}}));
    let uri = "x".repeat(8193);
    let error = Local::resource(
        config,
        json!(1),
        Some(json!({"uri":uri})),
        &|_, _| true,
        Revision::R2026_07_28,
    )
    .unwrap_err();
    let body: Value = serde_json::from_slice(&error.body()).unwrap();
    assert_eq!(body["error"]["code"], -32602);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("byte limit"));
    assert!(error.body().len() < 1024);
}
