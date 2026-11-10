// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tools:` GRAMMAR'S TYPED READING — the half of the composition root's registry-row
//! battery (`crates/busbar/src/root/tests/linked_tools.rs`) that needs the plane's own
//! types: what the section's custom `Deserialize` reads a document INTO (the values, the
//! pin mechanisms and their root-ness, the deny-by-default grants, the ask lists), the
//! published-name invariant (`validate_published_names`, read off the built `Catalogue`)
//! and the Statement facts the root side reads the plane's words from.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{SECTION_DECLARING, SECTION_SELECTS};
use serde_json::{json, Value};

use super::{namespaced, validate_published_names, ToolsCfg, SECTION, SUBJECT_NOUN};
use crate::client::jsonrpc::ServerAsk;

/// The section read by the grammar alone, as the door reads its settings (no rule spanning
/// registrations): what one server's well-formedness is judged by.
fn grammar(section: Value) -> Result<ToolsCfg, String> {
    serde_json::from_value::<ToolsCfg>(section).map_err(|e| e.to_string())
}

/// The door's own `validate` over the whole section (what boot runs through the folded row).
fn door_validate(section: &Value) -> Result<ToolsCfg, String> {
    crate::statement::test_support::read_tools_section(
        &serde_json::to_vec(section).expect("a section serialises"),
    )
}

/// An ABSOLUTE program path AS THIS PLATFORM SPELLS ONE (the check is `Path::is_absolute`;
/// see the root battery's `ABS_PROGRAM` for why a hardcoded unix spelling would pass on the
/// wrong assertion on Windows).
const ABS_PROGRAM: &str = if cfg!(windows) {
    r"C:\Windows\System32\cmd.exe"
} else {
    "/bin/true"
};

/// THE LOCKED SECTION SHAPE, verbatim: the section knobs, the object pin, the `tools_allow`
/// MAP, the per-server credential mode and the bare-name hook attach.
fn locked_example() -> Value {
    json!({
        "hooks": ["tool-sanitizer"],
        "filesystem": {
            "url": "https://tools.internal/fs",
            "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" },
            "tools_allow": { "read_file": {} },
            "upstream_credentials": "own",
            "hooks": ["tool-sanitizer", "dispatch-order"]
        }
    })
}

#[test]
fn the_locked_section_shape_parses_into_the_values_it_declares() {
    let cfg = grammar(locked_example()).expect("the locked example must parse");
    assert_eq!(cfg.all_server_hooks, vec!["tool-sanitizer".to_string()]);
    assert_eq!(cfg.servers.len(), 1, "one server, and `hooks:` is not one");
    let fs = &cfg.servers["filesystem"];
    assert_eq!(fs.url, "https://tools.internal/fs");
    assert_eq!(fs.pin.mechanism.token(), "cert_spki");
    assert_eq!(fs.pin.key.as_deref(), Some("sha256/PIN=="));

    assert!(fs.tools_allow.contains_key("read_file"));
    assert_eq!(fs.tools_allow["read_file"].schema_hash, None);

    assert_eq!(
        fs.hooks,
        vec!["tool-sanitizer".to_string(), "dispatch-order".to_string()]
    );

    assert_eq!(
        cfg.effective_upstream_credentials("filesystem"),
        Some(busbar_contract::config::UpstreamCreds::Own)
    );
    door_validate(&locked_example()).expect("the door's validate accepts it");
}

/// THE SEPARATOR RULE, the grammar's half: a server id carrying the separator is refused
/// and a tool name carrying it is not, and the arithmetic that makes the server-id rule
/// necessary.
#[test]
fn the_namespace_separator_is_refused_in_a_server_id_and_allowed_in_a_tool_name() {
    let err = grammar(json!({
        "my_server": { "url": "https://x/", "pin": { "mechanism": "unpinned" } }
    }))
    .expect_err("a server id carrying the separator is ambiguous");
    assert!(err.contains("namespaced routing key"), "got: {err}");
    assert!(err.contains("my-server"), "a legal spelling: {err}");
    grammar(json!({
        "fs": {
            "url": "https://x/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "read_file": {} }
        }
    }))
    .expect("a tool name may carry the separator — the locked example does");

    assert_eq!(
        namespaced("a_b", "c"),
        namespaced("a", "b_c"),
        "if this equality ever stops holding, the server-id rule can be relaxed — and not before"
    );
    assert_ne!(
        namespaced("a", "b_c"),
        namespaced("a", "b-c"),
        "and two tools on ONE server never collide, whatever they are called"
    );
}

/// DENY-BY-DEFAULT is the `Default` impl, not a rule written down somewhere else and
/// remembered at each call site.
#[test]
fn server_initiated_grants_default_to_denied() {
    let cfg = grammar(json!({ "s": { "url": "https://x/", "pin": { "mechanism": "unpinned" } } }))
        .unwrap();
    let g = cfg.servers["s"].grants;
    assert!(!g.sampling && !g.elicitation && !g.roots);
    for method in [
        "sampling/createMessage",
        "elicitation/create",
        "roots/list",
        "some/future_ask",
    ] {
        assert!(
            !g.allows(ServerAsk::of_method(Some(method))),
            "an unwritten grant must deny `{method}` — including one this build has never heard of"
        );
    }

    let cfg = grammar(json!({
        "s": {
            "url": "https://x/",
            "pin": { "mechanism": "unpinned" },
            "grants": { "sampling": true }
        }
    }))
    .unwrap();
    let g = cfg.servers["s"].grants;
    assert!(g.allows(ServerAsk::Sampling));
    assert!(!g.allows(ServerAsk::Elicitation) && !g.allows(ServerAsk::Roots));
}

#[test]
fn sampling_bounds_grammar_defaults_round_trips_and_refuses() {
    let server = |bounds: Value| {
        json!({ "s": { "url": "https://x/", "pin": { "mechanism": "unpinned" },
            "grants": { "sampling": true }, "sampling_bounds": bounds } })
    };
    let omitted =
        grammar(json!({ "s": { "url": "https://x/", "pin": { "mechanism": "unpinned" } } }))
            .unwrap();
    let d = omitted.servers["s"].sampling_bounds;
    assert_eq!(
        (
            d.max_messages,
            d.max_prompt_bytes,
            d.max_stop_sequences,
            d.max_stop_sequence_bytes,
            d.temperature_min_milli,
            d.temperature_max_milli
        ),
        (64, 65536, 8, 64, 0, 2000)
    );
    assert_eq!(
        d.max_input_response_bytes, 1_048_576,
        "the reply cap defaults to 1 MiB when omitted"
    );

    let written = grammar(server(
        json!({ "max_messages": 5, "temperature_max_milli": 900 }),
    ))
    .unwrap();
    let b = written.servers["s"].sampling_bounds;
    assert_eq!((b.max_messages, b.temperature_max_milli), (5, 900));
    assert_eq!(
        b.max_prompt_bytes, 65536,
        "an unwritten key keeps its default"
    );
    let again: super::SamplingBoundsCfg =
        serde_json::from_value(serde_json::to_value(b).expect("public bounds serialize"))
            .expect("public bounds round trip");
    assert_eq!(again, b);
    assert_eq!(d, super::SamplingBoundsCfg::default());
    assert_ne!(b, super::SamplingBoundsCfg::default());

    assert!(grammar(server(json!({ "max_message": 5 }))).is_err());

    for (bounds, key) in [
        (json!({ "max_messages": 0 }), "max_messages"),
        (json!({ "max_prompt_bytes": 0 }), "max_prompt_bytes"),
        (
            json!({ "max_input_response_bytes": 0 }),
            "max_input_response_bytes",
        ),
        (
            json!({ "temperature_min_milli": 1500, "temperature_max_milli": 500 }),
            "temperature_min_milli",
        ),
    ] {
        let err = door_validate(&server(bounds)).expect_err(key);
        assert!(
            err.contains(&format!("sampling_bounds.{key}")),
            "the refusal names `{key}`: {err}"
        );
    }
    door_validate(&server(json!({ "max_messages": 1, "max_prompt_bytes": 1 })))
        .expect("positive caps are accepted");
}

/// BOTH TRANSPORTS BOOT, the typed half: a stdio registration carries its command and
/// arguments and no url (the root battery asserts boot accepts both).
#[test]
fn both_transports_are_accepted_at_parse() {
    grammar(json!({
        "s": {
            "url": "https://x/",
            "pin": { "mechanism": "unpinned" },
            "transport": "streamable_http"
        }
    }))
    .expect("the network transport is accepted");
    let cfg = grammar(json!({
        "s": {
            "pin": { "mechanism": "unpinned" },
            "transport": "stdio",
            "command": ABS_PROGRAM,
            "args": ["--root", "/srv"]
        }
    }))
    .expect("a stdio registration with a command is accepted");
    let s = &cfg.servers["s"];
    assert_eq!(s.command.as_deref(), Some(ABS_PROGRAM));
    assert_eq!(s.args, vec!["--root".to_string(), "/srv".to_string()]);
    assert!(
        s.url.is_empty(),
        "a stdio registration reaches no address, so it carries no url"
    );
}

/// Every name the catalogue would PUBLISH for `cfg`, sorted — read off the built snapshot
/// (the plane's own catalogue, the one its door serves `tools/list` from) rather than
/// recomputed from the config, so a test cannot agree with a formula the catalogue no
/// longer uses.
fn published_names(cfg: &ToolsCfg) -> Vec<String> {
    let cat = crate::catalogue::Catalogue::build(1, cfg);
    let mut names: Vec<String> = cat
        .tools_for(&|_, _| true)
        .into_iter()
        .map(|t| t.namespaced.clone())
        .collect();
    names.sort();
    names
}

/// THE DEFAULT IS UNCHANGED, and this is the test that has to keep passing forever: a
/// config that writes no `publish_as:` publishes exactly what it published before the field
/// existed.
#[test]
fn absent_publish_as_publishes_the_namespaced_default_byte_for_byte() {
    let cfg = grammar(locked_example()).expect("the locked example must parse");
    assert_eq!(
        cfg.servers["filesystem"].tools_allow["read_file"].publish_as,
        None
    );
    validate_published_names(&cfg).expect("no override can never collide with itself");

    assert_eq!(
        published_names(&cfg),
        vec!["filesystem_read_file".to_string()],
        "the namespaced default must still be the published name"
    );
}

/// The override is READ, and it is the name the CATALOGUE publishes — which is the same
/// string `tools/call` dispatches on and an `mcp_tool:` grant names.
#[test]
fn publish_as_is_the_published_name_and_the_namespaced_default_is_then_gone() {
    let cfg = grammar(json!({
        "github": {
            "url": "https://tools.internal/gh",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "greet": { "publish_as": "greet" } }
        }
    }))
    .expect("an override must parse");
    validate_published_names(&cfg).expect("one tool cannot collide with itself");

    let cat = crate::catalogue::Catalogue::build(1, &cfg);
    let all = cat.tools_for(&|_, _| true);

    assert_eq!(
        all.len(),
        1,
        "the override replaces the default; it does not alias it"
    );
    assert_eq!(all[0].namespaced, "greet");
    assert_eq!(all[0].server, "github");
    assert_eq!(all[0].tool, "greet");
}

fn exchanged_published_name(published: &str) -> Value {
    json!({
        "fs": {
            "url": "https://tools.example/fs",
            "pin": { "mechanism": "unpinned" },
            "aud": "https://tools.example/fs",
            "token_exchange": {
                "token_url": "https://as.example/token",
                "subject_token": {"module": "fixture-env-source", "settings": {"name": "SUBJECT"}}
            },
            "tools_allow": {
                "read_file": { "schema_hash": "sha256:approved", "publish_as": published }
            }
        }
    })
}

#[test]
fn an_exchanged_published_name_must_be_one_oauth_scope_token() {
    for published in [
        "read admin",
        "read\tadmin",
        "read\nadmin",
        "read\radmin",
        "read\"admin",
        "read\\admin",
        "read\u{7f}admin",
        "read\0admin",
        "readéadmin",
    ] {
        let section = exchanged_published_name(published);
        let err = grammar(section.clone())
            .expect_err("one MCP grant must not become multiple or malformed OAuth scopes");
        assert!(err.contains("tools.fs"), "{err}");
        assert!(err.contains("tools_allow.read_file.publish_as"), "{err}");
        assert!(err.contains("scope token"), "{err}");
        assert_eq!(door_validate(&section).unwrap_err(), err);
    }
}

#[test]
fn exchanged_scope_tokens_preserve_the_published_name_bytes_and_default() {
    for published in ["read:admin", "!#[]~", "read%20admin"] {
        let cfg = door_validate(&exchanged_published_name(published))
            .expect("RFC 6749 punctuation remains legal in a scope token");
        assert_eq!(published_names(&cfg), vec![published.to_string()]);
        assert_eq!(
            crate::tool_scope::registration_scope("fs", &cfg.servers["fs"]),
            published
        );
        let catalogue = crate::catalogue::Catalogue::build(1, &cfg);
        for wildcard in [false, true] {
            assert_eq!(
                crate::tool_scope::caller_downscope(
                    &catalogue,
                    "fs",
                    published,
                    wildcard,
                    &|name| name == published,
                ),
                published
            );
        }
    }
    let mut section = exchanged_published_name("unused");
    section["fs"]["tools_allow"]["read_file"] = json!({"schema_hash": "sha256:approved"});
    let cfg = door_validate(&section).expect("the namespaced default remains one scope token");
    assert_eq!(published_names(&cfg), vec!["fs_read_file".to_string()]);
    assert_eq!(
        crate::tool_scope::registration_scope("fs", &cfg.servers["fs"]),
        "fs_read_file"
    );
}

#[test]
fn an_exchanged_default_name_cannot_hide_a_scope_separator() {
    for (server, tool) in [("fs", "read admin"), ("bad server", "read_file")] {
        let section = json!({
            server: {
                "url": "https://tools.example/fs",
            "pin": { "mechanism": "unpinned" },
                "aud": "https://tools.example/fs",
                "token_exchange": {
                    "token_url": "https://as.example/token",
                    "subject_token": {"module": "fixture-env-source", "settings": {"name": "SUBJECT"}}
                },
                "tools_allow": { tool: { "schema_hash": "sha256:approved" } }
            }
        });
        let err = grammar(section.clone())
            .expect_err("the server and tool identity rules already refuse embedded spaces");
        assert_eq!(door_validate(&section).unwrap_err(), err);
    }
}

#[test]
fn ordinary_published_names_keep_their_non_oauth_spelling() {
    for published in [
        "read admin",
        "read\tadmin",
        "read\"admin",
        "read\\admin",
        "readéadmin",
    ] {
        let mut section = exchanged_published_name(published);
        section["fs"]
            .as_object_mut()
            .unwrap()
            .remove("token_exchange");
        let cfg = door_validate(&section)
            .expect("an ordinary MCP published name need not be an OAuth scope token");
        assert_eq!(published_names(&cfg), vec![published.to_string()]);
    }
}

/// RED 1 — TWO OVERRIDES COLLIDING. The obvious case, and the only one a naive check catches.
#[test]
fn two_publish_as_overrides_that_collide_refuse_the_config() {
    let section = json!({
        "alpha": {
            "url": "https://a/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "greet_a": { "publish_as": "greet" } }
        },
        "beta": {
            "url": "https://b/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "greet_b": { "publish_as": "greet" } }
        }
    });
    let cfg = grammar(section.clone())
        .expect("both servers are individually well-formed; the collision is cross-server");
    let err =
        validate_published_names(&cfg).expect_err("two tools published as `greet` must refuse");
    assert!(err.contains("published as `greet`"), "{err}");

    assert!(
        err.contains("tools.alpha.tools_allow.greet_a.publish_as"),
        "{err}"
    );
    assert!(
        err.contains("tools.beta.tools_allow.greet_b.publish_as"),
        "{err}"
    );
    assert_eq!(
        door_validate(&section).expect_err("the door refuses it"),
        err,
        "the door's validate over the whole section (what boot runs) refuses it in the same words"
    );
}

/// RED 2 — THE SUBTLE CASE, and the reason the check is against the WHOLE PUBLISHED SET
/// rather than override-against-override.
#[test]
fn an_override_colliding_with_a_namespaced_default_refuses_the_config() {
    let section = json!({
        "foo": {
            "url": "https://foo/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "bar": {} }
        },
        "other": {
            "url": "https://other/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "anything": { "publish_as": "foo_bar" } }
        }
    });
    let cfg =
        grammar(section.clone()).expect("neither server is individually wrong; only the pair is");
    let err = validate_published_names(&cfg)
        .expect_err("an override must not shadow another server's namespaced default");
    assert!(err.contains("published as `foo_bar`"), "{err}");

    assert!(
        err.contains("the default `{server}_{tool}` name of `tools.foo.tools_allow.bar`"),
        "{err}"
    );
    assert!(
        err.contains("tools.other.tools_allow.anything.publish_as"),
        "{err}"
    );
    assert_eq!(
        door_validate(&section).expect_err("the door refuses it"),
        err,
        "the door's validate over the whole section (what boot runs) refuses it in the same words"
    );
}

/// The same collision in the OTHER declaration order. Config order must not decide whether
/// a config boots: an operator who reorders two server blocks has changed nothing.
#[test]
fn the_default_versus_override_collision_is_refused_in_either_declaration_order() {
    let section = json!({
        "aaa": {
            "url": "https://a/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "anything": { "publish_as": "zzz_bar" } }
        },
        "zzz": {
            "url": "https://z/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "bar": {} }
        }
    });
    let cfg = grammar(section.clone()).expect("parses");
    let err = validate_published_names(&cfg).expect_err("order must not decide this");
    assert!(err.contains("published as `zzz_bar`"), "{err}");
    assert_eq!(
        door_validate(&section).expect_err("the door refuses it"),
        err,
        "the door's validate over the whole section (what boot runs) refuses it in the same words"
    );
}

/// An override that spells the namespaced default is NOT a collision — it publishes the
/// same one name the default would have.
#[test]
fn an_override_equal_to_its_own_namespaced_default_is_not_a_collision() {
    let cfg = grammar(json!({
        "foo": {
            "url": "https://foo/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "bar": { "publish_as": "foo_bar" } }
        }
    }))
    .expect("parses");
    validate_published_names(&cfg).expect("one tool, one name — whichever way it is spelled");
    assert_eq!(published_names(&cfg), vec!["foo_bar".to_string()]);
}

/// The three legal ask methods parse into a three-entry round, read as written: the rule
/// refuses typos, not asks (the refusals themselves are the root battery's, at boot).
#[test]
fn every_ask_list_is_validated_and_the_three_legal_methods_still_parse() {
    let cfg = grammar(json!({
        "filesystem": {
            "url": "https://tools.internal/fs",
            "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" },
            "prompts_allow": {
                "summarise": {
                    "template": "hi",
                    "ask_caller": [
                        { "a": { "method": "elicitation/create" } },
                        { "b": { "method": "sampling/createMessage" } },
                        { "c": { "method": "roots/list" } }
                    ]
                }
            }
        }
    }))
    .expect("all three legal methods must still parse — the rule refuses typos, not asks");
    assert_eq!(
        cfg.servers["filesystem"].prompts_allow["summarise"]
            .ask_caller
            .len(),
        3
    );
}

/// Whether `stated` is the tail string built from `word` (the tail's strings are constants
/// of this crate, so a word is found by address and length, as `tests/statement.rs` reads
/// them).
fn spells(stated: AbiStr, word: &str) -> bool {
    stated.ptr() == word.as_ptr() && stated.len() == word.len()
}

/// THE WORDS THE ROOT BATTERY READS OFF THE STATEMENT ARE THE GRAMMAR'S: the declaring
/// section is `SECTION`, the owned one the endpoint block (which selects the plane), the
/// subject noun `SUBJECT_NOUN`; and the endpoint's fixed mount and its RFC 9728 document
/// are spelled from the endpoint block's name (so the root may build them from the section
/// the Statement owns).
#[test]
fn the_statement_names_the_grammars_section_noun_and_endpoint() {
    let sections = crate::statement::SECTIONS;
    assert_eq!(sections.len(), 2);
    assert!(spells(sections[0].name, SECTION), "the declaring section");
    assert_ne!(sections[0].flags & SECTION_DECLARING, 0);
    assert!(
        spells(sections[1].name, crate::statement::ENDPOINT_SECTION),
        "the owned endpoint block"
    );
    assert_eq!(sections[1].flags & SECTION_DECLARING, 0);
    assert_ne!(
        sections[1].flags & SECTION_SELECTS,
        0,
        "the endpoint block selects the plane (Law 7)"
    );
    assert!(spells(crate::statement::TAIL.subject_noun, SUBJECT_NOUN));
    assert_eq!(
        crate::tool_claims::DEFAULT_MOUNT,
        format!("/{}", crate::statement::ENDPOINT_SECTION)
    );
    assert_eq!(
        crate::tool_claims::DEFAULT_METADATA,
        format!(
            "/.well-known/oauth-protected-resource/{}",
            crate::statement::ENDPOINT_SECTION
        )
    );
    assert_eq!(crate::statement::TAIL.dialects_len(), 1, "one wire dialect");
}

#[test]
fn a_servers_timeout_bounds_the_doors_own_fetches_and_the_kernel_owns_its_judgement() {
    let server = |extra: Value| {
        let mut s = json!({
            "url": "https://tools.internal/fs",
            "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" },
            "tools_allow": { "read_file": {} },
        });
        if let (Some(s), Some(extra)) = (s.as_object_mut(), extra.as_object()) {
            s.extend(extra.clone());
        }
        s
    };
    let cfg = grammar(json!({
        "timed": server(json!({ "timeout": "10s" })),
        "untimed": server(json!({})),
    }))
    .expect("both read");
    assert_eq!(cfg.servers["timed"].timeout_ms(), 10_000);
    assert_eq!(
        cfg.servers["untimed"].timeout_ms(),
        super::DEFAULT_UPSTREAM_TIMEOUT_MS
    );
    assert_eq!(
        super::DEFAULT_UPSTREAM_TIMEOUT_MS,
        30_000,
        "docs/mcp.md's default"
    );
    assert!(
        door_validate(&json!({ "zero": server(json!({ "timeout": "0s" })) })).is_err(),
        "door validation delegates zero-timeout rejection to the shared kernel parser"
    );
}

/// EVERY CAPABILITY'S PUBLISHED NAME IS IN THE ONE SET. A prompt, a resource and a template
/// are published under `{server}_{name}` and admitted by an `mcp_tool:` grant on that name,
/// exactly as a tool is: a tool published as `bar_greet` on `foo` and the prompt `greet` on
/// `bar` would make one `mcp_tool: bar_greet` grant admit both.
#[test]
fn a_tool_override_colliding_with_another_servers_prompt_refuses_the_config() {
    let section = json!({
        "foo": {
            "url": "https://foo/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "hello": { "publish_as": "bar_greet" } }
        },
        "bar": {
            "url": "https://bar/",
            "pin": { "mechanism": "unpinned" },
            "prompts_allow": { "greet": { "template": "hi" } }
        }
    });
    let cfg = grammar(section.clone()).expect("each server is well-formed on its own");
    let err = validate_published_names(&cfg)
        .expect_err("one published name may not mean a tool and a prompt");
    assert!(err.contains("published as `bar_greet`"), "{err}");
    assert!(
        err.contains("tools.foo.tools_allow.hello.publish_as"),
        "{err}"
    );
    assert!(
        err.contains("the default `{server}_{tool}` name of `tools.bar.prompts_allow.greet`"),
        "{err}"
    );
    assert_eq!(
        door_validate(&section).expect_err("the door refuses it"),
        err,
        "the door's validate over the whole section refuses it in the same words"
    );
}

/// The same set holds resources and resource templates: a tool override shadowing another
/// server's resource URI, or its template, is refused in turn.
#[test]
fn a_tool_override_colliding_with_a_resource_or_a_template_refuses_the_config() {
    for (family, key, published) in [
        ("resources_allow", "file:///readme", "bar_file:///readme"),
        (
            "resource_templates_allow",
            "file:///logs/{date}",
            "bar_file:///logs/{date}",
        ),
    ] {
        let mut bar = json!({ "url": "https://bar/", "pin": { "mechanism": "unpinned" } });
        bar[family] = json!({ key: { "text": "log {date}" } });
        let cfg = grammar(json!({
            "foo": {
                "url": "https://foo/",
                "pin": { "mechanism": "unpinned" },
                "tools_allow": { "hello": { "publish_as": published } }
            },
            "bar": bar
        }))
        .expect("each server is well-formed on its own");
        let err = validate_published_names(&cfg)
            .expect_err("one published name may not mean a tool and a resource");
        assert!(
            err.contains(&format!("`tools.bar.{family}.{key}`")),
            "{err}"
        );
    }
}

/// Distinct capabilities on distinct names still boot: the widened set refuses collisions only.
#[test]
fn distinct_capability_names_across_families_still_validate() {
    let cfg = grammar(json!({
        "fs": {
            "url": "https://fs/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "read_file": {} },
            "prompts_allow": { "summarise": { "template": "hi" } },
            "resources_allow": { "file:///readme": { "text": "hi" } },
            "resource_templates_allow": { "file:///logs/{date}": { "text": "log {date}" } }
        }
    }))
    .expect("a well-formed server");
    validate_published_names(&cfg).expect("four names, four capabilities");
}

/// `mtls` NEEDS A CLIENT IDENTITY: a registration that says its server is behind mutual TLS
/// and names nothing to present is refused at boot, not at the server's handshake.
#[test]
fn mtls_without_a_client_identity_is_refused_and_with_one_reads() {
    let identity = json!({
        "cert": {"module": "fixture-env-source", "settings": {"name": "MCP_CLIENT_CERT"}},
        "key": {"module": "fixture-env-source", "settings": {"name": "MCP_CLIENT_KEY"}}
    });
    let bare = json!({
        "fs": { "url": "https://fs/", "pin": { "mechanism": "mtls", "key": "AAAA" } }
    });
    let err = grammar(bare).expect_err("mtls with nothing to present");
    assert!(
        err.contains("`pin.mechanism: mtls` needs `client_identity:`"),
        "{err}"
    );

    let cfg = grammar(json!({
        "fs": {
            "url": "https://fs/",
            "pin": { "mechanism": "mtls", "key": "AAAA" },
            "client_identity": identity
        }
    }))
    .expect("mtls with an identity reads");
    assert!(
        cfg.servers["fs"].client_identity.is_some(),
        "the identity is read"
    );

    grammar(json!({
        "fs": {
            "url": "https://fs/",
            "pin": { "mechanism": "cert_spki", "key": "AAAA" },
            "client_identity": identity
        }
    }))
    .expect("an identity beside a cert_spki pin reads");
}

/// A client certificate is a TLS-handshake object: refused where there is no handshake, on
/// an `http://` url and on `transport: stdio`.
#[test]
fn a_client_identity_with_no_handshake_to_present_it_in_is_refused() {
    let identity = json!({ "cert": {"module": "fixture-env-source", "settings": {"name": "C"}}, "key": {"module": "fixture-env-source", "settings": {"name": "K"}} });
    let err = grammar(json!({
        "fs": {
            "url": "http://fs.internal/",
            "pin": { "mechanism": "unpinned" },
            "client_identity": identity
        }
    }))
    .expect_err("an identity over plaintext");
    assert!(err.contains("`url:` is `http://`"), "{err}");
    let err = grammar(json!({
        "s": {
            "pin": { "mechanism": "unpinned" },
            "transport": "stdio",
            "command": ABS_PROGRAM,
            "client_identity": identity
        }
    }))
    .expect_err("an identity on a pipe");
    assert!(
        err.contains("`transport: stdio` makes no handshake"),
        "{err}"
    );
}

/// The typed grammar preserves public CA material; the host's operator-CA parser owns PEM/DER
/// validation before publication. Client identity remains the existing sibling object.
#[test]
fn a_member_tls_bundle_keeps_public_material_and_legacy_client_identity_separate() {
    let public_material =
        "-----BEGIN CERTIFICATE-----\nopaque to the typed grammar\n-----END CERTIFICATE-----";
    let identity = json!({"cert": {"module": "fixture-env-source", "settings": {"name": "C"}}, "key": {"module": "fixture-env-source", "settings": {"name": "K"}}});
    for (mechanism, with_identity) in [("cert_spki", false), ("mtls", true)] {
        let mut server = json!({
            "url": "https://fs.internal/",
            "pin": {"mechanism": mechanism, "key": "AAAA"},
            "tls": {"ca_cert_pem": public_material}
        });
        if with_identity {
            server["client_identity"] = identity.clone();
        }
        let cfg = grammar(json!({"fs": server})).expect("the TLS config shape reads");
        let def = &cfg.servers["fs"];
        assert_eq!(def.tls.as_ref().unwrap().ca_cert_pem, public_material);
        assert_eq!(def.client_identity.is_some(), with_identity);
        let encoded = serde_json::to_value(def.tls.as_ref().unwrap()).unwrap();
        assert_eq!(encoded["ca_cert_pem"], public_material);
        assert!(encoded.get("client_identity").is_none());
    }
    let old = grammar(json!({"fs": {
        "url": "https://fs.internal/",
        "pin": {"mechanism": "mtls", "key": "AAAA"},
        "client_identity": identity
    }}))
    .expect("existing identity-only config stays valid");
    assert!(old.servers["fs"].tls.is_none());
    assert!(old.servers["fs"].client_identity.is_some());
}

#[test]
fn member_tls_refuses_empty_wrong_shape_and_nested_identity_spellings() {
    for tls in [
        json!({}),
        json!({"ca_cert_pem": ""}),
        json!({"ca_cert_pem": " \n\t"}),
        json!({"ca_cert_pem": {"module": "fixture-file-source", "settings": {"path": "/run/ca.pem"}}}),
        json!({"ca_cert_pem": 42}),
        json!({"ca_cert_pem": "public CA", "client_identity": {"cert": {"module": "fixture-env-source", "settings": {"name": "C"}}, "key": {"module": "fixture-env-source", "settings": {"name": "K"}}}}),
        json!({"ca_cert_pem": "public CA", "unknown": true}),
    ] {
        assert!(
            grammar(json!({"fs": {
                "url": "https://fs.internal/",
                "pin": {"mechanism": "cert_spki", "key": "AAAA"},
                "tls": tls
            }}))
            .is_err(),
            "invalid TLS shape was accepted"
        );
    }
}

#[test]
fn member_tls_is_refused_without_a_secured_network_handshake() {
    for server in [
        json!({"url": "http://fs.internal/", "pin": {"mechanism": "unpinned"}, "tls": {"ca_cert_pem": "public CA"}}),
        json!({"transport": "stdio", "command": ABS_PROGRAM, "pin": {"mechanism": "unpinned"}, "tls": {"ca_cert_pem": "public CA"}}),
    ] {
        let err = grammar(json!({"fs": server})).expect_err("TLS cannot be silently ignored");
        assert!(err.contains("`tls:`"), "{err}");
    }
}

/// THE CANARY a credential-echo test plants: bytes that may appear in a config and must
/// appear in no refusal, error or `Debug` rendering of it.
const CANARY: &str = "CANARY-plane-mcp-echo-7f3a91";

/// One registration read straight into its typed definition, then judged by
/// [`validate_server`], the function boot and the admin write path both call.
fn refusal_of(extra: Value) -> String {
    let mut s = json!({
        "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" },
        "tools_allow": { "read_file": {} },
    });
    if let (Some(s), Some(extra)) = (s.as_object_mut(), extra.as_object()) {
        s.extend(extra.clone());
    }
    let def: super::McpServerDefCfg = serde_json::from_value(s).expect("the shape reads");
    super::validate_server("canary", &def).expect_err("the registration is refused")
}

/// A `url:` refused for its scheme names the URL it refused, WITHOUT the userinfo an
/// operator put in it: the refusal reaches stderr and the read-only admin validate
/// endpoint, so a password in the URL would be handed to anyone who can read either.
#[test]
fn a_refused_url_does_not_echo_its_userinfo() {
    let err = refusal_of(json!({ "url": format!("ftp://user:{CANARY}@tools.internal/mcp") }));
    assert!(
        !err.contains(CANARY),
        "the refusal echoes the credential: {err}"
    );
    assert!(
        !err.contains("user:"),
        "the refusal echoes the userinfo: {err}"
    );
    assert!(
        err.contains("`url:` must be an http:// or https:// endpoint, got `<redacted URL>`"),
        "the refusal keeps its words and the rest of the URL: {err}"
    );
}

/// The same for `token_exchange.token_url:`, refused for plaintext to a public host.
#[test]
fn a_refused_token_url_does_not_echo_its_userinfo() {
    let err = refusal_of(json!({
        "url": "https://tools.internal/mcp",
        "token_exchange": {
            "token_url": format!("http://busbar:{CANARY}@auth.example.com/token"),
            "subject_token": {"module": "fixture-env-source", "settings": {"name": "BUSBAR_SUBJECT"}},
        },
    }));
    assert!(
        !err.contains(CANARY),
        "the refusal echoes the credential: {err}"
    );
    assert!(
        err.contains("Got `<redacted URL>`."),
        "the refusal keeps its words and the rest of the URL: {err}"
    );
}

/// A URL with no userinfo is echoed byte for byte: masking removes credential bytes and
/// nothing else, so every refusal that never carried a credential reads exactly as it did.
#[test]
fn a_refused_url_without_userinfo_is_echoed_verbatim() {
    assert_eq!(super::url_for_display("https://h/p"), "https://h/p");
    for raw in [
        "https:/u:secret@h",
        "ftp://u:sec/ret@host",
        "ftp://u:sec?ret@host",
        "ftp://u:sec#ret@host",
        "ftp://u:sec\\ret@host",
        "u:p@h/x",
    ] {
        assert_eq!(super::url_for_display(raw), "<redacted URL>");
    }
}

/// A stdio child's `env:` literal is not printed by `Debug`: a value an operator pasted
/// there may be the credential the secret-reference arm exists to keep out of the config,
/// and `Debug` is what a log line or a panic message renders.
#[test]
fn a_child_env_literal_is_not_printed_by_debug() {
    let plain = super::ChildEnvValue::Plain(
        busbar_contract::abi::sdk::cred::Cred::take(&mut json!(CANARY)).expect("a string"),
    );
    let shown = format!("{plain:?}");
    assert!(!shown.contains(CANARY), "{shown}");
    assert_eq!(shown, "Plain(<redacted>)");
}

/// A stdio child's `env:` literal is sealed as it is read (CHIP-DESIGN v4.1 change 12): the
/// registration holds it as a `Cred`, so neither writing the registration back nor its
/// `Debug` spells it, and the same literal read twice is still the same registration.
#[test]
fn a_child_env_literal_is_sealed_at_parse_and_never_written_back() {
    let section = json!({
        "s": {
            "pin": { "mechanism": "unpinned" },
            "transport": "stdio",
            "command": ABS_PROGRAM,
            "env": { "API_KEY": CANARY, "UPSTREAM": {"module": "fixture-env-source", "settings": {"name": "BUSBAR_UPSTREAM_KEY"}} }
        }
    });
    let cfg = grammar(section.clone()).expect("a stdio registration with an env literal");
    let def = &cfg.servers["s"];
    assert!(!format!("{def:?}").contains(CANARY));
    assert_eq!(&grammar(section).expect("reads again").servers["s"], def);
}

/// One network registration `fs`, stating the RFC 8693 exchange (`token_exchange:` with its
/// `aud:`) when `exchanged`.
fn registration(exchanged: bool) -> Value {
    let mut fs = json!({
        "url": "https://tools.internal/fs",
        "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" },
        "tools_allow": { "read_file": {} }
    });
    if exchanged {
        fs["aud"] = json!("https://tools.internal");
        fs["token_exchange"] = json!({
            "token_url": "https://as.internal/token",
            "subject_token": {"module": "fixture-env-source", "settings": {"name": "BUSBAR_FS_SUBJECT"}}
        });
    }
    fs
}

/// The sentence every refusal of a forwarded caller credential carries: what it would
/// forward and the two modes that forward nothing of the caller's.
fn assert_explained(err: &str, server: &str) {
    for word in [
        format!("`tools.{server}`"),
        "busbar credential".to_string(),
        "`token_exchange:`".to_string(),
        "`own`".to_string(),
    ] {
        assert!(err.contains(&word), "the refusal names {word}: {err}");
    }
}

/// THE SECTION DEFAULT NEVER SILENTLY OVERRIDES AN EXCHANGE (website `mcp.md:501-505`): a
/// section-level `upstream_credentials: passthrough` beside a registration that states
/// `token_exchange:` used to validate, and the registration was then bound to passthrough
/// with its exchange dropped.
#[test]
fn a_section_passthrough_default_refuses_a_token_exchange_registration() {
    let section = json!({ "upstream_credentials": "passthrough", "fs": registration(true) });
    let err = grammar(section.clone()).expect_err("the exchange is never silently dropped");
    assert_explained(&err, "fs");
    assert!(err.contains("token_exchange"), "{err}");
    let err = door_validate(&section).expect_err("the door's validate refuses it too");
    assert_explained(&err, "fs");

    let err = grammar(json!({ "upstream_credentials": "passthrough", "fs": registration(false) }))
        .expect_err("a section passthrough default is refused");
    assert_explained(&err, "fs");

    let tail = crate::statement::TAIL.caller_credential_refusal;
    assert!(
        !tail.ptr().is_null() && !tail.is_empty(),
        "the tail states the sentence the kernel refuses a section passthrough default in"
    );

    grammar(json!({ "upstream_credentials": "own", "fs": registration(true) }))
        .expect("an exchange under the `own` default is accepted");
}

/// A REGISTRATION'S OWN `passthrough` IS REFUSED, alone or beside its own
/// `token_exchange:`, naming the registration and the alternatives: it would present the
/// caller's busbar credential to that server.
#[test]
fn a_registrations_own_passthrough_is_refused_alone_and_beside_an_exchange() {
    for exchanged in [false, true] {
        let mut fs = registration(exchanged);
        fs["upstream_credentials"] = json!("passthrough");
        let err = grammar(json!({ "fs": fs })).expect_err("passthrough is refused");
        assert_explained(&err, "fs");
        if exchanged {
            assert!(err.contains("token_exchange"), "{err}");
        }
    }
}

#[test]
fn an_unverified_manifest_key_is_not_an_authenticity_root() {
    let section = json!({"fs": {
        "url": "https://mcp.example/rpc",
        "pin": {"mechanism": "pinned_pubkey", "key": "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="}
    }});
    let error = door_validate(&section).expect_err("no manifest signature is verified");
    assert!(
        error.contains("pinned_pubkey") && error.contains("authenticates nothing"),
        "{error}"
    );
    assert!(
        error.contains("cert_spki") && error.contains("mtls"),
        "{error}"
    );
}

#[test]
fn supported_endpoint_pins_still_validate_with_their_required_identity() {
    for mechanism in ["cert_spki", "mtls"] {
        let mut entry = json!({
            "url": "https://mcp.example/rpc",
            "pin": {"mechanism": mechanism, "key": "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="}
        });
        if mechanism == "mtls" {
            entry["client_identity"] = json!({"cert": {"module": "fixture-file-source", "settings": {"path": "/run/mcp/client.crt"}}, "key": {"module": "fixture-file-source", "settings": {"path": "/run/mcp/client.key"}}});
        }
        door_validate(&json!({"fs": entry})).expect("supported pin and identity grammar");
    }
}

#[test]
fn program_paths_are_validated_with_the_exact_bytes_the_child_will_receive() {
    let directory = if cfg!(windows) { r"C:\Windows" } else { "/tmp" };
    for field in ["command", "cwd"] {
        let value = if field == "command" {
            ABS_PROGRAM
        } else {
            directory
        };
        for padded in [format!(" {value}"), format!("{value} ")] {
            let mut entry = json!({"transport": "stdio", "command": ABS_PROGRAM, "pin": {"mechanism": "unpinned"}});
            entry[field] = padded.into();
            let error = door_validate(&json!({"fs": entry})).expect_err("padded exec path");
            assert!(error.contains(field), "{error}");
        }
    }
}

#[test]
fn every_advertised_tool_name_fits_the_existing_call_limit() {
    let max = crate::call::MAX_TOOL_NAME_BYTES;
    for overridden in [false, true] {
        for length in [max, max + 1] {
            let tool = if overridden {
                "read".to_owned()
            } else {
                "a".repeat(length - 3)
            };
            let allow = if overridden {
                json!({"publish_as": "a".repeat(length)})
            } else {
                json!({})
            };
            let section = json!({"fs": {"url": "https://mcp.example/rpc", "pin": {"mechanism": "unpinned"}, "tools_allow": {(tool): allow}}});
            let result = door_validate(&section);
            assert_eq!(
                result.is_ok(),
                length == max,
                "override={overridden}, length={length}: {result:?}"
            );
        }
    }
}

#[test]
fn a_uri_template_rejects_unmatched_closing_braces_in_every_literal_segment() {
    for template in [
        "file:///a}b/{name}",
        "file:///{name}/a}b/{tail}",
        "file:///{name}/end}",
    ] {
        let section = json!({"fs": {"url": "https://mcp.example/rpc", "pin": {"mechanism": "unpinned"}, "resource_templates_allow": {(template): {"text": "Hello {name}"}}}});
        door_validate(&section).expect_err("stray closing brace");
    }
    door_validate(&json!({"fs": {"url": "https://mcp.example/rpc", "pin": {"mechanism": "unpinned"}, "resource_templates_allow": {"file:///{name}": {"text": "Hello {name}"}}}})).expect("balanced template");
}

#[test]
fn audit_invalid_uri_templates_and_resource_indicators_are_refused() {
    for template in [
        "file:///{.ext}",
        "file:///{a.}",
        "file:///{a..b}",
        "file:///{a}{b}",
    ] {
        assert!(
            super::validate_uri_template("test", template).is_err(),
            "{template}"
        );
    }
    assert!(super::validate_uri_template("test", "file:///{a.b}/{c}").is_ok());
    for aud in ["https://", "http://", "https://example.com/mcp#frag"] {
        assert!(door_validate(&json!({"s":{"url":"https://example.com/mcp", "aud":aud}})).is_err());
    }
    assert!(
        door_validate(&json!({"s":{"url":"https://example.com/mcp", "timeout":"nonsense"}}))
            .is_err()
    );
}

#[test]
fn audit_prompt_content_refuses_unknown_keys() {
    assert!(grammar(
        json!({"s":{"url":"https://example.com/mcp", "prompts_allow":{"p":{
            "messages":[{"content":{"type":"text", "text":"hello", "typo":true}}]
        }}}})
    )
    .is_err());
}

#[test]
fn pinned_schema_rejects_invalid_header_annotations_at_configuration_time() {
    for annotation in [serde_json::json!(true), serde_json::json!("bad name")] {
        let section = serde_json::json!({"s":{"url":"https://example.com/mcp","pin":{"mechanism":"unpinned"},
            "tools_allow":{"t":{"input_schema":{"properties":{"target":{"x-mcp-header":annotation}}}}}}});
        assert!(
            crate::statement::test_support::read_tools_section(section.to_string().as_bytes())
                .is_err()
        );
    }
}

// This is a compile-time assertion: adding Serialize gives each type two possible
// marker implementations, so inference fails instead of permitting a secret dump.
#[test]
fn secret_bearing_consumer_configs_cannot_serialize() {
    trait AmbiguousIfSerialize<Marker> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
    struct Serializable;
    impl<T: ?Sized + serde::Serialize> AmbiguousIfSerialize<Serializable> for T {}
    let _ = <super::ClientIdentityCfg as AmbiguousIfSerialize<_>>::check;
    let _ = <super::McpServerDefCfg as AmbiguousIfSerialize<_>>::check;
    let _ = <super::TokenExchangeCfg as AmbiguousIfSerialize<_>>::check;
    let _ = <super::ChildEnvValue as AmbiguousIfSerialize<_>>::check;
}

#[test]
fn tls_pins_refuse_plaintext_endpoints_with_their_wire_token() {
    for mechanism in ["cert_spki", "mtls"] {
        let error = grammar(json!({"fs": {
            "url": "http://127.0.0.1/mcp",
            "allow_private": true,
            "pin": {"mechanism": mechanism, "key": "AAAA"}
        }}))
        .expect_err("a TLS pin cannot authenticate a plaintext endpoint");
        assert!(
            error.contains(&format!("pin.mechanism: {mechanism}")),
            "{error}"
        );
        assert!(error.contains("no TLS handshake to verify"), "{error}");
    }
}
