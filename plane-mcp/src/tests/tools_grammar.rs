// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tools:` GRAMMAR'S TYPED READING — the half of the composition root's registry-row battery
//! (`crates/busbar/src/root/tests/linked_tools.rs`) that needs the plane's own types: what the
//! section's custom `Deserialize` reads a document INTO (the values, the pin mechanisms and their
//! root-ness, the deny-by-default grants, the ask lists), the published-name invariant
//! (`validate_published_names`, read off the built `Catalogue`) and the Statement facts the root
//! side reads the plane's words from. The root half judges the same documents through the kernel
//! and the folded row (boot's Ok/Err and its words); this half says what an accepted document
//! means.
//!
//! Every document here goes through `serde_json` into `ToolsCfg` — the carriage the door itself
//! reads its settings by (`door::read_tools_section`) — rather than constructing the struct, because
//! the thing under test IS the grammar: a test that built `McpServerDefCfg` directly would skip the
//! custom `Deserialize` where the reserved keys, the section knobs and the value rules all live.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::SECTION_DECLARING;
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
    crate::door::read_tools_section(&serde_json::to_vec(section).expect("a section serialises"))
}

/// An ABSOLUTE program path AS THIS PLATFORM SPELLS ONE (the check is `Path::is_absolute`; see the
/// root battery's `ABS_PROGRAM` for why a hardcoded unix spelling would pass on the wrong assertion
/// on Windows). Unquoted here: a JSON string carries the backslashes byte for byte. Chosen by
/// `cfg!` rather than a `#[cfg]` item: this crate compiles every item one way (`tests/invariance.rs`).
const ABS_PROGRAM: &str = if cfg!(windows) {
    r"C:\Windows\System32\cmd.exe"
} else {
    "/bin/true"
};

/// THE LOCKED SECTION SHAPE, verbatim: the section knobs, the object pin, the `tools_allow` MAP,
/// the per-server credential mode and the bare-name hook attach. The same document the root
/// battery's `LOCKED_EXAMPLE` writes in YAML.
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
    // THE MAP, not a list: `read_file` has a SLOT, and it is empty, which is "allowed, no hash
    // approved yet". A list could not have expressed the slot at all.
    assert!(fs.tools_allow.contains_key("read_file"));
    assert_eq!(fs.tools_allow["read_file"].schema_hash, None);
    // The two attach lists the kernel's `attach_list` merges (the root battery's half): the
    // section's and the server's own, each read as written.
    assert_eq!(
        fs.hooks,
        vec!["tool-sanitizer".to_string(), "dispatch-order".to_string()]
    );
    // SCALAR ⇒ OVERRIDE.
    assert_eq!(
        cfg.effective_upstream_credentials("filesystem"),
        Some(busbar_contract::config::UpstreamCreds::Own)
    );
    door_validate(&locked_example()).expect("the door's validate accepts it");
}

/// THE SEPARATOR RULE, the grammar's half: a server id carrying the separator is refused and a tool
/// name carrying it is not, and the arithmetic that makes the server-id rule necessary.
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

    // THE COLLISION the server-id rule prevents, stated as the arithmetic it is. `a_b` + `c` and
    // `a` + `b_c` render the SAME grant value; with `a_b` unregistrable, only one of the two pairs
    // can exist, and the key splits exactly one way at the FIRST separator.
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

/// DENY-BY-DEFAULT is the `Default` impl, not a rule written down somewhere else and remembered at
/// each call site. A registry entry that names no grants grants nothing.
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
    // And a granted one is granted, so the default is a default and not a hardcoded refusal.
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

/// `tools.<server>.sampling_bounds` (owner ruling Q22c): omitted ⇒ the shipped defaults; written ⇒
/// read as written, round-tripping through the serialised form; a typo'd key fails; zero
/// `max_messages`/`max_prompt_bytes` and an inverted temperature range are refused naming the key.
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
    let def = &written.servers["s"];
    let again: crate::tools_config::McpServerDefCfg =
        serde_json::from_value(serde_json::to_value(def).expect("serialises"))
            .expect("round trips");
    assert_eq!(again.sampling_bounds, b);
    assert_eq!(&again, def);
    let plain = serde_json::to_value(&omitted.servers["s"]).expect("serialises");
    assert!(
        plain.get("sampling_bounds").is_none(),
        "an all-default block is not written back"
    );

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

/// BOTH TRANSPORTS BOOT, the typed half: a stdio registration carries its command and arguments and
/// no url (the root battery asserts boot accepts both).
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

// ── `publish_as` — the OPTIONAL wire-name override, and the invariant it moves ───────────────────
//
// `{server}_{tool}` protects one property: ONE PUBLISHED NAME RESOLVES TO EXACTLY ONE
// `(server, tool)`. Today it holds by construction. With an override it holds by
// `validate_published_names`, and these tests are what say so — including the case a naive
// implementation misses, which is an override colliding with a name NOBODY TYPED.

/// Every name the catalogue would PUBLISH for `cfg`, sorted — read off the built snapshot (the
/// plane's own catalogue, the one its door serves `tools/list` from) rather than recomputed from
/// the config, so a test cannot agree with a formula the catalogue no longer uses. Asked with every
/// grant admitted: these tests are about which NAMES are published, not who may see them.
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

/// THE DEFAULT IS UNCHANGED, and this is the test that has to keep passing forever: a config that
/// writes no `publish_as:` publishes exactly what it published before the field existed. No
/// migration, no grant to re-audit.
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

/// The override is READ, and it is the name the CATALOGUE publishes — which is the same string
/// `tools/call` dispatches on and an `mcp_tool:` grant names.
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
    // ONE name, not two: the override REPLACES the default rather than aliasing it. Two names for
    // one tool would mean an `mcp_tool:` grant on one of them silently missing the other, and the
    // uniqueness check would then be validating a set that is not what is published.
    assert_eq!(
        all.len(),
        1,
        "the override replaces the default; it does not alias it"
    );
    assert_eq!(all[0].namespaced, "greet");
    assert_eq!(all[0].server, "github");
    assert_eq!(all[0].tool, "greet");
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
    // BOTH sides named, because the operator has to know which two lines to look at.
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

/// RED 2 — THE SUBTLE CASE, and the reason the check is against the WHOLE PUBLISHED SET rather than
/// override-against-override.
///
/// `publish_as: foo_bar` collides with server `foo`'s tool `bar`, which namespaces to `foo_bar`.
/// NOBODY TYPED `foo_bar` on the `foo` side — it is a name the default MECHANISM produced — so an
/// implementation that compared overrides only to each other finds nothing to compare against,
/// accepts this config, and lets one wire name resolve to two `(server, tool)` pairs. Because
/// `catalogue::granted` keys the `mcp_tool` grant on the published name, that is one grant silently
/// authorizing two upstreams.
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
    // The DEFAULT side is described as the default, not as a `publish_as:` the operator can go and
    // delete — it is a name nothing typed.
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

/// The same collision in the OTHER declaration order. Config order must not decide whether a
/// config boots: an operator who reorders two server blocks has changed nothing.
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

/// An override that spells the namespaced default is NOT a collision — it publishes the same one
/// name the default would have. Refusing it would refuse a config that changes nothing.
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

/// The three legal ask methods parse into a three-entry round, read as written: the rule refuses
/// typos, not asks (the refusals themselves are the root battery's, at boot).
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

/// Whether `stated` is the tail string built from `word` (the tail's strings are constants of this
/// crate, so a word is found by address and length, as `tests/door.rs` reads them).
fn spells(stated: AbiStr, word: &str) -> bool {
    stated.ptr() == word.as_ptr() && stated.len() == word.len()
}

/// THE WORDS THE ROOT BATTERY READS OFF THE STATEMENT ARE THE GRAMMAR'S: the declaring section is
/// `SECTION`, the owned one the endpoint block, the subject noun `SUBJECT_NOUN`; and the endpoint's
/// fixed mount and
/// its RFC 9728 document are spelled from the endpoint block's name (so the root may build them from
/// the section the Statement owns).
#[test]
fn the_statement_names_the_grammars_section_noun_and_endpoint() {
    let sections = crate::door::SECTIONS;
    assert_eq!(sections.len(), 2);
    assert!(spells(sections[0].name, SECTION), "the declaring section");
    assert_ne!(sections[0].flags & SECTION_DECLARING, 0);
    assert!(
        spells(sections[1].name, crate::door::ENDPOINT_SECTION),
        "the owned endpoint block"
    );
    assert_eq!(sections[1].flags & SECTION_DECLARING, 0);
    assert!(spells(crate::door::TAIL.subject_noun, SUBJECT_NOUN));
    assert_eq!(
        crate::tool_claims::DEFAULT_MOUNT,
        format!("/{}", crate::door::ENDPOINT_SECTION)
    );
    assert_eq!(
        crate::tool_claims::DEFAULT_METADATA,
        format!(
            "/.well-known/oauth-protected-resource/{}",
            crate::door::ENDPOINT_SECTION
        )
    );
    assert_eq!(crate::door::TAIL.dialects_len(), 1, "one wire dialect");
}

/// RED (ARCHITECT timeout ruling): a server's `timeout:` is the kernel's reserved per-entry key, and
/// the door reads it — through the kernel's one reading — as the budget of the tool-list fetches it
/// makes itself: `10s` is 10 000 ms; a server that writes none gets the documented `30s`
/// (`docs/mcp.md`). One owner judges it: the door does not refuse a value the kernel refuses (a
/// zero), it never sees one at load.
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
        door_validate(&json!({ "zero": server(json!({ "timeout": "0s" })) })).is_ok(),
        "the zero timeout is the kernel's to refuse, not the door's"
    );
}

/// EVERY CAPABILITY'S PUBLISHED NAME IS IN THE ONE SET. A prompt, a resource and a template are
/// published under `{server}_{name}` and admitted by an `mcp_tool:` grant on that name, exactly as a
/// tool is: a tool published as `bar_greet` on `foo` and the prompt `greet` on `bar` would make one
/// `mcp_tool: bar_greet` grant admit both. RED on a check that walked `tools_allow` alone.
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

/// EVERY PIN OF THE FAR END'S KEY IS A PEER-KEY PIN. The host seals a registration's pin into its
/// member route only under a mechanism declared `peer_key`, and the connector enforces only what is
/// sealed: RED on the grammar that declared `cert_spki` and `mtls` `peer_key: false`.
/// `pinned_pubkey` stays a root whose key is a manifest issuer's (predev's posture).
#[test]
fn every_far_end_pin_mechanism_is_declared_a_peer_key_pin() {
    let roots: Vec<&str> = TRUST_KEYS[0]
        .mechanisms
        .iter()
        .filter(|m| m.root)
        .map(|m| m.token)
        .collect();
    assert_eq!(roots, ["pinned_pubkey", "cert_spki", "mtls"]);
    let peer: Vec<&str> = TRUST_KEYS[0]
        .mechanisms
        .iter()
        .filter(|m| m.peer_key)
        .map(|m| m.token)
        .collect();
    assert_eq!(
        peer,
        ["cert_spki", "mtls"],
        "the two pins of the far end's key are sealed and enforced; a manifest issuer's key is not \
         the far end's"
    );
}

/// `mtls` NEEDS A CLIENT IDENTITY: a registration that says its server is behind mutual TLS and
/// names nothing to present is refused at boot, not at the server's handshake.
#[test]
fn mtls_without_a_client_identity_is_refused_and_with_one_reads() {
    let identity = json!({
        "cert": { "env": "MCP_CLIENT_CERT" },
        "key": { "env": "MCP_CLIENT_KEY" }
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

    // Optional under the other roots: a server may ask for a client certificate whatever its pin.
    grammar(json!({
        "fs": {
            "url": "https://fs/",
            "pin": { "mechanism": "cert_spki", "key": "AAAA" },
            "client_identity": identity
        }
    }))
    .expect("an identity beside a cert_spki pin reads");
}

/// A client certificate is a TLS-handshake object: refused where there is no handshake, on an
/// `http://` url and on `transport: stdio`.
#[test]
fn a_client_identity_with_no_handshake_to_present_it_in_is_refused() {
    let identity = json!({ "cert": { "env": "C" }, "key": { "env": "K" } });
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

/// THE CANARY a credential-echo test plants: bytes that may appear in a config and must appear in
/// no refusal, error or `Debug` rendering of it.
const CANARY: &str = "CANARY-plane-mcp-echo-7f3a91";

/// One registration read straight into its typed definition, then judged by [`validate_server`],
/// the function boot and the admin write path both call. The refusal it answers is what reaches
/// `busbar --validate`'s stderr and the read-only admin dry-run validate endpoint.
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

/// A `url:` refused for its scheme names the URL it refused, WITHOUT the userinfo an operator put
/// in it: the refusal reaches stderr and the read-only admin validate endpoint, so a password in
/// the URL would be handed to anyone who can read either.
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
        err.contains(
            "`url:` must be an http:// or https:// endpoint, got `ftp://***@tools.internal/mcp`"
        ),
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
            "subject_token": { "env": "BUSBAR_SUBJECT" },
        },
    }));
    assert!(
        !err.contains(CANARY),
        "the refusal echoes the credential: {err}"
    );
    assert!(
        err.contains("Got `http://***@auth.example.com/token`."),
        "the refusal keeps its words and the rest of the URL: {err}"
    );
}

/// A URL with no userinfo is echoed byte for byte: masking removes credential bytes and nothing
/// else, so every refusal that never carried a credential reads exactly as it did.
#[test]
fn a_refused_url_without_userinfo_is_echoed_verbatim() {
    let err = refusal_of(json!({ "url": "ftp://tools.internal/a@b?c=d@e" }));
    assert!(
        err.ends_with(
            "`url:` must be an http:// or https:// endpoint, got `ftp://tools.internal/a@b?c=d@e`"
        ),
        "{err}"
    );
    for (raw, shown) in [
        ("https://h/p", "https://h/p"),
        ("u:p@h/x", "***@h/x"),
        ("https://u@h", "https://***@h"),
        ("https://a@b@h:1/x?q#f", "https://***@h:1/x?q#f"),
        ("x/y?r=https://u:p@h", "x/y?r=https://u:p@h"),
        ("u:p@h?r=https://x", "***@h?r=https://x"),
        ("", ""),
    ] {
        assert_eq!(super::url_for_display(raw), shown, "{raw}");
    }
}

/// A stdio child's `env:` literal is not printed by `Debug`: a value an operator pasted there may
/// be the credential the secret-reference arm exists to keep out of the config, and `Debug` is
/// what a log line or a panic message renders.
#[test]
fn a_child_env_literal_is_not_printed_by_debug() {
    let plain = super::ChildEnvValue::Plain(CANARY.to_string());
    let shown = format!("{plain:?}");
    assert!(!shown.contains(CANARY), "{shown}");
    assert_eq!(shown, "Plain(<redacted>)");
}
