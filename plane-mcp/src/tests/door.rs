// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's declarations: the tail the loader judges, the trust keys it states against the
//! grammar's own table, the settings reader and each generation's snapshot.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::plane::check::check_tail;
use busbar_contract::abi::plane::{
    CLAIM_EXACT, CLAIM_OPEN, MECHANISM_PEER_KEY, MECHANISM_ROOT, TRUST_PIN, TRUST_PRIVATE_REACH,
    TRUST_REVERIFY_TTL,
};

use super::*;

/// A good section: one fronted server.
const GOOD: &[u8] =
    br#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;
/// A registration the grammar refuses: a server id holding the routing-key separator.
const BAD: &[u8] =
    br#"{"my_fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;

/// The plane-record kinds the tail must declare, in its index order.
const PLANE_KINDS: [&str; 4] = [
    crate::tool_records::KIND_CALL,
    crate::tool_records::KIND_DEMOTION,
    crate::tool_records::KIND_APPROVAL,
    crate::tool_records::KIND_TASK,
];

/// A tail string read back through the `&'static str` it was built from: the tail's strings are
/// constants of this crate, so a string this test knows is found by address and length.
fn text(a: AbiStr) -> String {
    if a.is_absent() {
        return String::new();
    }
    [
        "pin",
        "verify_ttl",
        "allow_private",
        crate::tools_config::TOOL_APPROVALS_KEY,
        crate::tools_config::TOOL_APPROVAL_FIELD,
        crate::tools_config::DEFAULT_MCP_VERIFY_TTL,
        "pinned_pubkey",
        "cert_spki",
        "mtls",
        "unpinned",
        crate::tool_records::KIND_CALL,
        crate::tool_records::KIND_DEMOTION,
        crate::tool_records::KIND_APPROVAL,
        crate::tool_records::KIND_TASK,
        crate::tool_meta::CLASS_TOOL_CALLS.as_str(),
        crate::tool_meta::CLASS_BYTES.as_str(),
        FEE_PER_REQUEST,
    ]
    .into_iter()
    .find(|c| c.as_ptr() == a.ptr() && c.len() == a.len())
    .expect("a tail string this test knows")
    .to_string()
}

#[test]
fn the_tail_is_one_the_loader_accepts() {
    assert_eq!(check_tail(TAIL), Ok(()));
}

/// The tail's trust keys, in judgement order, and its pin mechanisms are the grammar's own: every
/// mechanism token parses, and the three roots are exactly the mechanisms that are not `unpinned`.
#[test]
fn the_tails_trust_keys_are_the_grammars() {
    let keys: Vec<(String, u32, String)> = TRUST_KEYS
        .iter()
        .map(|k| (text(k.key), k.role, text(k.default)))
        .collect();
    assert_eq!(
        keys,
        [
            ("pin".to_string(), TRUST_PIN, String::new()),
            (
                "verify_ttl".to_string(),
                TRUST_REVERIFY_TTL,
                crate::tools_config::DEFAULT_MCP_VERIFY_TTL.to_string()
            ),
            (
                "allow_private".to_string(),
                TRUST_PRIVATE_REACH,
                String::new()
            ),
            (
                crate::tools_config::TOOL_APPROVALS_KEY.to_string(),
                busbar_contract::abi::plane::TRUST_ITEM_APPROVALS,
                crate::tools_config::TOOL_APPROVAL_FIELD.to_string()
            ),
        ]
    );
    assert_eq!(TRUST_KEYS[0].mechanisms_len(), PIN_MECHANISMS.len());
    assert_eq!(PIN_MECHANISMS.len(), 4, "every mechanism the grammar has");
    for abi in PIN_MECHANISMS {
        let token = text(abi.token);
        let parsed: crate::tools_config::ServerPinCfg =
            serde_json::from_value(serde_json::json!({ "mechanism": token }))
                .unwrap_or_else(|e| panic!("`{token}` is a grammar token: {e}"));
        assert_eq!(parsed.mechanism.token(), token);
        assert_eq!(
            abi.flags & MECHANISM_ROOT != 0,
            parsed.mechanism != crate::tools_config::McpPinMechanism::Unpinned,
            "{token}"
        );
        // `cert_spki` and `mtls` pin the far end's key, which the host seals into the member route.
        assert_eq!(
            abi.flags & MECHANISM_PEER_KEY != 0,
            matches!(
                parsed.mechanism,
                crate::tools_config::McpPinMechanism::CertSpki
                    | crate::tools_config::McpPinMechanism::ClientCertBinding
            ),
            "{token}"
        );
    }
}

/// The tail declares exactly the task kind as TerminalOnly: every other kind is purged by age.
#[test]
fn the_tail_declares_the_task_kind_as_terminal_only() {
    // Each rule's kind is read by its index from the plane's own kind list, which
    // `the_tail_names_the_planes_own_classes_and_kinds` holds equal to the tail's, entry by entry.
    let retentions: Vec<(String, u32)> = RECORD_RETENTIONS
        .iter()
        .map(|r| (PLANE_KINDS[r.kind as usize].to_string(), r.rule))
        .collect();
    assert_eq!(
        retentions,
        [(
            crate::tool_records::KIND_TASK.to_string(),
            Retention::TerminalOnly.code()
        )]
    );
    // The tail points at that table, not a copy.
    assert_eq!(TAIL.record_retentions, RECORD_RETENTIONS.as_ptr());
    assert_eq!(TAIL.record_retentions_len, RECORD_RETENTIONS.len());
}

/// The record kinds and billable classes are the plane's own symbols, stated once.
#[test]
fn the_tail_names_the_planes_own_classes_and_kinds() {
    let kinds: Vec<String> = RECORD_KINDS.iter().map(|k| text(*k)).collect();
    assert_eq!(kinds, PLANE_KINDS);
    let classes: Vec<String> = BILLABLE_CLASSES.iter().map(|c| text(c.class)).collect();
    assert_eq!(
        classes,
        [
            crate::tool_meta::CLASS_TOOL_CALLS.as_str(),
            crate::tool_meta::CLASS_BYTES.as_str(),
            FEE_PER_REQUEST,
        ]
    );
    assert_eq!(
        text(BILLABLE_CLASSES[CLASS_FEE_INDEX as usize].class),
        FEE_PER_REQUEST
    );
}

#[test]
fn an_empty_blob_is_the_empty_section() {
    assert_eq!(
        read_tools_section(b""),
        Ok(crate::tools_config::ToolsCfg::default())
    );
}

#[test]
fn a_good_section_reads_and_a_bad_one_is_refused_in_the_grammars_words() {
    let cfg = read_tools_section(GOOD).expect("one fronted server reads");
    assert_eq!(cfg.servers.len(), 1);
    let err = read_tools_section(BAD).expect_err("a separator in the id is refused");
    assert!(
        err.starts_with("`tools.my_fs`: an MCP server id may not contain `_`."),
        "{err}"
    );
}

/// With no public base there is no audience and nothing is claimed; with one, the endpoint and its
/// metadata document are absolute and every route is claimed, the discovery document open.
#[test]
fn a_generation_claims_its_routes_only_with_a_public_base() {
    let none = snapshot_spec_with(None, None);
    assert!(none.claims.is_empty());
    assert_eq!(none.audience, None);
    assert_eq!(none.admin_routes.len(), ADMIN_VERBS.len());

    let some = snapshot_spec_with(Some(under_public_url("https://gw.example/")), None);
    assert_eq!(some.audience.as_deref(), Some("https://gw.example/mcp"));
    assert_eq!(
        some.resource_metadata.as_deref(),
        Some("https://gw.example/.well-known/oauth-protected-resource/mcp")
    );
    assert_eq!(some.claims.len(), ROUTES.len());
    assert_eq!(some.claims[0].flags, CLAIM_EXACT | CLAIM_OPEN);
    assert!(some.claims[1..].iter().all(|c| c.flags == CLAIM_EXACT));
}

/// THE ENDPOINT THE CLAIMS ARE STATED UNDER (ARCHITECT Q-L3B-AUD, predev's rule): the plane's own
/// `mcp:` block when the document writes one — its canonical URI verbatim as the audience, whatever
/// the public base URL — else the public base URL; neither, nothing; a malformed block, refused in
/// its grammar's words.
#[test]
fn the_claims_are_stated_under_the_endpoint_block_else_the_public_base() {
    let owned = br#"{"mcp": {"canonical_uri": "https://Gw.Example:443/mcp", "authorization_servers": ["https://login.example"]}}"#;
    assert_eq!(
        admitted_endpoint(Some("https://other.example"), owned),
        Ok(Some((
            "https://Gw.Example:443/mcp".to_string(),
            "https://Gw.Example:443/.well-known/oauth-protected-resource/mcp".to_string()
        ))),
        "the block's canonical URI, verbatim"
    );
    assert_eq!(
        admitted_endpoint(Some("https://gw.example/"), b""),
        Ok(Some(under_public_url("https://gw.example/")))
    );
    assert_eq!(admitted_endpoint(None, b""), Ok(None));
    assert_eq!(admitted_endpoint(None, br#"{"other": {}}"#), Ok(None));
    let refused = admitted_endpoint(
        None,
        br#"{"mcp": {"canonical_uri": "https://gw.example/elsewhere", "authorization_servers": ["https://l.example"]}}"#,
    )
    .expect_err("a block naming another path is refused");
    assert!(refused.contains("only at `/mcp`"), "{refused}");
    let claimed = snapshot_spec_with(admitted_endpoint(None, owned).unwrap(), None);
    assert_eq!(
        claimed.audience.as_deref(),
        Some("https://Gw.Example:443/mcp")
    );
    assert_eq!(claimed.claims.len(), ROUTES.len());
}

/// The Statement's version is the crate's: read from the manifest, as the plane reads no build
/// environment.
#[test]
fn the_statement_version_is_the_crates() {
    let manifest = include_str!("../../Cargo.toml");
    assert!(
        manifest.contains(&format!("version = \"{}\"", crate::tool_door::VERSION)),
        "the Statement names {} and the manifest does not",
        crate::tool_door::VERSION
    );
}

/// The tail states one operation class per method row's class, in their order, and each row's
/// class is found at its own index.
#[test]
fn the_tail_states_every_operation_class() {
    assert_eq!(OP_CLASS_TABLE.len(), crate::tool_ops::OP_CLASSES.len());
    for (i, op) in crate::tool_ops::OP_CLASSES.iter().enumerate() {
        assert_eq!(op_class_index(*op), Some(i as u32));
        let abi = OP_CLASS_TABLE[i].op;
        assert_eq!(
            (abi.ptr(), abi.len()),
            (op.as_str().as_ptr(), op.as_str().len())
        );
    }
    assert_eq!(TAIL.op_classes_len(), OP_CLASS_TABLE.len());
}

/// THE DNS-REBINDING ALLOWLIST is the `mcp:` block's `allowed_origins` (none without a block), and
/// the refusal is the served engine's words: an OAuth-style `invalid_origin` object.
#[test]
fn the_admitted_origins_are_the_blocks_and_the_refusal_is_the_served_words() {
    assert_eq!(allowed_origins(b""), Ok(Vec::new()));
    let owned = br#"{"mcp":{"canonical_uri":"https://gw.example/mcp","allowed_origins":["https://app.example"]}}"#;
    assert_eq!(
        allowed_origins(owned),
        Ok(vec!["https://app.example".to_string()])
    );
    let body: serde_json::Value =
        serde_json::from_slice(&forbidden_origin_body()).expect("a JSON object");
    assert_eq!(
        body,
        serde_json::json!({
            "error": "invalid_origin",
            "error_description":
                "This Origin is not allowed. Browser origins must be listed in mcp.allowed_origins.",
        })
    );
    assert_eq!(STATUS_FORBIDDEN_ORIGIN, 403);
}

/// THE ADMIN OPENAPI BLOB CARRIES ITS OWN BODIES (ARCHITECT Q2): every admin verb's `200` names a
/// typed body by `$ref`, and every `$ref` in the blob, its schemas' included, names a schema the
/// blob's `components.schemas` states. The schemas' bytes are held to the committed admin document
/// by the admin crate's drift test.
#[test]
fn the_admin_openapi_blob_states_every_body_its_verbs_name() {
    fn refs(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(r) = m.get("$ref").and_then(|r| r.as_str()) {
                    out.push(r.to_string());
                }
                m.values().for_each(|v| refs(v, out));
            }
            serde_json::Value::Array(a) => a.iter().for_each(|v| refs(v, out)),
            _ => {}
        }
    }
    let blob: serde_json::Value = serde_json::from_str(ADMIN_OPENAPI).expect("a JSON object");
    let schemas = blob["components"]["schemas"]
        .as_object()
        .expect("the blob states its schemas");
    for (verb, target) in ADMIN_VERBS {
        let op = &blob[*target][verb.to_ascii_lowercase()];
        let body = &op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"];
        assert!(body.is_string(), "{verb} {target} names no typed body");
    }
    let mut named = Vec::new();
    refs(&blob, &mut named);
    for r in &named {
        let name = r
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("`{r}` is no component reference"));
        assert!(schemas.contains_key(name), "`{r}` names no stated schema");
    }
    for name in schemas.keys() {
        assert!(
            named.iter().any(|r| r.ends_with(&format!("/{name}"))),
            "the blob states `{name}` and nothing names it"
        );
    }
}

/// `validate` reads the blob stage 3g deals a plane (`{tools: <section>, mcp: <endpoint>}`): the
/// `tools:` section inside it is judged; a blob that writes no `tools:` is the empty section; the
/// endpoint block beside it is not this reader's to judge.
#[test]
fn validate_reads_the_dealt_blob_at_its_tools_section() {
    use crate::door::read_dealt_tools;
    let empty = crate::tools_config::ToolsCfg::default();
    assert_eq!(read_dealt_tools(b""), Ok(empty.clone()));
    assert_eq!(read_dealt_tools(br#"{"mcp":{}}"#), Ok(empty));
    let mut dealt = br#"{"tools":"#.to_vec();
    dealt.extend_from_slice(GOOD);
    dealt.push(b'}');
    assert_eq!(
        read_dealt_tools(&dealt).expect("the dealt section reads"),
        read_tools_section(GOOD).expect("the bare section reads")
    );
    let mut bad = br#"{"tools":"#.to_vec();
    bad.extend_from_slice(BAD);
    bad.push(b'}');
    assert!(read_dealt_tools(&bad).is_err());
    assert!(read_dealt_tools(b"[]").is_err());
}

/// THE TASK-RUN ROUTE is a closed, exact route over the http carrier at its own path.
#[test]
fn the_task_run_route_is_closed_and_exact() {
    let route = &ROUTES[crate::door::TASK_RUN_ROUTE];
    assert_eq!(route.target, crate::tool_claims::TASK_RUN_MOUNT);
    assert_eq!(route.carrier, crate::tool_claims::CARRIER_HTTP);
    assert!(!route.open);
    assert_eq!(route.claim_flags() & CLAIM_EXACT, CLAIM_EXACT);
}

/// THE CALL LOG CANNOT BE REWRITTEN: the call kind is the one record chain the door declares, so
/// the host hash-chains every call record (its prelude length-prefixed, the scope in the digest)
/// and a record whose middle is replaced breaks the chain. This is what production declares; no
/// operation table of the plane's own stands in for it.
#[test]
fn the_call_log_is_the_one_chain_the_host_keeps() {
    assert_eq!(RECORD_CHAINS.len(), 1);
    let chain = RECORD_CHAINS[0];
    assert_eq!(chain.kind, RECORD_CALL);
    assert_eq!(chain.framing, CHAIN_LENGTH_PREFIXED);
    assert_eq!(chain.flags, CHAIN_DIGESTS_SCOPE);
    let kind = RECORD_KINDS[RECORD_CALL as usize];
    assert_eq!(text(kind), crate::tool_records::KIND_CALL);
}

/// B2: A SETTINGS REFUSAL NAMES NO POSITION IN THE HOST-BUILT BLOB. The plane reads its section
/// from JSON the host built, never from text the operator wrote, so serde's words are read from a
/// value (as the SDK's `settings_as` reads them) and name no `line`/`column`: core's refusal names
/// the operator's own position after them. A `tools:` written as a list or a scalar is refused by
/// serde_json's own reader, which is where a position was named: at validate (the dealt blob), and
/// at open and refresh (the section and the pools beside it).
#[test]
fn a_settings_refusal_names_no_position_in_the_host_built_blob() {
    for dealt in [&br#"{"tools":[1]}"#[..], br#"{"tools":"x"}"#] {
        let refused = crate::door::read_dealt_tools(dealt).expect_err("a section that is no map");
        assert!(refused.starts_with("invalid type: "), "{refused}");
        assert!(!refused.contains(" at line "), "validate: {refused}");
    }
    for section in [&b"[1]"[..], br#""x""#] {
        let refused = crate::door::read_open(section).expect_err("a section that is no map");
        assert!(refused.starts_with("invalid type: "), "{refused}");
        assert!(!refused.contains(" at line "), "open/refresh: {refused}");
        let refused = read_tools_section(section).expect_err("a section that is no map");
        assert!(
            !refused.contains(" at line "),
            "the section reader: {refused}"
        );
    }
    let typo = br#"{"tools":{"fs":{"url":"https://fs.example/mcp","pin":{"mechanism":"unpinned"},"bogus":1}}}"#;
    let refused = crate::door::read_dealt_tools(typo).expect_err("an unknown key is refused");
    assert!(refused.starts_with("unknown field `bogus`"), "{refused}");
    assert!(!refused.contains(" at line "), "{refused}");
}
