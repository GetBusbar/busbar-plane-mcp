// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S DOOR, its declarations: what the plane states once in its Statement tail, what

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, EGRESS_PROVIDER, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob};
use busbar_contract::abi::mechanism::door::{Section, SECTION_DECLARING, SECTION_SELECTS};
use busbar_contract::abi::plane::{
    AdminRoute, BillableClass, OpClass, PinMechanism, PlaneTail, RecordChain, RecordRetention,
    TrustKey, ANSWER_LAYOUT, CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED, INGRESS_REQUEST_RESPONSE,
    INGRESS_RESPONSE_STREAM, MECHANISM_PEER_KEY, MECHANISM_ROOT, SHAPE_PIECEWISE, TRUST_PIN,
    TRUST_PRIVATE_REACH, TRUST_REVERIFY_TTL,
};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::plane::dealt_section;
use busbar_contract::abi::sdk::publish::{
    admin_route, class_index, record_retention, AdminRouteSpec, ServedRoute, SnapshotSpec,
};
use busbar_contract::records::Retention;

use crate::tool_claims::{
    CARRIER_HTTP, CARRIER_SSE, CARRIER_STDIO, DEFAULT_METADATA, DEFAULT_MOUNT, TASK_RUN_MOUNT,
};
use crate::tools_config::{ToolsCfg, DEFAULT_MCP_VERIFY_TTL, SUBJECT_NOUN};

/// The grant kind that admits traffic on this plane: one registered server.
pub const SCOPE: &str = "mcp_server";
/// The second grant kind: one tool of a registered server, keyed on its published name.
pub const SCOPE_TOOL: &str = "mcp_tool";
/// The section this plane owns beside `tools:`: its endpoint block.
pub const ENDPOINT_SECTION: &str = "mcp";

/// The fee unit this plane declares: one per request.
pub const FEE_PER_REQUEST: &str = busbar_contract::plane::PER_REQUEST;

/// THE SECTIONS THE PLANE'S STATEMENT DECLARES: `tools:`, which it owns and judges, and its endpoint
pub const SECTIONS: &[Section] = &[
    Section {
        name: abi_str("tools"),
        flags: SECTION_DECLARING,
        ..Section::ZERO
    },
    Section {
        name: abi_str("mcp"),
        flags: SECTION_SELECTS,
        ..Section::ZERO
    },
];

/// WHERE EACH REGISTERED SERVER'S CLIENT IDENTITY IS WRITTEN, as a member path (`settings.*.<key>`,
pub const CLIENT_IDENTITY_FROM: &str = "settings.*.client_identity";

/// THE SECRET REFERENCES ITS SECTION HOLDS, by settings path (`*` = every registration, every
pub const SECRET_REFS: &[AbiStr] = &[
    abi_str("settings.*.token_exchange.subject_token"),
    abi_str("settings.*.env.*"),
    abi_str("settings.*.client_identity.cert"),
    abi_str("settings.*.client_identity.key"),
];

/// The far end's response fields the plane reads: the answer's media type (a JSON document or an
pub const KEEP_RESPONSE_HEADERS: &[AbiStr] = &[
    abi_str(crate::framing::CONTENT_TYPE),
    abi_str(crate::adapt::H_SESSION_ID),
];

/// The index of [`NEEDS`]' first need: the relayed calls to the registered servers reached at a URL.
pub const NEED_UPSTREAM: u32 = 0;

/// The index of [`NEEDS`]' second need: the `transport: stdio` registrations, each a PROGRAM the
pub const NEED_PROGRAM: u32 = 1;

/// Host-generated launch fields retained on the program need's first successful lease head.
pub const KEEP_PROGRAM_HEADERS: &[AbiStr] = &[
    abi_str(busbar_contract::conn::PROGRAM_GENERATION_FIELD),
    abi_str(busbar_contract::conn::PROGRAM_INSTANCE_FIELD),
    abi_str(busbar_contract::conn::PROGRAM_IDENTITY_FIELD),
];

/// THE PLANE'S CONNECTION NEEDS: outbound over http to the servers the operator registered at a URL,
pub const NEEDS: &[Need] = &[
    {
        let mut n = Need::EMPTY.with_keep_response_headers(KEEP_RESPONSE_HEADERS);
        n.direction = DIRECTION_OUTBOUND;
        n.egress_class = EGRESS_PROVIDER;
        n.transport = abi_str(CARRIER_HTTP);

        n.target_from = abi_str("settings.*.url");

        n.trust_from = abi_str(CLIENT_IDENTITY_FROM);
        n.keep_mode = KEEP_NAMED;
        n
    },
    {
        let mut n = Need::EMPTY.with_keep_response_headers(KEEP_PROGRAM_HEADERS);
        n.direction = DIRECTION_OUTBOUND;
        n.egress_class = EGRESS_OPERATOR_INFRASTRUCTURE;
        n.transport = abi_str(CARRIER_STDIO);

        n.target_from = abi_str(busbar_contract::section::MEMBER_PROGRAM);
        n.keep_mode = KEEP_NAMED;
        n
    },
];

/// The one wire dialect: JSON-RPC 2.0, carried over each of the plane's transports.
const DIALECTS: &[AbiStr] = &[abi_str("jsonrpc")];

const SCOPE_KINDS: &[AbiStr] = &[abi_str(SCOPE), abi_str(SCOPE_TOOL)];

const BILLABLE_CLASSES: &[BillableClass] = &[
    BillableClass {
        class: abi_str(crate::tool_meta::CLASS_TOOL_CALLS.as_str()),
        family: abi_str("count"),
    },
    BillableClass {
        class: abi_str(crate::tool_meta::CLASS_BYTES.as_str()),
        family: abi_str("byte"),
    },
    BillableClass {
        class: abi_str(FEE_PER_REQUEST),

        family: abi_str("count"),
    },
];

/// The tail index of the fee unit's class in [`BILLABLE_CLASSES`].
pub const CLASS_FEE_INDEX: u32 = 2;

const FEE_UNITS: &[AbiStr] = &[abi_str(FEE_PER_REQUEST)];

const RECORD_KINDS: &[AbiStr] = &[
    abi_str(crate::tool_records::KIND_CALL),
    abi_str(crate::tool_records::KIND_DEMOTION),
    abi_str(crate::tool_records::KIND_APPROVAL),
    abi_str(crate::tool_records::KIND_TASK),
];

/// The retention rule of each record kind that is not purged by age ([`RECORD_KINDS`] indexes): a
const RECORD_RETENTIONS: &[RecordRetention] =
    &[record_retention(RECORD_TASK, Retention::TerminalOnly)];

/// The index of the call record's kind in [`RECORD_KINDS`].
pub const RECORD_CALL: u32 = 0;

/// The index of the task kind in [`RECORD_KINDS`]: a task's result chunks are written under it.
pub const RECORD_TASK: u32 = 3;

/// THE CALL LOG IS A CHAIN: each caller's call records are hash-chained by the host, the prelude
const RECORD_CHAINS: &[RecordChain] = &[RecordChain {
    kind: RECORD_CALL,
    framing: CHAIN_LENGTH_PREFIXED,
    flags: CHAIN_DIGESTS_SCOPE,
    _reserved: 0,
}];

/// `cert_spki` and `mtls` seal a peer key into the member route. `local_program` instead verifies
const PIN_MECHANISMS: &[PinMechanism] = &[
    PinMechanism {
        token: abi_str("pinned_pubkey"),
        flags: 0,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("cert_spki"),
        flags: MECHANISM_ROOT | MECHANISM_PEER_KEY,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("mtls"),
        flags: MECHANISM_ROOT | MECHANISM_PEER_KEY,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("local_program"),
        flags: MECHANISM_ROOT,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("unpinned"),
        flags: 0,
        _reserved: 0,
    },
];

/// The kernel-owned trust keys of one entry;
const TRUST_KEYS: &[TrustKey] = &[
    {
        let mut k = TrustKey::EMPTY.with_mechanisms(PIN_MECHANISMS);
        k.key = abi_str("pin");
        k.role = TRUST_PIN;
        k
    },
    {
        let mut k = TrustKey::EMPTY;
        k.key = abi_str("verify_ttl");
        k.role = TRUST_REVERIFY_TTL;
        k.default = abi_str(DEFAULT_MCP_VERIFY_TTL);
        k
    },
    {
        let mut k = TrustKey::EMPTY;
        k.key = abi_str("allow_private");
        k.role = TRUST_PRIVATE_REACH;
        k
    },
    {
        let mut k = TrustKey::EMPTY;
        k.key = abi_str(crate::tools_config::TOOL_APPROVALS_KEY);
        k.role = busbar_contract::abi::plane::TRUST_ITEM_APPROVALS;
        k.default = abi_str(crate::tools_config::TOOL_APPROVAL_FIELD);
        k
    },
];

/// The operation classes, in [`crate::tool_ops::OP_CLASSES`] order, each named by its own key.
const OP_CLASS_TABLE: &[OpClass] = &{
    const N: usize = crate::tool_ops::OP_CLASSES.len();
    let mut table = [OpClass::ZERO; N];
    let mut i = 0;
    while i < N {
        let key = abi_str(crate::tool_ops::OP_CLASSES[i].as_str());
        table[i] = OpClass { op: key, name: key };
        i += 1;
    }
    table
};

/// The tail index of an operation class, where the table holds it (the SDK's one index rule,
#[must_use]
pub fn op_class_index(op: busbar_contract::ids::OpClassId) -> Option<u32> {
    class_index(crate::tool_ops::OP_CLASSES, op)
}

/// The status of a verb the endpoint does not serve for the request as it came: a GET or DELETE
pub const STATUS_METHOD_NOT_ALLOWED: u32 = 405;

/// The body of a GET or DELETE the endpoint does not serve: what each revision opens instead.
#[must_use]
pub fn method_not_allowed_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": "method_not_allowed",
        "error_description":
            "A GET or DELETE here must name an MCP session (Mcp-Session-Id). MCP 2026-07-28 is \
             POST only; 2025-11-25 and 2025-06-18 open a session with a POSTed `initialize`; a \
             2024-11-05 client opens its event stream with a GET that accepts text/event-stream \
             and names no MCP-Protocol-Version.",
    }))
    .unwrap_or_default()
}

/// The status an arrival from a browser origin the deployment does not admit is refused with.
pub const STATUS_FORBIDDEN_ORIGIN: u32 = 403;

/// THE DNS-REBINDING REFUSAL's body (the served engine's `ForbiddenOrigin` words, as its envelope
#[must_use]
pub fn forbidden_origin_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": "invalid_origin",
        "error_description":
            "This Origin is not allowed. Browser origins must be listed in mcp.allowed_origins.",
    }))
    .unwrap_or_default()
}

/// THE BROWSER ORIGINS the deployment admits beyond loopback: the `mcp:` block's
pub fn allowed_origins(owned: &[u8]) -> Result<Vec<String>, String> {
    Ok(mcp_block(owned)?
        .map(|cfg| cfg.allowed_origins)
        .unwrap_or_default())
}

/// The `mcp:` block among the sections `owned` keys by name; `None` when it writes none.
fn mcp_block(owned: &[u8]) -> Result<Option<crate::endpoint::McpCfg>, String> {
    if owned.is_empty() {
        return Ok(None);
    }
    let value: serde_json::Value = serde_json::from_slice(owned).map_err(|e| e.to_string())?;
    value
        .get(ENDPOINT_SECTION)
        .map(|block| serde_json::from_value(block.clone()).map_err(|e| e.to_string()))
        .transpose()
}

const TAIL_VALUE: PlaneTail = {
    let mut t = PlaneTail::EMPTY
        .with_dialects(DIALECTS)
        .with_scope_kinds(SCOPE_KINDS)
        .with_op_classes(OP_CLASS_TABLE)
        .with_billable_classes(BILLABLE_CLASSES)
        .with_fee_units(FEE_UNITS)
        .with_record_kinds(RECORD_KINDS)
        .with_record_chains(RECORD_CHAINS)
        .with_trust_keys(TRUST_KEYS)
        .with_admin_routes(ADMIN_ROUTES);

    t.flags = busbar_contract::abi::plane::TAIL_HOOKS_GATED;
    t.ingress = INGRESS_REQUEST_RESPONSE | INGRESS_RESPONSE_STREAM;
    t.dispatch_shape = SHAPE_PIECEWISE;
    t.answer_layout = ANSWER_LAYOUT;
    t.scope = abi_str(SCOPE);
    t.label = abi_str("MCP");
    t.subject_noun = abi_str(SUBJECT_NOUN);

    t.admin_noun = abi_str("mcp-server");
    t.audit_kind = abi_str("mcp_server");

    t.signing_domain = abi_str("mcp/ask-state/v1");
    t.signing_kid_prefix = abi_str("busbar-mcp-ask-");
    t.cli_help = abi_str(crate::tool_meta::HELP_FLAGS);

    t.caller_credential_refusal = abi_str(crate::tools_config::REFUSE_PASSTHROUGH_SECTION);
    t.admin_openapi = Blob::json(ADMIN_OPENAPI.as_bytes());

    t.record_retentions = RECORD_RETENTIONS.as_ptr();
    t.record_retentions_len = RECORD_RETENTIONS.len();
    t
};

/// The Statement tail: the plane's static facts.
pub const TAIL: &PlaneTail = &TAIL_VALUE;

/// EVERY ROUTE THE PLANE SERVES, in the order the engine mounts them: the discovery document, the
pub const ROUTES: &[ServedRoute] = &[
    route("GET", DEFAULT_METADATA, CARRIER_HTTP, true),
    route("POST", DEFAULT_MOUNT, CARRIER_HTTP, false),
    route("GET", DEFAULT_MOUNT, CARRIER_HTTP, false),
    route("DELETE", DEFAULT_MOUNT, CARRIER_HTTP, false),
    route("POST", DEFAULT_MOUNT, CARRIER_SSE, false),
    route("POST", TASK_RUN_MOUNT, CARRIER_HTTP, false),
    route("POST", DEFAULT_MOUNT, CARRIER_STDIO, false),
];

/// One [`ROUTES`] row.
const fn route(
    verb: &'static str,
    target: &'static str,
    carrier: &'static str,
    open: bool,
) -> ServedRoute {
    ServedRoute {
        verb,
        target,
        carrier,
        open,
    }
}

/// The index of the task-run claim in [`ROUTES`].
pub const TASK_RUN_ROUTE: usize = 5;

/// The index of the line carrier's claim in [`ROUTES`].
pub const LINE_ROUTE: usize = 6;

/// The word each admin verb is audited under (`connect` reaches the operator's estate and can
pub const ADMIN_AUDIT: &[&str] = &["connect", "", ""];

/// THE TRUST VERBS' OpenAPI FRAGMENT, each path relative to the admin mount (the kernel keys it
pub const ADMIN_OPENAPI: &str = r##"{"/tools/{name}/connect":{"post":{"summary":"Fetch a registered MCP server's LIVE tool list, hash it, and record the observation. Approves nothing: adopting what was seen is a separate operator act","security":[{"adminToken":[]}],"parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"OK (the derived trust state and changes queue; a refresh that landed a quarantine is still a 200 — the drift is in the body)","content":{"application/json":{"schema":{"$ref":"#/components/schemas/McpTrustView"}}}}}}},"/tools/{name}/changes":{"get":{"summary":"The changes queue for one MCP server, derived from the LAST observation. Contacts nothing","security":[{"adminToken":[]}],"parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"OK","content":{"application/json":{"schema":{"$ref":"#/components/schemas/McpTrustView"}}}}}}},"/tools/{name}/health":{"get":{"summary":"Whether one MCP server currently serves, and why not when it does not","security":[{"adminToken":[]}],"parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"OK","content":{"application/json":{"schema":{"$ref":"#/components/schemas/McpHealthView"}}}}}}},"components":{"schemas":{"McpTrustView":{"description":"THE TRUST VIEW of one registered MCP server — `POST /tools/{name}/connect` and\n`GET /tools/{name}/changes` answer with this.","properties":{"added":{"description":"Offered now, never ruled on.","items":{"type":"string"},"type":"array"},"capabilities":{"description":"Every capability's standing status, in name order.","items":{"$ref":"#/components/schemas/McpCapabilityView"},"type":"array"},"changed":{"description":"Approved, but offered at a DIFFERENT digest. THIS IS THE RUG-PULL ROW.","items":{"type":"string"},"type":"array"},"failure":{"description":"Why the last contact failed, when it did.","type":["string","null"]},"name":{"type":"string"},"observed_tools":{"description":"How many tools the last successful observation carried.","format":"uint","minimum":0,"type":"integer"},"pin_changed":{"description":"The presented identity is not the locked one. Its own axis: adopting a new identity is a\ndifferent act from adopting new content.","type":"boolean"},"pin_mechanism":{"description":"The operator's word for the authenticity root. Never interpreted by the machine.","type":"string"},"removed":{"description":"Approved, and no longer offered.","items":{"type":"string"},"type":"array"},"state":{"description":"`pending`, `approved`, `quarantined`, `suspended` or `error`. DERIVED from the approval and\nthe last sighting on every read, so there is no stored state to go stale.","type":"string"}},"required":["name","state","pin_mechanism","pin_changed","added","changed","removed","observed_tools","failure","capabilities"],"type":"object"},"McpCapabilityView":{"description":"ONE CAPABILITY'S STANDING STATUS, the three-way answer a trust view has to render.\n\nThree and not two: `approved at a digest`, `rejected`, and `allowed but never ruled on`. The\nthird is `pending` and it is the one a queue exists to drain, so collapsing it into \"not\napproved\" would hide the operator's whole worklist.","properties":{"approved_digest":{"description":"The digest the operator approved, when there is one. A rejected or pending capability has\nnone, and reporting the last OBSERVED digest here would read as an approval.","type":["string","null"]},"status":{"description":"`approved`, `rejected` or `pending`.","type":"string"},"tool":{"description":"The bare tool name, as the upstream spells it.","type":"string"}},"required":["tool","status","approved_digest"],"type":"object"},"McpHealthView":{"description":"THE HEALTH VIEW — `GET /tools/{name}/health`. Deliberately smaller than the trust view: health\nanswers \"can busbar use this server right now, and if not why\", and a dashboard polling it should\nnot be re-rendering the whole changes queue to find out.","properties":{"contacted":{"description":"`false` until a refresh has ever landed. A server that has never been contacted is not\nunhealthy, and reporting it as such would page somebody for a declarative deployment.","type":"boolean"},"failure":{"type":["string","null"]},"name":{"type":"string"},"observed_tools":{"format":"uint","minimum":0,"type":"integer"},"serving":{"description":"Whether this server currently SERVES: `state == approved`. Named separately from `state`\nbecause it is the one bit a caller usually wants and deriving it from a word is how a client\nends up hard-coding a spelling.","type":"boolean"},"state":{"type":"string"}},"required":["name","state","serving","contacted","failure","observed_tools"],"type":"object"}}}}"##;

/// The trust verbs the plane serves on the kernel's admin mount, relative to it: `(verb, target)`.
pub const ADMIN_VERBS: &[(&str, &str)] = &[
    ("POST", "/tools/{name}/connect"),
    ("GET", "/tools/{name}/changes"),
    ("GET", "/tools/{name}/health"),
];

/// [`ADMIN_VERBS`] in the ABI's spelling, each audited under its [`ADMIN_AUDIT`] word.
pub const ADMIN_ROUTES: &[AdminRoute] = &[
    admin_route(ADMIN_VERBS[0], 0, ADMIN_AUDIT[0]),
    admin_route(ADMIN_VERBS[1], 0, ADMIN_AUDIT[1]),
    admin_route(ADMIN_VERBS[2], 0, ADMIN_AUDIT[2]),
];

/// The bare `tools:` section, as bytes (what the tests state a section as): read as `validate`,
#[cfg(test)]
pub fn read_tools_section(settings: &[u8]) -> Result<ToolsCfg, String> {
    if settings.is_empty() {
        return Ok(ToolsCfg::default());
    }
    read_tools_value(serde_json::from_slice(settings).map_err(|e| e.to_string())?)
}

/// The `tools:` section read from the value the host built. serde's words are read from a value
fn read_tools_value(section: serde_json::Value) -> Result<ToolsCfg, String> {
    let cfg = serde_json::from_value::<ToolsCfg>(section).map_err(|e| e.to_string())?;

    crate::tools_config::validate_published_names(&cfg)?;
    Ok(cfg)
}

/// ONE POOL of the section (the unified `pools:` its registrations resolved to, handed at the
/// section's reserved `pools` key): its interchangeable servers in the operator's order, the first
/// the primary, and the operations (bare tool names) it may perform twice.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolPool {
    /// The member servers, in order.
    pub members: Vec<String>,
    /// The operations a member that answered with a failure may be repeated on another member for.
    pub repeatable: Vec<String>,
}

/// `validate`: the blob stage 3g deals a plane (`{<verb>: <section>}` for each stated verb the
pub fn read_dealt_tools(settings: &[u8]) -> Result<ToolsCfg, String> {
    let cfg = match dealt_section(settings, crate::tools_config::SECTION)? {
        None => ToolsCfg::default(),
        Some(section) => read_tools_value(section)?,
    };
    judge_endpoint_block(settings)?;
    Ok(cfg)
}

/// THE `mcp:` ENDPOINT BLOCK JUDGED, among the sections `owned` keys by name, by every reader
pub fn judge_endpoint_block(owned: &[u8]) -> Result<(), String> {
    admitted_endpoint(None, owned)?;
    allowed_origins(owned)?;
    Ok(())
}

/// THE SETTINGS `open` and `refresh` are handed: the section ([`read_tools_value`]) and the pools the
pub fn read_open(
    settings: &[u8],
) -> Result<(ToolsCfg, std::collections::BTreeMap<String, ToolPool>), String> {
    if settings.is_empty() {
        return Ok((ToolsCfg::default(), std::collections::BTreeMap::new()));
    }
    let mut value: serde_json::Value =
        serde_json::from_slice(settings).map_err(|e| e.to_string())?;
    let stated = value
        .as_object_mut()
        .and_then(|m| m.remove(busbar_contract::section::RESERVED_POOLS_KEY));
    let mut pools = std::collections::BTreeMap::new();
    if let Some(stated) = stated {
        let map = stated
            .as_object()
            .ok_or("the section's pools are not a map")?;
        let list = |v: Option<&serde_json::Value>| -> Result<Vec<String>, String> {
            v.map_or(Ok(Vec::new()), |v| {
                serde_json::from_value::<Vec<String>>(v.clone()).map_err(|e| e.to_string())
            })
        };
        for (name, pool) in map {
            pools.insert(
                name.clone(),
                ToolPool {
                    members: list(pool.get(busbar_contract::section::POOL_MEMBERS_KEY))?,
                    repeatable: list(pool.get(busbar_contract::section::POOL_REPEATABLE_KEY))?,
                },
            );
        }
    }
    Ok((read_tools_value(value)?, pools))
}

/// The audience and metadata document of an endpoint mounted under the deployment's public base
#[must_use]
pub fn under_public_url(public_url: &str) -> (String, String) {
    let base = public_url.trim_end_matches('/');
    (
        format!("{base}{DEFAULT_MOUNT}"),
        format!("{base}{DEFAULT_METADATA}"),
    )
}

/// THE ENDPOINT THE PLANE STATES ITS CLAIMS UNDER : its own
pub fn admitted_endpoint(
    public_url: Option<&str>,
    owned: &[u8],
) -> Result<Option<(String, String)>, String> {
    match mcp_block(owned)? {
        Some(cfg) => {
            let resource =
                crate::endpoint::McpResource::from_cfg(&cfg).map_err(|e| e.to_string())?;
            Ok(Some((
                resource.canonical_uri().to_string(),
                resource.metadata_url().to_string(),
            )))
        }
        None => Ok(public_url.map(under_public_url)),
    }
}

/// The protected-resource facts its `mcp:` block states: its
pub fn resource_facts(owned: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let Some(cfg) = mcp_block(owned)? else {
        return Ok(None);
    };
    let resource = crate::endpoint::McpResource::from_cfg(&cfg).map_err(|e| e.to_string())?;
    Ok(Some(
        serde_json::json!({
            "authorization_servers": resource.authorization_servers(),
            "scopes_supported": resource.scopes_supported(),
        })
        .to_string()
        .into_bytes(),
    ))
}

/// One generation's snapshot under `admitted` (the endpoint's audience and metadata document,
#[must_use]
pub fn snapshot_spec_with(
    admitted: Option<(String, String)>,
    facts: Option<Vec<u8>>,
) -> SnapshotSpec {
    let (audience, resource_metadata, claims) = match admitted {
        Some((a, m)) => (
            Some(a),
            Some(m),
            ROUTES.iter().map(ServedRoute::claim_spec).collect(),
        ),
        None => (None, None, Vec::new()),
    };
    SnapshotSpec {
        claims,
        admin_routes: ADMIN_ROUTES
            .iter()
            .zip(ADMIN_VERBS)
            .zip(ADMIN_AUDIT)
            .map(|((r, (verb, target)), audit)| AdminRouteSpec {
                audit_verb: (*audit).to_string(),
                ..AdminRouteSpec::new(verb, target, r.flags)
            })
            .collect(),
        openapi: None,
        resource_facts: facts.filter(|_| audience.is_some()),
        audience,
        resource_metadata,
        listed: Vec::new(),
    }
}

#[cfg(test)]
#[path = "tests/statement.rs"]
mod tests;
