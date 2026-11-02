// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP WIRE VOCABULARY, written down once: the revision string, the method names, the `_meta`

/// The discriminator on a result this node is handing over as finished.
pub const RESULT_TYPE_COMPLETE: &str = "complete";

/// `value`'s compact JSON bytes, the members a [`busbar_contract::jsonrpc`] `*_bytes` envelope
#[must_use]
pub fn json(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// The discriminator on a result that asks the caller for something first.
pub const RESULT_TYPE_INPUT_REQUIRED: &str = "input_required";

/// THE DISCOVERY PATH FOR A GIVEN MOUNT (RFC 9728: the well-known segment, then the mount).
#[must_use]
pub fn protected_resource_metadata_path(mount_path: &str) -> String {
    format!("/.well-known/oauth-protected-resource{mount_path}")
}

/// THE STATELESS REVISION: the one the plane's dispatch is written against, and the one busbar
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// Invoke a tool by name, with arguments.
pub const METHOD_TOOLS_CALL: &str = "tools/call";

/// THE `_meta` KEY CARRYING A REQUEST'S PROTOCOL VERSION (at `params._meta`).
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// THE `_meta` KEY CARRYING THE CLIENT'S CAPABILITIES FOR ONE REQUEST: required, and absent is a
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// The header mirroring the body's `method`. REQUIRED on every request.
pub const H_MCP_METHOD: &str = "mcp-method";
/// The header mirroring the target name. REQUIRED on `tools/call`, `resources/read`, `prompts/get`.
pub const H_MCP_NAME: &str = "mcp-name";
/// The header mirroring the `_meta` protocol version.
pub const H_PROTOCOL_VERSION: &str = "mcp-protocol-version";

/// The envelope was not a request. JSON-RPC standard.
pub const CODE_INVALID_REQUEST: i64 = -32600;
/// The method named is not one this node answers. JSON-RPC standard; MCP pairs it with `404`.
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;
/// The parameters were not admissible — including a missing or incomplete `params._meta`, which is
pub const CODE_INVALID_PARAMS: i64 = -32602;
/// Something on this side failed. JSON-RPC standard.
pub const CODE_INTERNAL: i64 = -32603;
/// MCP `HeaderMismatchError`: an HTTP header disagreed with the body it mirrors. Always `400`.
pub const CODE_HEADER_MISMATCH: i64 = -32020;
/// MCP `MissingRequiredClientCapability`: the caller did not declare a capability the answer would
pub const CODE_MISSING_CLIENT_CAPABILITY: i64 = -32021;
/// MCP `UnsupportedProtocolVersionError`: carries `data.requested` and `data.supported`. Always
pub const CODE_UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
/// A policy said no. The first code in JSON-RPC's implementation-defined server-error range,
pub const CODE_REFUSED: i64 = -32000;
/// The server this call would have reached could not be reached — the call NEVER HAPPENED, which
pub const CODE_UPSTREAM_UNAVAILABLE: i64 = -32030;

/// THE METHODS THIS DIALECT DISPATCHES. A method absent from here takes the `-32601` / `404` arm.
pub const IMPLEMENTED_METHODS: &[&str] = &[
    "server/discover",
    "tools/list",
    METHOD_TOOLS_CALL,
    "prompts/list",
    "prompts/get",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "completion/complete",
    "tasks/get",
    "tasks/update",
    "tasks/cancel",
    "subscriptions/listen",
];

/// WHICH `params` MEMBER CARRIES A REQUEST'S SUBJECT, for the methods that address one.
#[must_use]
pub fn name_source_of(method: &str) -> Option<&'static str> {
    match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        "tasks/get" | "tasks/update" | "tasks/cancel" => Some("taskId"),
        _ => None,
    }
}

/// The fields THIS BODY implies, by lower-case name: the `Accept` preference (a request that named
#[must_use]
pub fn mirrored(value: &serde_json::Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let meta = value.get("params").and_then(|p| p.get("_meta"));
    let wants_stream = meta.is_some_and(|m| {
        m.get(crate::framing::META_LOGGING_LEVEL).is_some()
            || m.get("progressToken").is_some_and(|t| !t.is_null())
    });
    out.push((
        "accept".to_string(),
        if wants_stream {
            "text/event-stream, application/json"
        } else {
            "application/json, text/event-stream"
        }
        .to_string(),
    ));
    if let Some(method) = value.get("method").and_then(serde_json::Value::as_str) {
        out.push((
            H_MCP_METHOD.to_string(),
            crate::client::jsonrpc::encode_sentinel(method),
        ));
        if let Some(name) = name_source_of(method)
            .and_then(|source| value.get("params").and_then(|p| p.get(source)))
            .and_then(serde_json::Value::as_str)
        {
            out.push((
                H_MCP_NAME.to_string(),
                crate::client::jsonrpc::encode_sentinel(name),
            ));
        }
    }
    if let Some(version) = meta
        .and_then(|m| m.get(META_PROTOCOL_VERSION))
        .and_then(serde_json::Value::as_str)
        .filter(|v| !v.is_empty())
    {
        out.push((H_PROTOCOL_VERSION.to_string(), version.to_string()));
    }
    out
}

#[cfg(test)]
#[path = "tests/codec_tests.rs"]
mod codec_tests;
