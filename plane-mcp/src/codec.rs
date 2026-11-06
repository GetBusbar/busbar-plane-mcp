// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP WIRE VOCABULARY, written down once: the revision string, the method names, the `_meta`
//! keys, the mirror headers and the JSON-RPC error code table.

#[path = "wire_json.rs"]
pub(crate) mod wire_json;

/// The discriminator on a result this node is handing over as finished.
pub const RESULT_TYPE_COMPLETE: &str = "complete";

/// `value`'s compact JSON bytes, the members a [`busbar_contract::jsonrpc`] `*_bytes` envelope
/// splices in.
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
/// speaks to an upstream first.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// Invoke a tool by name, with arguments.
pub const METHOD_TOOLS_CALL: &str = "tools/call";

/// THE `_meta` KEY CARRYING A REQUEST'S PROTOCOL VERSION (at `params._meta`).
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// THE `_meta` KEY CARRYING THE CLIENT'S CAPABILITIES FOR ONE REQUEST: required, and absent is a
/// refusal rather than the empty capability set.
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// The header mirroring the body's `method`. REQUIRED on every request.
pub const H_MCP_METHOD: &str = "mcp-method";
/// The header mirroring the target name on methods selected by [`name_source_of`], including task verbs.
pub const H_MCP_NAME: &str = "mcp-name";
/// The header mirroring the `_meta` protocol version.
pub const H_PROTOCOL_VERSION: &str = "mcp-protocol-version";

/// The envelope was not a request. JSON-RPC standard.
pub const CODE_INVALID_REQUEST: i64 = -32600;
/// The method named is not one this node answers. JSON-RPC standard; MCP pairs it with `404`.
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;
/// The parameters were not admissible — including a missing or incomplete `params._meta`, which is
/// a member of `params` and so is the standard "invalid params" rather than a header defect.
pub const CODE_INVALID_PARAMS: i64 = -32602;
/// Something on this side failed. JSON-RPC standard.
pub const CODE_INTERNAL: i64 = -32603;
/// MCP `HeaderMismatchError`: an HTTP header disagreed with the body it mirrors. Always `400`.
pub const CODE_HEADER_MISMATCH: i64 = -32020;
/// MCP `MissingRequiredClientCapability`: the caller did not declare a capability the answer would
/// have needed.
pub const CODE_MISSING_CLIENT_CAPABILITY: i64 = -32021;
/// MCP `UnsupportedProtocolVersionError`: carries `data.requested` and `data.supported`. Always
/// `400`.
pub const CODE_UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
/// A policy said no. The first code in JSON-RPC's implementation-defined server-error range,
/// because every reserved code is wrong for a specific reason.
pub const CODE_REFUSED: i64 = -32000;
/// The server this call would have reached could not be reached — the call NEVER HAPPENED, which
/// is why it is an extension rather than `-32603` (busbar broke) or `-32602` (the caller erred).
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
///
/// Read in both directions (the server validates the `Mcp-Name` mirror, the client composes it).
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
/// a logging level or a progress token asked for the frames only a stream carries), the method,
/// the target name where the method has one, and the protocol version its `_meta` states.
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

/// The JSON wire length without allocating a second encoded document.
pub(crate) fn json_len(value: &impl serde::Serialize) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("JSON length overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    if serde_json::to_writer(&mut counter, value).is_err() {
        usize::MAX
    } else {
        counter.0
    }
}

#[cfg(test)]
#[path = "tests/wire_json.rs"]
mod wire_json_tests;
