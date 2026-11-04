// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STATELESS REVISION'S ENVELOPE CHECKS: `params._meta` and its required members, the mirrored
//! request fields, and the revision the request names.

use serde_json::Value;

use crate::codec::{
    name_source_of, CODE_HEADER_MISMATCH, CODE_INVALID_PARAMS, CODE_UNSUPPORTED_PROTOCOL_VERSION,
    H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION, META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};

/// The revisions the STATELESS dispatch serves, as `data.supported` names them: the revision a
/// request's own `_meta` may name.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[PROTOCOL_VERSION];

/// The status every refusal here is answered with.
pub const STATUS: u32 = 400;

/// One refusal: its code, its sentence and its `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The JSON-RPC error code.
    pub code: i64,
    /// The sentence.
    pub message: &'static str,
    /// The `data` member, where the refusal carries one.
    pub data: Option<Value>,
}

impl Refused {
    fn invalid_params(message: &'static str) -> Self {
        Refused {
            code: CODE_INVALID_PARAMS,
            message,
            data: None,
        }
    }

    fn header_mismatch(message: &'static str) -> Self {
        Refused {
            code: CODE_HEADER_MISMATCH,
            message,
            data: None,
        }
    }
}

/// A `Mcp-Name` (or `Mcp-Param-*`) value with this revision's `=?base64?…?=` sentinel decoded, or the
/// value as it stands when it carries none.
#[must_use]
pub fn decode_sentinel(value: &str) -> Option<String> {
    use base64::Engine as _;
    let Some(inner) = value
        .strip_prefix("=?base64?")
        .and_then(|v| v.strip_suffix("?="))
    else {
        return Some(value.to_string());
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(inner)
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// THE CHECKS, in the served order. `field` reads one request head field by its lower-case name.
///
/// # Errors
///
/// The first refusal the request earns.
pub fn check_request<'a>(
    value: &Value,
    method: &str,
    field: impl Fn(&str) -> Option<&'a str>,
) -> Result<(), Refused> {
    let Some(meta) = value.get("params").and_then(|p| p.get("_meta")) else {
        return Err(Refused::invalid_params(
            "`params._meta` is required on every request. This revision has no handshake, so each \
             request states its own protocol version and client capabilities there.",
        ));
    };
    let Some(body_version) = meta
        .get(META_PROTOCOL_VERSION)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    else {
        return Err(Refused::invalid_params(
            "`params._meta` must carry `io.modelcontextprotocol/protocolVersion`; this revision \
             negotiates per request, so the version cannot be inferred.",
        ));
    };
    if meta.get(META_CLIENT_CAPABILITIES).is_none() {
        return Err(Refused::invalid_params(
            "`params._meta` must carry `io.modelcontextprotocol/clientCapabilities`. With no \
             handshake there is no earlier message it could have been declared in, and this server \
             will not decide on a client's behalf what that client can do; send `{}` to declare \
             none.",
        ));
    }

    let Some(header_version) = field(H_PROTOCOL_VERSION) else {
        return Err(Refused::header_mismatch(
            "Every POST to the MCP endpoint must carry an `MCP-Protocol-Version` header.",
        ));
    };
    if header_version != body_version {
        return Err(Refused::header_mismatch(
            "The `MCP-Protocol-Version` header does not match the body's \
             `_meta.io.modelcontextprotocol/protocolVersion`.",
        ));
    }
    let Some(header_method) = field(H_MCP_METHOD) else {
        return Err(Refused::header_mismatch(
            "The `Mcp-Method` header is required on every request.",
        ));
    };
    if decode_sentinel(header_method).as_deref() != Some(method) {
        return Err(Refused::header_mismatch(
            "The `Mcp-Method` header does not match the body's `method`.",
        ));
    }
    if let Some(source) = name_source_of(method) {
        let body_name = value
            .get("params")
            .and_then(|p| p.get(source))
            .and_then(Value::as_str);
        let Some(header_name) = field(H_MCP_NAME) else {
            return Err(Refused::header_mismatch(
                "The `Mcp-Name` header is required on this method.",
            ));
        };
        let Some(decoded) = decode_sentinel(header_name) else {
            return Err(Refused::header_mismatch(
                "The `Mcp-Name` header carries a `=?base64?…?=` sentinel that is not valid Base64.",
            ));
        };
        if body_name != Some(decoded.as_str()) {
            return Err(Refused::header_mismatch(
                "The `Mcp-Name` header does not match the body's target name.",
            ));
        }
    }

    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&body_version) {
        return Err(Refused {
            code: CODE_UNSUPPORTED_PROTOCOL_VERSION,
            message: "This server does not implement the requested MCP protocol version.",
            data: Some(serde_json::json!({
                "requested": body_version,
                "supported": SUPPORTED_PROTOCOL_VERSIONS,
            })),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/checks.rs"]
mod tests;
