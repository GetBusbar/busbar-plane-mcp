// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MCP Apps 2026-01-26 gateway policy. Rendering and app/model origin enforcement belong to
//! the authenticated downstream host. Nothing in this module treats visibility as identity.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const EXTENSION: &str = "io.modelcontextprotocol/ui";
pub(crate) const MIME: &str = "text/html;profile=mcp-app";
pub(crate) const SPEC: &str = "2026-01-26";

/// Per-member Apps opt-in. The gateway implements HTTP relay, not a browser sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppsCfg {
    /// Disabled unless explicitly enabled by the operator.
    pub enabled: bool,
    /// Pinned extension version.
    pub spec_version: String,
    /// Supported UI types; intersected with the downstream session's advertised types.
    pub mime_types: Vec<String>,
    /// Maximum decoded HTML bytes per resource response.
    pub max_resource_bytes: usize,
    /// Explicit compatibility adapter for deprecated `_meta["ui/resourceUri"]`.
    pub allow_legacy_resource_meta: bool,
    /// Exact upstream UI resources authorized for dynamic reads.
    pub resources: BTreeMap<String, ResourcePolicy>,
}
impl Default for AppsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            spec_version: SPEC.into(),
            mime_types: vec![MIME.into()],
            max_resource_bytes: 1_048_576,
            allow_legacy_resource_meta: false,
            resources: BTreeMap::new(),
        }
    }
}
/// Approved resource security metadata and optional immutable content digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicy {
    /// SHA-256 of decoded HTML bytes, or absent for a mutable trusted-origin resource.
    #[serde(default)]
    pub digest: Option<String>,
    /// Exact `_meta.ui` security metadata approved by the operator; absent means `{}`.
    #[serde(default = "empty_object")]
    pub ui: Value,
}
fn empty_object() -> Value {
    json!({})
}
impl AppsCfg {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.spec_version != SPEC
            || self.mime_types.is_empty()
            || self.mime_types.iter().any(|m| m != MIME)
            || !(1..=8 * 1024 * 1024).contains(&self.max_resource_bytes)
        {
            return Err("apps: unsupported version, MIME type or resource byte bound".into());
        }
        if self.resources.len() > 1024 {
            return Err("apps: too many UI resources".into());
        }
        for (uri, policy) in &self.resources {
            validate_uri(uri)?;
            security_metadata(&policy.ui)?;
            if policy.digest.as_ref().is_some_and(|d| {
                !d.strip_prefix("sha256:")
                    .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            }) {
                return Err("apps: resource digest must be sha256:<64 hex digits>".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Profile(pub BTreeSet<String>);
impl Profile {
    pub(crate) fn parse(capabilities: Option<&Value>) -> Result<Self, String> {
        let Some(extension) = capabilities
            .and_then(|v| v.get("extensions"))
            .and_then(|v| v.get(EXTENSION))
        else {
            return Ok(Self::default());
        };
        let types = extension
            .get("mimeTypes")
            .and_then(Value::as_array)
            .ok_or("Apps capability requires a mimeTypes array")?;
        if types.len() > 16 {
            return Err("Too many Apps MIME types".into());
        }
        let mut result = BTreeSet::new();
        for mime in types {
            let mime = mime
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 128)
                .ok_or("Invalid Apps MIME type")?;
            result.insert(mime.into());
        }
        Ok(Self(result))
    }
    pub(crate) fn effective(&self, cfg: &AppsCfg) -> Self {
        Self(if cfg.enabled {
            self.0
                .iter()
                .filter(|m| cfg.mime_types.contains(m))
                .cloned()
                .collect()
        } else {
            BTreeSet::new()
        })
    }
    pub(crate) fn enabled(&self) -> bool {
        self.0.contains(MIME)
    }
    pub(crate) fn capabilities(&self) -> Value {
        if self.0.is_empty() {
            json!({})
        } else {
            json!({"extensions": {EXTENSION: {"mimeTypes": self.0}}})
        }
    }
    pub(crate) fn apply(&self, request: &mut crate::client::jsonrpc::OutboundRequest) {
        if let Ok(mut body) = crate::codec::wire_json::parse(&request.body) {
            let caps = &mut body["params"]["_meta"][crate::codec::META_CLIENT_CAPABILITIES];
            if caps.is_null() {
                *caps = json!({});
            }
            if self.enabled() {
                caps["extensions"][EXTENSION] =
                    self.capabilities()["extensions"][EXTENSION].clone();
            } else if let Some(extensions) =
                caps.get_mut("extensions").and_then(Value::as_object_mut)
            {
                extensions.remove(EXTENSION);
            }
            request.body = crate::codec::json(&body);
        }
    }
}

pub(crate) fn validate_uri(uri: &str) -> Result<(), String> {
    let parsed = url::Url::parse(uri).map_err(|_| "Invalid Apps URI")?;
    if !uri.starts_with("ui://")
        || parsed.host_str().is_none()
        || uri.len() > 8192
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || uri.chars().any(char::is_whitespace)
        || uri.contains(['{', '}'])
    {
        return Err(
            "Apps resource must be an exact ui:// URI without userinfo or template expressions"
                .into(),
        );
    }
    Ok(())
}

/// Validate and normalize only the declared metadata location; arbitrary strings are never rewritten.
pub(crate) fn tool_meta(meta: Option<&Value>, legacy: bool) -> Result<Option<Value>, String> {
    let Some(meta) = meta else {
        return Ok(None);
    };
    let obj = meta.as_object().ok_or("Tool _meta must be an object")?;
    let flat = obj.get("ui/resourceUri");
    if flat.is_some() && !legacy {
        return Err("Deprecated UI metadata requires explicit compatibility opt-in".into());
    }
    let mut ui = obj.get("ui").cloned();
    if ui.as_ref().is_some_and(|v| !v.is_object()) {
        return Err("Tool _meta.ui must be an object".into());
    }
    if let Some(flat) = flat {
        let uri = flat
            .as_str()
            .ok_or("Deprecated UI resourceUri must be a string")?;
        if let Some(current) = ui.as_ref().and_then(|u| u.get("resourceUri")) {
            if current != flat {
                return Err("Conflicting UI resource URIs".into());
            }
        } else {
            ui.get_or_insert_with(empty_object)["resourceUri"] = Value::String(uri.into());
        }
    }
    let Some(mut ui) = ui else {
        return Ok(None);
    };
    let obj = ui
        .as_object_mut()
        .ok_or("Tool _meta.ui must be an object")?;
    if let Some(uri) = obj.get("resourceUri") {
        validate_uri(uri.as_str().ok_or("UI resourceUri must be a string")?)?;
    }
    let visibility = obj
        .entry("visibility")
        .or_insert_with(|| json!(["model", "app"]));
    let values = visibility
        .as_array()
        .ok_or("UI visibility must be an array")?;
    let mut normalized = BTreeSet::new();
    for value in values {
        let v = value
            .as_str()
            .filter(|v| matches!(*v, "model" | "app"))
            .ok_or("Invalid UI visibility")?;
        if !normalized.insert(v.to_owned()) {
            return Err("Duplicate UI visibility".into());
        }
    }
    *visibility = json!(normalized);
    Ok(Some(ui))
}
pub(crate) fn model_visible(meta: Option<&Value>, legacy: bool) -> bool {
    tool_meta(meta, legacy).is_ok_and(|ui| {
        ui.is_none_or(|ui| {
            ui["visibility"]
                .as_array()
                .is_some_and(|v| v.iter().any(|v| v == "model"))
        })
    })
}

/// Apps approvals have a domain-separated digest. Legacy tools retain their existing digest.
pub(crate) fn digest(
    name: &str,
    description: &str,
    schema: &Value,
    meta: Option<&Value>,
    legacy: bool,
) -> Result<String, String> {
    let Some(ui) = tool_meta(meta, legacy)? else {
        return Ok(crate::trust::tool_digest(name, description, schema));
    };
    let mut normalized = meta.cloned().unwrap_or_else(empty_object);
    normalized
        .as_object_mut()
        .expect("validated metadata")
        .remove("ui/resourceUri");
    normalized["ui"] = ui.clone();
    let body = json!({"version":"busbar-mcp-apps-v1", "name":name,"description":description,"inputSchema":schema,"ui":ui,"meta":normalized});
    Ok(format!(
        "sha256:{}",
        busbar_contract::redacted::sha256_hex(crate::trust::canonical_json(&body).as_bytes())
    ))
}

pub(crate) fn security_metadata(ui: &Value) -> Result<(), String> {
    let obj = ui
        .as_object()
        .ok_or("Resource _meta.ui must be an object")?;
    for (key, value) in obj {
        match key.as_str() {
            "csp" => {
                let csp = value.as_object().ok_or("UI CSP must be an object")?;
                for (key, domains) in csp {
                    if !matches!(
                        key.as_str(),
                        "connectDomains" | "resourceDomains" | "frameDomains" | "baseUriDomains"
                    ) {
                        return Err("Unknown CSP directive".into());
                    }
                    let domains = domains
                        .as_array()
                        .filter(|v| v.len() <= 64)
                        .ok_or("CSP domains must be a bounded array")?;
                    for domain in domains {
                        let domain = domain.as_str().ok_or("CSP origin must be a string")?;
                        let parsed = url::Url::parse(domain).map_err(|_| "Invalid CSP origin")?;
                        if !matches!(parsed.scheme(), "https" | "wss")
                            || parsed.host_str().is_none()
                            || !parsed.username().is_empty()
                            || parsed.password().is_some()
                            || parsed.query().is_some()
                            || parsed.fragment().is_some()
                            || parsed.path() != "/"
                            || domain.contains(['*', '\'', ';'])
                            || domain.chars().any(char::is_whitespace)
                        {
                            return Err("CSP domains must be exact HTTPS/WSS origins".into());
                        }
                    }
                }
            }
            "permissions" => {
                for (key, value) in value
                    .as_object()
                    .ok_or("UI permissions must be an object")?
                {
                    if !matches!(
                        key.as_str(),
                        "camera" | "microphone" | "geolocation" | "clipboardWrite"
                    ) || value.as_object().is_none_or(|v| !v.is_empty())
                    {
                        return Err("Invalid UI permission".into());
                    }
                }
            }
            "domain" => {
                let domain = value.as_str().ok_or("UI domain must be a string")?;
                let u = url::Url::parse(domain).map_err(|_| "Invalid UI domain")?;
                if u.scheme() != "https"
                    || u.host_str().is_none()
                    || !u.username().is_empty()
                    || u.password().is_some()
                    || u.query().is_some()
                    || u.fragment().is_some()
                    || u.path() != "/"
                {
                    return Err("Invalid UI domain".into());
                }
            }
            "prefersBorder" if value.is_boolean() => {}
            _ => return Err("Unknown or malformed UI security metadata".into()),
        }
    }
    Ok(())
}

pub(crate) fn resource_result(
    result: &mut Value,
    original: &str,
    published: &str,
    cfg: &AppsCfg,
) -> Result<(), String> {
    let policy = cfg
        .resources
        .get(original)
        .ok_or("UI resource is not approved")?;
    let contents = result
        .get_mut("contents")
        .and_then(Value::as_array_mut)
        .filter(|v| v.len() == 1)
        .ok_or("UI read must return exactly one resource")?;
    let content = &mut contents[0];
    if content.get("uri").and_then(Value::as_str) != Some(original)
        || content.get("mimeType").and_then(Value::as_str) != Some(MIME)
    {
        return Err("UI read returned an unexpected URI or MIME type".into());
    }
    let bytes = match (content.get("text"), content.get("blob")) {
        (Some(Value::String(text)), None) if text.len() <= cfg.max_resource_bytes => {
            text.as_bytes().to_vec()
        }
        (None, Some(Value::String(blob)))
            if blob.len()
                <= cfg
                    .max_resource_bytes
                    .saturating_mul(4)
                    .div_ceil(3)
                    .saturating_add(4) =>
        {
            base64::engine::general_purpose::STANDARD
                .decode(blob)
                .map_err(|_| "Invalid UI base64")?
        }
        _ => return Err("UI resource needs exactly one bounded text or blob content".into()),
    };
    if bytes.len() > cfg.max_resource_bytes || std::str::from_utf8(&bytes).is_err() {
        return Err("UI HTML is oversized or not UTF-8".into());
    }
    let ui = content
        .get("_meta")
        .and_then(|m| m.get("ui"))
        .cloned()
        .unwrap_or_else(empty_object);
    security_metadata(&ui)?;
    if ui != policy.ui {
        return Err("UI security metadata drifted from its approved policy".into());
    }
    if policy.digest.as_ref().is_some_and(|expected| {
        *expected != format!("sha256:{}", busbar_contract::redacted::sha256_hex(&bytes))
    }) {
        return Err("UI resource content digest drifted".into());
    }
    content["uri"] = published.into();
    if content.get("_meta").is_some_and(|m| !m.is_object()) {
        return Err("UI resource metadata must be an object".into());
    }
    if content.get("_meta").is_none() {
        content["_meta"] = json!({});
    }
    content["_meta"]["io.busbar/mutable"] = policy.digest.is_none().into();
    Ok(())
}

#[cfg(test)]
#[path = "tests/apps.rs"]
mod tests;
