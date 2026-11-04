// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `mcp:` ENDPOINT BLOCK: its grammar ([`McpCfg`]), its boot refusals ([`McpCfgError`]) and the
//! validated resource ([`McpResource`]) the composition root lowers it to at boot.

use serde::{Deserialize, Serialize};

use crate::{codec::protected_resource_metadata_path, tool_claims::DEFAULT_MOUNT};

/// The top-level `mcp:` config block. Its PRESENCE mounts the MCP plane under the resource it names.
/// Without it, the endpoint is mounted only when a `tools:` section selects the plane and the
/// deployment has a public URL (`statement::admitted_endpoint`), under that URL; with
/// neither, the deployment carries no MCP surface at all — no ingress, no metadata document, nothing
/// added to the route table. A gateway that is not an MCP server should not answer as one.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpCfg {
    /// The RFC 8707 resource indicator for this deployment: the canonical, absolute URI that names
    /// busbar's MCP endpoint, and therefore the exact `aud` value every inbound token must carry.
    ///
    /// It is OPERATOR-CONFIGURED rather than derived from the request's `Host`, and that is the
    /// whole point: deriving it from the request would let a caller choose its own audience by
    /// sending a `Host` header, which turns the confused-deputy defence into a formality. It is also
    /// what closes the multi-tenant gap — one deployment, one canonical audience, stated once.
    ///
    /// Its PATH must be the one path the claim table names: the mount is fixed, not configured, and
    /// a URI naming any other path is refused at boot (CG-17). The scheme, host and port are the
    /// operator's; the path is not.
    pub canonical_uri: String,
    /// RFC 9728 `authorization_servers`: the issuer identifiers of the authorization servers that
    /// may mint tokens for this resource — in practice, the operator's IdP. At least one is
    /// REQUIRED, because this list is the entire content of the answer a credential-less client came
    /// for; an empty one advertises a resource nobody can obtain a token for.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// RFC 9728 `scopes_supported`: the scope values this resource understands. Advisory metadata —
    /// authorization is decided by the caller's grant, never by what this list says.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Browser origins accepted on the MCP ingress, for the `2026-07-28` `Origin` MUST.
    ///
    /// EMPTY IS THE DEFAULT AND IT MEANS "no browser origin beyond loopback is accepted", which is the
    /// safe posture for a server whose clients are agents rather than pages: a request carrying NO
    /// `Origin` (every non-browser client) is unaffected, a loopback origin (`localhost`,
    /// `127.0.0.1`, `[::1]`, any port) is always admitted
    /// ([`busbar_contract::jsonrpc::origin_admitted`]), and a request carrying any other origin is
    /// refused unless the operator listed it. The threat is DNS rebinding — a page on an attacker's
    /// origin resolving a name to busbar's loopback address and driving the tool plane with the
    /// user's ambient credentials.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// The VALIDATED MCP resource: `McpCfg` after every derivation and refusal has already happened, so
/// nothing downstream re-parses a URI or re-decides a path.
///
/// Built once at boot. A config that cannot produce one does not boot — an MCP plane that is
/// half-configured is worse than one that is absent, because it answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpResource {
    /// The configured canonical URI after trimming surrounding whitespace. THE audience.
    canonical_uri: String,
    /// The absolute RFC 9728 section 3.1 metadata URL (the well-known prefix, then the resource's
    /// path), which is what goes in the challenge.
    metadata_url: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
}

/// Why an `mcp:` block was refused at boot. Every arm names the field and what a correct value looks
/// like: a boot refusal that does not say what to type is a boot refusal the operator works around.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpCfgError {
    /// `canonical_uri` was empty or absent.
    MissingCanonicalUri,
    /// `canonical_uri` was not an absolute `http`/`https` URI.
    CanonicalUriNotAbsolute(String),
    /// `canonical_uri` carried a query or a fragment. RFC 8707 section 2 forbids a fragment outright, and a
    /// query would make the identifier depend on parameter ordering — two spellings of one resource
    /// is one spelling too many when the value is compared for equality.
    CanonicalUriHasQueryOrFragment(String),
    /// `canonical_uri` had no path, or only `/`. The resource must be distinguishable from the
    /// deployment's root: mounting the MCP plane at `/` would put it in front of the LLM residual
    /// and claim every path in the process.
    CanonicalUriHasNoPath(String),
    /// `canonical_uri` named a path other than the one the claim table names. Inbound paths are
    /// compile-time claims in the Statement; a configured address naming another path would
    /// advertise, and bind every token's audience to, a path nothing is served at. The mount is
    /// fixed rather than configurable (CG-17). Carries the URI as configured and the path it named,
    /// normalised.
    CanonicalUriPathNotClaimed {
        /// The URI as configured.
        uri: String,
        /// The path it named, normalised to a leading and no trailing slash.
        path: String,
    },
    /// `authorization_servers` was empty.
    NoAuthorizationServers,
    /// An `authorization_servers` entry was not an absolute `http`/`https` URI.
    AuthorizationServerNotAbsolute(String),
    /// An `authorization_servers` entry carried a query or a fragment. RFC 8414 section 2 defines an
    /// issuer identifier as a URL with neither, and a client builds the issuer's metadata URL from
    /// it and compares the returned `issuer` to it for equality.
    AuthorizationServerHasQueryOrFragment(String),
}

impl std::fmt::Display for McpCfgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpCfgError::MissingCanonicalUri => write!(
                f,
                "mcp.canonical_uri is required: it is the audience every inbound token must carry \
                 (RFC 8707) and the path the endpoint mounts at. Example: \
                 `canonical_uri: https://gateway.example.com/mcp`"
            ),
            McpCfgError::CanonicalUriNotAbsolute(v) => write!(
                f,
                "mcp.canonical_uri `{v}` is not an absolute http(s) URI. It is compared for exact \
                 equality against a token's `aud`, so it must be the same absolute string the \
                 authorization server was asked to mint for. Example: \
                 `https://gateway.example.com/mcp`"
            ),
            McpCfgError::CanonicalUriHasQueryOrFragment(v) => write!(
                f,
                "mcp.canonical_uri `{v}` carries a query or fragment. RFC 8707 resource indicators \
                 carry neither: drop everything from the first `?` or `#`."
            ),
            McpCfgError::CanonicalUriHasNoPath(v) => write!(
                f,
                "mcp.canonical_uri `{v}` has no path. The MCP endpoint needs its own path so it \
                 does not claim the whole deployment. Example: `https://gateway.example.com/mcp`"
            ),
            McpCfgError::CanonicalUriPathNotClaimed { uri, path } => write!(
                f,
                "mcp.canonical_uri `{uri}` names the path `{path}`, but the MCP endpoint is served \
                 only at `{DEFAULT_MOUNT}`; the path is fixed, not configurable. Keep the scheme, \
                 host and port and end the URI in `{DEFAULT_MOUNT}`. Example: \
                 `https://gateway.example.com{DEFAULT_MOUNT}`"
            ),
            McpCfgError::NoAuthorizationServers => write!(
                f,
                "mcp.authorization_servers must list at least one issuer. It is the entire content \
                 of the answer a client with no credential comes here for; with none, the `401` it \
                 gets names nowhere to go. Example: \
                 `authorization_servers: [https://login.example.com]`"
            ),
            McpCfgError::AuthorizationServerNotAbsolute(v) => write!(
                f,
                "mcp.authorization_servers entry `{v}` is not an absolute http(s) URI. An issuer \
                 identifier is an absolute URL. Example: `https://login.example.com`"
            ),
            McpCfgError::AuthorizationServerHasQueryOrFragment(v) => write!(
                f,
                "mcp.authorization_servers entry `{v}` carries a query or fragment. An issuer \
                 identifier (RFC 8414) carries neither: drop everything from the first `?` or `#`. \
                 Example: `https://login.example.com`"
            ),
        }
    }
}

impl McpResource {
    /// Validate and derive. Every refusal is fail-closed at BOOT rather than at first request: an
    /// operator finds out from a process that will not start, not from an agent that cannot connect.
    pub fn from_cfg(cfg: &McpCfg) -> Result<Self, McpCfgError> {
        let uri = cfg.canonical_uri.trim();
        if uri.is_empty() {
            return Err(McpCfgError::MissingCanonicalUri);
        }
        let (origin, path) = split_absolute(uri)
            .ok_or_else(|| McpCfgError::CanonicalUriNotAbsolute(uri.to_string()))?;
        if path.contains('?') || path.contains('#') || origin.contains('#') {
            return Err(McpCfgError::CanonicalUriHasQueryOrFragment(uri.to_string()));
        }
        let mount_path = normalise_path(path);
        if mount_path.is_empty() {
            return Err(McpCfgError::CanonicalUriHasNoPath(uri.to_string()));
        }

        if mount_path != DEFAULT_MOUNT || path != mount_path {
            return Err(McpCfgError::CanonicalUriPathNotClaimed {
                uri: uri.to_string(),
                path: mount_path,
            });
        }
        if cfg.authorization_servers.is_empty() {
            return Err(McpCfgError::NoAuthorizationServers);
        }
        for issuer in &cfg.authorization_servers {
            let Some((_, path)) = split_absolute(issuer.trim()) else {
                return Err(McpCfgError::AuthorizationServerNotAbsolute(issuer.clone()));
            };
            if path.contains('?') || path.contains('#') {
                return Err(McpCfgError::AuthorizationServerHasQueryOrFragment(
                    issuer.clone(),
                ));
            }
        }
        Ok(Self {
            metadata_url: format!("{origin}{}", protected_resource_metadata_path(&mount_path)),
            canonical_uri: uri.to_string(),
            authorization_servers: cfg
                .authorization_servers
                .iter()
                .map(|s| s.trim().to_string())
                .collect(),
            scopes_supported: cfg.scopes_supported.clone(),
        })
    }

    /// THE audience. Compared for equality by the verifier; never parsed again.
    pub fn canonical_uri(&self) -> &str {
        &self.canonical_uri
    }

    /// The absolute metadata URL, for the `resource_metadata` challenge parameter.
    pub fn metadata_url(&self) -> &str {
        &self.metadata_url
    }

    /// The issuers allowed to mint tokens for this resource, trimmed.
    pub fn authorization_servers(&self) -> &[String] {
        &self.authorization_servers
    }

    /// The advisory scope values this resource lists.
    pub fn scopes_supported(&self) -> &[String] {
        &self.scopes_supported
    }
}

/// Split an absolute `http(s)` URI into `(origin, path)`, or `None` when it is not one.
///
/// Hand-written rather than pulled from a URL crate on purpose: what is needed is a STRICT
/// recogniser for one shape, and a permissive general-purpose parser is the wrong tool for a value
/// whose whole job is to be compared for exact equality. A lenient parse that accepts and normalises
/// `HTTPS://Host:443/mcp` would hand back a string that no longer equals the `aud` the IdP minted.
/// So: recognise, do not normalise.
fn split_absolute(uri: &str) -> Option<(&str, &str)> {
    let parsed = url::Url::parse(uri).ok()?;
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || uri.chars().any(|c| c.is_whitespace() || c.is_control())
        || uri.contains('\\')
    {
        return None;
    }
    let rest = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))?;

    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if authority_len == 0 {
        return None;
    }
    let scheme_len = uri.len() - rest.len();
    let split = scheme_len + authority_len;
    Some((&uri[..split], &uri[split..]))
}

/// `/mcp/` -> `/mcp`, `` -> ``, `/` -> ``. The same normalisation
/// core's plane dispatch applies to its mount path, so the derived mount and the dispatch mount are
/// the same string by construction rather than by two functions agreeing.
fn normalise_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    format!("/{trimmed}")
}

#[cfg(test)]
#[path = "tests/endpoint.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/endpoint_audit.rs"]
mod endpoint_audit;
