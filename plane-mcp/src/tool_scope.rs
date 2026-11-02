// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SCOPE A `token_exchange:` REGISTRATION'S TOKEN IS ASKED FOR: derived, never configured — a configured scope list would be a second

use crate::catalogue::Catalogue;
use crate::tools_config::McpServerDefCfg;

/// The down-scope of a call to the tool `called` (its published name on `server`, the member the
#[must_use]
pub fn caller_downscope(
    catalogue: &Catalogue,
    server: &str,
    called: &str,
    wildcard: bool,
    granted: &impl Fn(&str) -> bool,
) -> String {
    let mut scopes: Vec<&str> = if wildcard {
        vec![called]
    } else {
        catalogue
            .tools_for(&|kind: &str, name: &str| {
                if kind == crate::statement::SCOPE {
                    name == server
                } else {
                    granted(name)
                }
            })
            .into_iter()
            .map(|t| t.namespaced.as_str())
            .collect()
    };
    scopes.sort_unstable();
    scopes.dedup();
    scopes.join(" ")
}

/// The scope of the door's own fetch from the registration `server` (`def`): every tool it approves
#[must_use]
pub fn registration_scope(server: &str, def: &McpServerDefCfg) -> String {
    let mut scopes: Vec<String> = def
        .tools_allow
        .iter()
        .filter(|(_, allow)| {
            allow
                .schema_hash
                .as_deref()
                .is_some_and(|h| !h.trim().is_empty())
        })
        .map(|(tool, allow)| {
            allow
                .publish_as
                .clone()
                .unwrap_or_else(|| crate::tools_config::namespaced(server, tool))
        })
        .collect();
    scopes.sort_unstable();
    scopes.dedup();
    scopes.join(" ")
}

/// Whether the registration `def` is bound to the token exchange: it states a `token_exchange:`
#[must_use]
pub fn exchanges(
    def: &McpServerDefCfg,
    upstream: Option<busbar_contract::config::UpstreamCreds>,
) -> bool {
    def.token_exchange.is_some()
        && upstream != Some(busbar_contract::config::UpstreamCreds::Passthrough)
}

#[cfg(test)]
#[path = "tests/tool_scope.rs"]
mod tests;
