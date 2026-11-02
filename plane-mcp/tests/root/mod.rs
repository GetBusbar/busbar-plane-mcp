// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE DOOR'S ROOT CELLS, as the composition root's door-cells row reads them: this file














/// THIS PLANE'S CAPABILITY-EQUALITY COLUMNS (`qa/capability-equality.json`): the cells its root leg
pub(crate) const COLUMNS: &[&str] = &["mcp-client", "mcp-server"];

/// `(capability, column, reason)`: the root-leg cells this plane is NOT owed, each the ledger's own
pub(crate) const NOT_APPLICABLE: &[(&str, &str, &str)] = &[
    (
        "breaker-trip",
        "mcp-server",
        "the front door is inbound; there is no upstream target whose availability could be recorded. An upstream's sampling/roots/elicitation ask is RELAYED to the caller (Law 11), never satisfied by a model leg busbar dials, so this role triggers no outbound of its own.",
    ),
    (
        "breaker-fastfail",
        "mcp-server",
        "the front door is inbound; admission-before-dispatch has no upstream target on this role. The only outbound a call through it triggers is the mcp-client leg (an upstream's ask is relayed to the caller, Law 11), which is that cell's evidence.",
    ),
    (
        "failover-reroute",
        "mcp-server",
        "inbound role; there is no candidate set to walk. Failover for the work this role triggers belongs to the outbound mcp-client cell (an upstream's ask is relayed to the caller, Law 11, and dials nothing).",
    ),
    (
        "disposition",
        "mcp-server",
        "disposition classifies an upstream's ANSWER; the inbound role has no upstream answer to classify. Rendering a refusal to a caller is the response path, not disposition.",
    ),
    (
        "net-guard",
        "mcp-server",
        "the inbound listener derives no outbound destination of its own; the destinations its work triggers are the mcp-client cell's, and an upstream's ask is relayed to the caller (Law 11), so busbar dials no model for it.",
    ),
    (
        "egress-auth",
        "mcp-server",
        "this role has no outbound of its own: an upstream's sampling/roots/elicitation ask is relayed to the caller (Law 11), never answered by a model leg busbar would credential; inbound caller authentication is the Auth plugin's subject, not egress.",
    ),
];

/// THE SECRET-SOURCE SCAN'S DRIVEN DOOR (the composition root's `secret_source.rs`, which holds
pub(crate) fn secret_source_driven() -> Vec<String> {
    Vec::new()
}
