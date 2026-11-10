// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE DOOR'S ROOT CELLS, as the composition root's door-cells row reads them:
//! this file is the one this crate states under its `links` name (`build.rs`,
//! `cargo::metadata=cells=`), compiled as a child of the composition root's serve module in
//! its test builds (`super::` is `root::serve`), the same for this pinned dependency as for
//! a path one.

/// THIS PLANE'S CAPABILITY-EQUALITY COLUMNS (`qa/capability-equality.json`): the cells its
/// root leg answers for.
pub(crate) const COLUMNS: &[&str] = &["mcp-client", "mcp-server"];

/// `(capability, column, reason)`: the root-leg cells this plane is NOT owed, each the
/// ledger's own not-applicable cell with its reason, word for word.
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

/// Actual plane composition cases that scan source refusals at the caller boundary.
mod secret_source;

pub(crate) fn secret_source_driven() -> Vec<String> {
    vec![super::secret_source_tests::statement_name(
        crate::root::serve::plane_mcp_door::tool_door::line_door(),
    )]
}

use crate::root::door_steps::tests::{
    isolated_fixture_cases, isolated_fixture_done, TokenEndpoint,
};
use crate::root::serve::door_tests::{independent_case_done, independent_cases};
include!("door_steps.rs");
include!("tools_door.rs");
#[path = "member_tls_negative.rs"]
mod member_tls_negative_tests;
#[path = "member_tls.rs"]
mod member_tls_tests;

// These owner-supplied cells execute inside the composition root, whose sealed
// authoring authority constructs the same reference document an operator submits.
fn fill_reference(value: &str) -> serde_json::Value {
    use busbar_contract::secret::SecretAxis as _;
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    let reference = crate::root::linked::secret_rows()
        .sugars()
        .reference_for_role(
            busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL,
            value,
        )
        .expect("the linked source supplies the fixture's fill role");
    serde_json::to_value(reference.authoring(&busbar_kernel::seal::acquire()))
        .expect("the root authors the fixture reference")
}

/// The owner's minimal valid section for composition-root coverage fixtures.
pub(crate) fn minimal_valid_config() -> (&'static str, serde_json::Value) {
    ("tools", serde_json::json!({"hooks": []}))
}

mod plane_driver_serve;

mod connections;
