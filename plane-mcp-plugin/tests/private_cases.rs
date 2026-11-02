// SPDX-License-Identifier: Apache-2.0
//! Ordinary private-state assertions compile the same actual production source.
#![allow(dead_code)]
/// The session revisions raised into, and lowered out of, the one dispatch.
#[path = "../../plane-mcp/src/adapt.rs"]
mod adapt;
#[path = "../../plane-mcp/src/answer.rs"]
mod answer;
/// The argument half of the dispatch SSRF guard: a schema-aware walk judging every URL and host a
#[path = "../../plane-mcp/src/argguard.rs"]
mod argguard;
#[path = "../../plane-mcp/src/ask.rs"]
mod ask;
#[path = "../../plane-mcp/src/call.rs"]
mod call;
#[path = "../../plane-mcp/src/catalogue.rs"]
mod catalogue;
#[path = "../../plane-mcp/src/checks.rs"]
mod checks;
#[path = "../../plane-mcp/src/client/mod.rs"]
mod client;
#[path = "../../plane-mcp/src/codec.rs"]
mod codec;
/// The plane's diagnostic catalog: the codes it raises, which its `declares.json` states (the tests
#[cfg(test)]
#[path = "../../plane-mcp/src/diagnostics.rs"]
mod diagnostics;
#[path = "../../plane-mcp/src/endpoint.rs"]
mod endpoint;
#[path = "../../plane-mcp/src/framing.rs"]
mod framing;
#[path = "../../plane-mcp/src/identity.rs"]
mod identity;
/// The line carrier's meanings: one JSON-RPC message per line, each its own unit.
#[path = "../../plane-mcp/src/line.rs"]
mod line;
#[path = "../../plane-mcp/src/local_output.rs"]
mod local_output;
#[path = "../../plane-mcp/src/local_renderer.rs"]
mod local_renderer;
#[allow(dead_code)]
mod plane_door {
    include!("../../plane-mcp/src/plane_door_impl.rs");
    mod child_work_custody_tests {
        include!("support/private_child_work.rs");
    }
}
#[path = "../../plane-mcp/src/program_trust.rs"]
mod program_trust;
#[path = "../../plane-mcp/src/statement.rs"]
mod statement;
#[path = "../../plane-mcp/src/tool_arrival.rs"]
mod tool_arrival;
#[path = "../../plane-mcp/src/tool_claims.rs"]
mod tool_claims;
#[path = "../../plane-mcp/src/tool_meta.rs"]
mod tool_meta;
#[path = "../../plane-mcp/src/tool_ops.rs"]
mod tool_ops;
/// The `transport: stdio` servers: one long-lived child per server, its messages correlated by id.
#[path = "../../plane-mcp/src/tool_program.rs"]
mod tool_program;
#[path = "../../plane-mcp/src/tool_scope.rs"]
mod tool_scope;
/// SEP-2663, the tasks extension: a task's state, shapes, sweep and durable rows.
#[path = "../../plane-mcp/src/tool_tasks.rs"]
mod tool_tasks;
#[path = "../../plane-mcp/src/tools_config.rs"]
mod tools_config;

/// The plugin's memory-ABI door.
pub use plane_door::door;

/// The plane's declared metadata (`declares.json`), linked by the distribution and signed into a
pub const DECLARES: &str = include_str!("../declares.json");

#[path = "../../plane-mcp/src/reads.rs"]
mod reads;
#[path = "../../plane-mcp/src/record.rs"]
mod record;
/// The dated revisions of the one MCP dialect, and their negotiation.
#[path = "../../plane-mcp/src/revision.rs"]
mod revision;
#[path = "../../plane-mcp/src/sanitize.rs"]
mod sanitize;
/// The sealed `requestState`: busbar's own ask state, signed by the host.
#[path = "../../plane-mcp/src/seal.rs"]
mod seal;
/// `subscriptions/listen`, as a state machine any carrier drives.
#[path = "../../plane-mcp/src/subscribe.rs"]
mod subscribe;
#[path = "../../plane-mcp/src/tool_records.rs"]
mod tool_records;
/// Bounded, owner-bound session state for the session revisions.
#[path = "../../plane-mcp/src/tool_sessions.rs"]
mod tool_sessions;
/// The trust surface: approvals, sightings, the derived state and the admin views.
#[path = "../../plane-mcp/src/trust.rs"]
mod trust;

/// THE REGISTRY KEY MCP IS KNOWN BY: the name the door's Statement states.
const PLANE_KEY: &str = "mcp";

#[cfg(test)]
#[path = "../../plane-mcp/src/tests/mod.rs"]
mod tests;

#[allow(dead_code, unused_imports)]
mod actual_legacy_driver {
    include!("../../plane-mcp/src/legacy_wire.rs");
    mod tests {
        include!("support/private_driver.rs");
    }
}
