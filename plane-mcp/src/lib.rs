//! The MCP plane: the plugin contract's plane kind for the Model Context Protocol, served
//! through its door ([`door`]) and declared metadata ([`DECLARES`]).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// The session revisions raised into, and lowered out of, the one dispatch.
mod adapt;
mod answer;
/// The argument half of the dispatch SSRF guard: a schema-aware walk judging every URL and
/// host a call's arguments carry.
mod argguard;
mod ask;
mod call;
mod catalogue;
mod checks;
mod client;
mod codec;
/// The plane's diagnostic catalog: the codes it raises, which its `declares.json` states
/// (the tests hold the two equal, and the codes equal to the ones the door raises).
#[cfg(test)]
mod diagnostics;
mod endpoint;
mod framing;
mod identity;
/// The line carrier's meanings: one JSON-RPC message per line, each its own unit.
mod line;
mod local_output;
mod local_renderer;
mod plane_door;
mod program_trust;
mod statement;
mod tool_arrival;
mod tool_claims;
mod tool_meta;
mod tool_ops;
/// The `transport: stdio` servers: one long-lived child per server, its messages correlated by id.
mod tool_program;
mod tool_scope;
/// SEP-2663, the tasks extension: a task's state, shapes, sweep and durable rows.
mod tool_tasks;
mod tools_config;

/// The plugin's memory-ABI door.
pub use plane_door::{door, MACRO_DOOR};

/// The plane's declared metadata (`declares.json`), linked by the distribution and signed
/// into a dropped-in plane's manifest.
pub const DECLARES: &str = include_str!("../declares.json");

mod reads;
mod record;
/// The dated revisions of the one MCP dialect, and their negotiation.
mod revision;
mod sanitize;
/// The sealed `requestState`: busbar's own ask state, signed by the host.
mod seal;
/// `subscriptions/listen`, as a state machine any carrier drives.
mod subscribe;
mod tool_records;
/// Bounded, owner-bound session state for the session revisions.
mod tool_sessions;
/// The trust surface: approvals, sightings, the derived state and the admin views.
mod trust;

/// THE REGISTRY KEY MCP IS KNOWN BY: the name the door's Statement states.
const PLANE_KEY: &str = "mcp";

#[cfg(test)]
mod tests;
