//! The MCP plane: the plugin contract's plane kind for the Model Context Protocol, served through
//! its door ([`tool_door::door`]). It opens no socket, reads no file and holds no state of its own.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// The session revisions raised into, and lowered out of, the one dispatch.
pub mod adapt;
pub mod answer;
/// The argument half of the dispatch SSRF guard: a schema-aware walk judging every URL and host a
/// call's arguments carry.
pub mod argguard;
pub mod ask;
pub mod call;
pub mod catalogue;
pub mod checks;
pub mod client;
pub mod codec;
pub mod door;
pub mod endpoint;
pub mod framing;
pub mod identity;
/// The line carrier's meanings: one JSON-RPC message per line, each its own unit.
pub mod line;
pub mod tool_arrival;
pub mod tool_claims;
pub mod tool_door;
pub mod tool_facts;
pub mod tool_meta;
pub mod tool_ops;
/// The `transport: stdio` servers: one long-lived child per server, its messages correlated by id.
pub mod tool_program;
pub mod tool_scope;
/// SEP-2663, the tasks extension: a task's state, shapes, sweep and durable rows.
pub mod tool_tasks;
pub mod tools_config;

/// The plane's manifest `declares` section (`declares.json`): its diagnostics catalog and breaker
/// posture. The release signs the same file into a dropped-in plane's manifest.
pub const DECLARES: &str = include_str!("../declares.json");
/// THE DOOR CRATE'S CONVENTIONAL PATH, `<crate>::plane_door::door`: what a test-linked `door:` row's
/// generated table names (the build scripts of the crates that test-link this door). The door
/// itself is [`tool_door::door`].
pub mod plane_door {
    pub use crate::tool_door::{door, MACRO_DOOR};
}
pub mod reads;
pub mod record;
/// The dated revisions of the one MCP dialect, and their negotiation.
pub mod revision;
pub mod sanitize;
/// The sealed `requestState`: busbar's own ask state, signed by the host.
pub mod seal;
/// `subscriptions/listen`, as a state machine any carrier drives.
pub mod subscribe;
pub mod tool_records;
/// Bounded, owner-bound session state for the session revisions.
pub mod tool_sessions;
/// The trust surface: approvals, sightings, the derived state and the admin views.
pub mod trust;

/// The registry key MCP is known by.
pub const PLANE_KEY: &str = "mcp";

use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// The MCP plane.
///
/// It carries no field: it is the type the plane's declarations (`PlaneMeta`) and its identity
/// (`Plugin`) hang on, and the served door reads those. There is no cell here, no lock and no
/// atomic: the purity test asserts that by walking the source, not by trusting this sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McpPlane;

impl McpPlane {
    /// The plane. Nothing varies per instance, so there is one value of it.
    pub const EMPTY: Self = Self;
}

impl Default for McpPlane {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Plugin for McpPlane {
    fn key(&self) -> &'static str {
        <Self as busbar_contract::plane::PlaneMeta>::KEY
    }

    fn kind(&self) -> Kind {
        Kind::Plane
    }

    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}
