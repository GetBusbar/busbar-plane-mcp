//! The MCP plane: what bytes mean, for a protocol that names its operation in the body.
//!
//! ## What this crate is
//!
//! An ADAPTER. Every method of the plane kind here is a few lines over a codec that already exists:
//! the envelope shape, the method vocabulary, the error code table, the result discriminators and
//! the record kinds. No wire format is written twice, because a wire format written twice is two
//! wire formats that will disagree, and the one that disagrees quietly is the one that reaches a
//! customer.
//!
//! ## What this crate is not
//!
//! It holds no governance, no breaker, no hook seat, no approval decision and no arithmetic over a
//! metered quantity. Those are units, and a unit is on the far side of the kernel from a plane. The
//! metering method here returns LOCATORS — the class, where the number is, and the number the codec
//! already read — and never a price, never a hold and never a decision. The routing method returns a
//! plan and never a connection. Nothing in this crate opens a socket, reads a file or reads a clock
//! other than the one the context hands it.
//!
//! ## What it holds across calls
//!
//! Nothing. The plane is a value with no interior mutability, asserted by a test rather than by a
//! comment. What state a held stream needs lives in the kernel-held per-connection codec state,
//! which the kernel hands in and takes back.
//!
//! ## Where this adapter had to write something down twice, and why
//!
//! The codec crate holds the method table, the error codes and the result discriminators, and it
//! holds all of them where only its own crate can see them; the envelope reader and writer live one
//! crate further away still, on the kernel side, where a plane may not name them at all. This crate
//! may not widen any of that. So those things are written once more here — and each of them is
//! PINNED by a test that reads the codec's own source or the conformance battery's own tables. A
//! copy that is checked is not a second opinion. A copy that is not checked is, and there are none
//! of those here.
//!
//! The full list of places the contract did not fit this protocol is in the notes each module
//! carries: the mount path that is configured where a claim must be a constant, the correlation type
//! that cannot hold a named identifier, the arena that cannot hold a span table, and the
//! introspection verb that takes no argument.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
#![deny(missing_docs)]

/// The session revisions raised into, and lowered out of, the one dispatch.
mod adapt;
mod answer;
/// The argument half of the dispatch SSRF guard: a schema-aware walk judging every URL and host a
/// call's arguments carry.
mod argguard;
mod ask;
mod call;
mod catalogue;
mod checks;
mod client;
mod codec;
/// The plane's diagnostic catalog, which its `declares.json` states (a test holds the two equal).
#[cfg(test)]
mod diagnostics;
mod door;
mod endpoint;
mod framing;
mod identity;
mod jsonrpc;
/// The line carrier's meanings: one JSON-RPC message per line, each its own unit.
mod line;
mod tool_arrival;
mod tool_claims;
mod tool_door;
mod tool_facts;
mod tool_meta;
mod tool_ops;
/// The `transport: stdio` servers: one long-lived child per server, its messages correlated by id.
mod tool_program;
mod tool_scope;
/// SEP-2663, the tasks extension: a task's state, shapes, sweep and durable rows.
mod tool_tasks;
mod tools_config;

/// THE DOOR: this plugin's one public item (BUSBAR-1.6.0.md l.3567, Crate shape).
pub use tool_door::door;

/// THE PLANE'S DECLARED METADATA (`declares.json`), as the tests read it: the one document the
/// door's Statement carries under `EXT_DECLARES` ([`tool_door`]'s `EXTENSIONS`) and the release signs
/// into a dropped-in plane's manifest. The codes its catalog holds are `diagnostics::DIAGNOSTICS`
/// (a test holds the two equal).
#[cfg(test)]
const DECLARES: &str = include_str!("../declares.json");

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

/// THE REGISTRY KEY MCP IS KNOWN BY, in the protocol registry and in the plane registry alike.
///
/// Named ONCE, here, because three declarations read it and all three must agree: this crate's
/// [`plane`] kind `KEY`, the engine's `PLANE_DECLARATION.key`, and the engine's `ProtocolDecl.name`. It
/// lives on the PLANE side because a plane is the thing being named — a key spelled engine-side
/// would be a key the plane could only copy, which is how two answers to "what is this plane
/// called" start to differ.
const PLANE_KEY: &str = "mcp";

use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// The MCP plane.
///
/// It carries no field: it is the type the plane's declarations (`PlaneMeta`) and its identity
/// (`Plugin`) hang on, and the served door reads those. There is no cell here, no lock and no
/// atomic: the purity test asserts that by walking the source, not by trusting this sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct McpPlane;

impl McpPlane {
    /// The plane. Nothing varies per instance, so there is one value of it.
    pub(crate) const EMPTY: Self = Self;
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

#[cfg(test)]
mod tests;
