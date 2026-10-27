//! The carriers and paths this plane serves.

/// The request transport this plane's document routes are served on.
pub const CARRIER_HTTP: &str = "http";

/// The framing a streamed answer arrives on: the same request's own event framing.
pub const CARRIER_SSE: &str = "sse";

/// The transport a locally launched server speaks over.
pub const CARRIER_STDIO: &str = "stdio";

/// The ONE path this protocol is served at. Fixed, not operator-configurable: a configured address
/// naming any other path is refused at validation (CG-17), and the validation reads this constant.
pub const DEFAULT_MOUNT: &str = "/mcp";

/// The discovery document for the default mount.
pub const DEFAULT_METADATA: &str = "/.well-known/oauth-protected-resource/mcp";

/// Where a task's continuation arrives, nested by the unit that created the task (`unit.nest`).
pub const TASK_RUN_MOUNT: &str = "/mcp/tasks/run";

#[cfg(test)]
#[path = "tests/claims.rs"]
mod tests;
