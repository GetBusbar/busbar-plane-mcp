//! The meter classes and `--help` lines this plane declares.

use busbar_contract::ids::MeterClassId;

/// The class key a completed call is counted under.
pub const CLASS_TOOL_CALLS: MeterClassId = MeterClassId::new("tool_calls");

/// The class key the bytes an exchange moved are counted under.
pub const CLASS_BYTES: MeterClassId = MeterClassId::new("bytes");

/// This plane's lines in the `Flags:` block of `busbar --help`, byte for byte as the binary has
/// always printed them (shadow-oracle cells `cli__--help` / `cli__-h`), with no trailing newline.
pub const HELP_FLAGS: &str =
    "    --mcp-stdio         serve the MCP plane on THIS PROCESS's stdin/stdout (newline-delimited
                        JSON-RPC) instead of binding any listener — for an MCP host that runs
                        busbar as a child process. Requires the `mcp:` block; on a deployment with
                        a configured `auth.chain`, BUSBAR_MCP_STDIO_CREDENTIAL must carry a
                        credential the chain admits (audience-bound to mcp.canonical_uri), and the
                        whole session runs as that key — budgets, audit and hooks apply";

#[cfg(test)]
#[path = "tests/meta.rs"]
mod tests;
