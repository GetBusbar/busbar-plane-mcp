// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MCP plane's call-record content.

/// THE CALL RECORD'S CONTENT SUFFIX, as the plane writes it to the host's record seam: the chained
/// fields after the prelude the host frames (`prev_hash`, the scope, `seq`), LengthPrefixed — every
/// field `len:u64-be ⧺ bytes`, a numeric field its eight big-endian bytes as one such field — in the
/// call digest's order: `ts, server, tool, outcome, reason, tool_digest, pin_generation`. The
/// `request_id` is not in it: a join key is never in the digest.
#[must_use]
pub fn call_suffix(
    ts: u64,
    server: &str,
    tool: &str,
    outcome: &str,
    reason: &str,
    tool_digest: &str,
    pin_generation: u64,
) -> Vec<u8> {
    let (ts, pin) = (ts.to_be_bytes(), pin_generation.to_be_bytes());
    let fields: [&[u8]; 7] = [
        &ts,
        server.as_bytes(),
        tool.as_bytes(),
        outcome.as_bytes(),
        reason.as_bytes(),
        tool_digest.as_bytes(),
        &pin,
    ];
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(&(f.len() as u64).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

#[cfg(test)]
#[path = "tests/record_tests.rs"]
mod record_tests;
