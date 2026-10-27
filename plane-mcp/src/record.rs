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
    fn text(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u64).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    fn num(out: &mut Vec<u8>, v: u64) {
        let b = v.to_be_bytes();
        out.extend_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(&b);
    }
    let mut out = Vec::new();
    num(&mut out, ts);
    text(&mut out, server);
    text(&mut out, tool);
    text(&mut out, outcome);
    text(&mut out, reason);
    text(&mut out, tool_digest);
    num(&mut out, pin_generation);
    out
}

#[cfg(test)]
#[path = "tests/record_tests.rs"]
mod record_tests;
