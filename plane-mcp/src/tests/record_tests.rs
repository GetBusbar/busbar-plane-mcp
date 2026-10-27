// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The call record's content suffix, in the framing the host's call-log seam chains.

use super::*;

/// Every field LengthPrefixed (`len:u64-be ⧺ bytes`, a number its eight big-endian bytes), in the
/// digest's order: ts, server, tool, outcome, reason, tool_digest, pin_generation.
#[test]
fn the_call_suffix_is_length_prefixed_in_digest_order() {
    fn lp(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(b);
    }
    let mut want = Vec::new();
    lp(&mut want, &1000u64.to_be_bytes());
    lp(&mut want, b"fs");
    lp(&mut want, b"fs_read");
    lp(&mut want, b"dispatched");
    lp(&mut want, b"");
    lp(&mut want, b"sha256:aaa");
    lp(&mut want, &7u64.to_be_bytes());
    assert_eq!(
        call_suffix(1000, "fs", "fs_read", "dispatched", "", "sha256:aaa", 7),
        want
    );
}
