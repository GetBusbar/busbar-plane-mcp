// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Audit regressions for host launch receipts.

use super::*;

/// A head that names only a generation (a host that sends no receipt, on a member that is not
/// `local_program`-pinned) is accepted, but never when its status says the launch failed: a
/// `500` head is refused as untrusted, not read as a launched child of generation `0`.
#[test]
fn a_failed_launch_head_is_not_a_launched_generation() {
    for status in [0, 199, 300, 404, 500, 503] {
        assert_eq!(
            block(status, b"", "/approved/child", false),
            Err(UNTRUSTED.to_string()),
            "status {status}"
        );
        assert_eq!(
            block(status, b"generation: 7\r\n", "/approved/child", false),
            Err(UNTRUSTED.to_string()),
            "status {status}"
        );
    }
    for status in [200, 204] {
        assert_eq!(
            block(status, b"generation: 7\r\n", "/approved/child", false),
            Ok(Observed {
                instance: 0,
                generation: 7
            }),
            "status {status}"
        );
    }
}

/// A failed head after a real generation was recorded is refused for what it is, never as "a
/// retired program".
#[test]
fn a_failed_launch_head_after_a_recorded_generation_is_not_called_retired() {
    let mut versions = Versions::default();
    let live = block(200, b"generation: 5\r\n", "/approved/child", false).unwrap();
    versions.stamp("server", live).unwrap();
    let refused = block(500, b"", "/approved/child", false).unwrap_err();
    assert_eq!(refused, UNTRUSTED);
    assert!(!refused.contains("retired"), "{refused}");
}

#[test]
fn generation_only_receipts_reject_noncanonical_numbers() {
    for generation in ["0", "01", "+1", " 1", "bogus"] {
        let fields = format!("generation: {generation}\r\n");
        assert!(block(200, fields.as_bytes(), "/child", false).is_err());
    }
}
