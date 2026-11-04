// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::Outcome;

#[test]
fn only_a_successful_settlement_releases_custody() {
    assert!(confirmed(Ok(())));
    assert!(
        !confirmed(Err(ServiceError::Declined(Outcome::Refused))),
        "refusal can describe live work or a settlement that may still roll back"
    );
}

#[test]
fn any_other_settle_failure_keeps_custody_for_a_retry() {
    for failed in [
        ServiceError::Unserved,
        ServiceError::Broken,
        ServiceError::Declined(Outcome::Failed),
        ServiceError::Short { bytes: 1, items: 1 },
    ] {
        assert!(
            !confirmed(Err(failed)),
            "{failed:?} is not proof of settlement"
        );
    }
}

#[test]
fn cleanup_owns_the_reference_after_the_open_reply_is_gone() {
    let plane = McpDoor::default();
    let reference = String::from("0123456789abcdef0123456789abcdef");
    hold(&plane, 42, &reference, 0);
    drop(reference);
    plane.relays.with_all(|works| {
        let work = works.get(&42).expect("cleanup retains the handle");
        assert_eq!(work.reference, "0123456789abcdef0123456789abcdef");
        assert_eq!(work.until_ms, 0);
        assert!(work.pending.is_none());
        assert!(work.terminal.is_none());
    });
}

#[test]
fn retry_delay_is_exponential_and_capped_without_a_busy_loop() {
    let plane = McpDoor::default();
    hold(&plane, 42, "0123456789abcdef0123456789abcdef", 0);
    plane.relays.with_all(|works| {
        let work = works.get_mut(&42).unwrap();
        let now = 1_000_000_000;
        for step in 0..16 {
            work.defer(Some(now));
            let expected = RETRY_MIN_NS.saturating_mul(1_u64 << step).min(RETRY_MAX_NS);
            assert_eq!(work.retry_at_ns, now + expected);
            assert!(work.retry_at_ns > now);
        }
        work.defer(None);
        assert_eq!(work.retry_at_ns, RETRY_MAX_NS);
    });
}
