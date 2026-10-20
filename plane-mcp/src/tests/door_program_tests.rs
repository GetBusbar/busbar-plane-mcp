// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The memo of a stdio child's own requests: decided once, and bounded by forgetting the oldest
//! decision first.

use super::*;

fn key(member: &str, id: u64) -> AnsweredKey {
    (member.to_string(), 1, id.to_string())
}

/// THE MEMO FORGETS ITS OLDEST DECISION FIRST, never a younger one. Evicting by key order instead
/// forgets the alphabetically-first member's live decision, and a second exchange reading that
/// child request would decide it again (answer the child twice, or put one ask to a call twice).
#[test]
fn the_memo_forgets_its_oldest_decision_first() {
    let mut memo = Answered::with_cap(2);
    assert_eq!(memo.decide(key("zeta", 1), || Some(10)), (Some(10), true));
    // Younger, and first in key order.
    assert_eq!(memo.decide(key("alpha", 1), || Some(20)), (Some(20), true));
    // The bound is reached: one decision goes, and it is the oldest.
    assert_eq!(memo.decide(key("mid", 1), || None), (None, true));
    assert_eq!(
        memo.decide(key("alpha", 1), || Some(77)),
        (Some(20), false),
        "the younger decision is still the one made"
    );
    assert_eq!(
        memo.decide(key("zeta", 1), || Some(99)),
        (Some(99), true),
        "the oldest decision was the one forgotten"
    );
}
