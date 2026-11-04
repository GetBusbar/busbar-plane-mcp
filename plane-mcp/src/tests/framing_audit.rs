// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Audit regressions for the `Accept` weight reading.

use super::*;

/// The weight's name is the grammar's case-insensitive literal: `Q=0.1` ranks the stream below
/// JSON exactly as `q=0.1` does.
#[test]
fn an_upper_case_weight_is_honoured() {
    assert!(!prefers_event_stream(Some(
        "text/event-stream;Q=0.1, application/json"
    )));
    assert!(!prefers_event_stream(Some(
        "text/event-stream; Q=0.1, application/json"
    )));
    assert!(prefers_event_stream(Some(
        "application/json;Q=0.2, text/event-stream"
    )));
}

/// A malformed weight never ranks its entry as the most preferred: `q=abc`, `q=`, `q=NaN` and an
/// out-of-range `q=2` make the stream unacceptable rather than `q=1`.
#[test]
fn a_malformed_weight_is_not_the_highest_preference() {
    for bad in ["abc", "", "NaN", "2", "-1"] {
        let accept = format!("text/event-stream;q={bad}, application/json;q=0.9");
        assert!(!prefers_event_stream(Some(&accept)), "{accept}");
    }
    assert!(prefers_event_stream(Some(
        "text/event-stream;q=0.9, application/json;q=abc"
    )));
}
