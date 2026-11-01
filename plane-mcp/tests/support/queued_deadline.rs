// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

static FIXED_NS: AtomicU64 = AtomicU64::new(0);

struct Clock;

impl Drop for Clock {
    fn drop(&mut self) {
        FIXED_NS.store(0, Ordering::SeqCst);
    }
}

pub(super) fn clock(input: *const c_void, out: *mut ServiceOut) -> Option<RawOutcome> {
    let mono = FIXED_NS.load(Ordering::SeqCst);
    if mono == 0 {
        return None;
    }
    // SAFETY: clock_now forwards its SDK-owned input and writable reading.
    let input = unsafe { input.cast::<ClockNowIn>().read() };
    // SAFETY: the host fills the SDK's live reading for this crossing only.
    unsafe {
        (*input.reading).wall_ns = 1_800_000_000_000_000_000 + mono;
        (*input.reading).mono_ns = mono;
    }
    Some(ready(out, 0, 0, 0))
}

#[test]
fn a_freed_stdio_queue_never_sends_at_or_after_its_existing_deadline() {
    for elapsed_ms in [999_u64, 1_000, 1_001] {
        let _serial = fresh();
        let _clock = Clock;
        let start = 100_000_000_000;
        FIXED_NS.store(start, Ordering::SeqCst);
        let d = open_on(
            &UNCONNECTED,
            &json!({"io":{
                "transport":"stdio", "command":"/usr/bin/true", "pin":pin(),
                "timeout":"1s", "grants":{"elicitation":true},
                "tools_allow":{"read_file":{"task_support":"required"}}
            }}),
        );
        create(&d, 1, "io", "io_read_file");
        let first_body = last_nested();
        let second = create(&d, 3, "io", "io_read_file");
        let second_body = last_nested();
        let sent = run(&d, 2, "io", &first_body);
        assert!(sent.far, "{}", sent.text());
        let queued = run(&d, 4, "io", &second_body);
        assert!(!queued.far, "the second call is actually queued");
        d.piece(
            2,
            &Given::far(ALICE, 200, &result_of(&sent, "first finished")),
        );
        FIXED_NS.store(start + elapsed_ms * 1_000_000, Ordering::SeqCst);
        let woke = d.piece(4, &Given::caller(ALICE, b""));
        if elapsed_ms < 1_000 {
            assert!(
                woke.far,
                "a free child receives the unexpired call: {}",
                woke.text()
            );
        } else {
            assert!(
                !woke.far,
                "the expired call never reaches the now-free child: {}",
                woke.text()
            );
            assert_failed(&get(&d, 6, &second), "deadline passed");
        }
    }
}

#[path = "reported_held_turn.rs"]
mod reported_held_turn;
