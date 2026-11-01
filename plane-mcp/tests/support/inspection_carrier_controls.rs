// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn cancel_driver(door: &Door) {
    let mut i: PlaneCancelIn = z();
    i.cancel = CancelIn {
        head: head::<PlaneCancelIn>(life::CANCEL, DRIVER),
        ticket: DRIVER,
    };
    let mut records = [z::<RecordWrite>(); 16];
    let mut arena = vec![0u8; 4096];
    i.records_buf = records.as_mut_ptr();
    i.records_cap = records.len();
    i.arena_buf = arena.as_mut_ptr();
    i.arena_cap = arena.len();
    let mut o: PlaneCancelOut = z();
    o.cancel.head = out_head::<PlaneCancelOut>();
    // SAFETY: CANCEL with its exact declared types and the test's live instance.
    let ret = lifecycle().cancel.unwrap()(
        door.instance,
        std::ptr::from_ref(&i).cast(),
        std::ptr::from_mut(&mut o).cast(),
    );
    assert_eq!(ret.outcome(), Outcome::Ready);
}

#[test]
fn carrier_inspection_missing_or_cancelled_receipts_never_retire_live_state() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _controls = Controls::new();
    let door = open();
    initialize(&door, 41_000, 7, ALICE);
    let first = start(&door, Some(1));
    assert_eq!(first.outcome, Outcome::Pending);
    let old = first.request.unwrap();
    cancel_driver(&door);
    let current = start(&door, Some(2));
    assert_eq!(current.outcome, Outcome::Pending);
    let stale = inspection_wire::carriers(&old, |_| false);
    let rejected = resume(&door, 2, Some(&stale), 16);
    assert_ne!(rejected.outcome, Outcome::Pending);
    assert!(rejected.request.is_none());
    let next = start(&door, Some(2));
    assert_eq!(
        inspection_wire::sessions(&next.request.unwrap()),
        Some(vec![7])
    );
    let missing = resume(&door, 2, None, 16);
    assert_ne!(missing.outcome, Outcome::Pending);
    assert!(
        missing.error.contains("MissingReceipt"),
        "{}",
        missing.error
    );
}

#[test]
fn carrier_maintenance_on_an_older_host_explains_feature_absence() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _controls = Controls::new();
    let door = open();
    initialize(&door, 42_000, 9, ALICE);
    let unsupported = start(&door, None);
    assert_ne!(unsupported.outcome, Outcome::Pending);
    assert!(
        unsupported.error.contains("Unsupported"),
        "{}",
        unsupported.error
    );
}

#[test]
fn carrier_tick_to_drive_inspection_preserves_the_existing_short_buffer_recall() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _controls = Controls::new();
    let door = open();
    initialize(&door, 43_000, 11, ALICE);
    let _endpoint = legacy_stream(&door, 43_001, ALICE);
    let pending = start(&door, Some(1));
    assert_eq!(pending.outcome, Outcome::Pending);
    let request = pending.request.unwrap();
    let reply = inspection_wire::carriers(&request, |_| true);
    let short = resume(&door, 1, Some(&reply), 0);
    assert_eq!(short.outcome, Outcome::Failed);
    assert!(short.needed > 0);
    assert!(short.request.is_none());
    let recalled = resume(&door, 1, None, short.needed as usize);
    assert_eq!(recalled.outcome, Outcome::Ready, "{}", recalled.error);
}

#[test]
fn a_true_carrier_observation_never_bypasses_the_emit_recheck() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _controls = Controls::new();
    let door = open();
    let opened = line(
        &door,
        44_000,
        13,
        ALICE,
        &json!({"jsonrpc":"2.0","id":"sub","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}),
    );
    assert_eq!(opened.status, 200, "{}", opened.text());
    TICKS.store(
        MONO.load(Ordering::SeqCst) + 60_000_000_000,
        Ordering::SeqCst,
    );
    let pending = start(&door, Some(1));
    let reply = inspection_wire::carriers(&pending.request.unwrap(), |_| true);
    CLOSED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(13);
    let done = resume(&door, 1, Some(&reply), 16);
    assert_eq!(done.outcome, Outcome::Ready, "{}", done.error);
    assert!(EMIT_ATTEMPTS.load(Ordering::SeqCst) > 0);
    assert_eq!(
        EMIT_ACCEPTED.load(Ordering::SeqCst),
        0,
        "the host refused a carrier closed after observation"
    );
    assert!(
        start(&door, Some(1)).request.is_none(),
        "the refused subscription was retired"
    );
}

#[test]
fn extension_pressure_drives_multiple_exact_carrier_batches() {
    use busbar_contract::abi::mechanism::{extensions, inspection};
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _controls = Controls::new();
    let door = open();
    for session in 31..=35 {
        initialize(
            &door,
            45_000 + session,
            session,
            if session % 2 == 0 { ALICE } else { BOB },
        );
    }
    let (mut low, mut high) = (0, inspection::MAX_BYTES);
    while low < high {
        let middle = low + (high - low) / 2;
        if inspection::max_carrier_sessions(middle) > 2 {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    assert_eq!(inspection::max_carrier_sessions(low), 2);
    let overhead = extensions::entry_len("carrier-test-padding", &[]);
    PRESSURE.store((low - overhead) as u64, Ordering::SeqCst);
    let mut pending = start(&door, Some(1));
    let mut seen = Vec::new();
    let mut batches = Vec::new();
    while let Some(request) = pending.request.take() {
        let ids = inspection_wire::sessions(&request).unwrap();
        assert!(ids.len() <= inspection::max_carrier_sessions(low));
        batches.push(ids.len());
        seen.extend(ids);
        let receipt = inspection_wire::carriers(&request, |id| id % 2 == 0);
        pending = resume(&door, 1, Some(&receipt), 16);
    }
    assert_eq!(pending.outcome, Outcome::Ready, "{}", pending.error);
    assert_eq!(
        batches,
        vec![2, 2, 1],
        "the byte budget forces genuine continuation batches"
    );
    assert_eq!(seen, vec![31, 32, 33, 34, 35]);
    let retained = start(&door, Some(1));
    assert_eq!(
        inspection_wire::sessions(&retained.request.unwrap()),
        Some(vec![32, 34])
    );
}
