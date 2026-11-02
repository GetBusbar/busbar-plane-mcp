// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn an_older_host_gets_an_explained_task_failure_without_a_fictitious_ttl() {
    let _serial = fresh();
    let _controls = Controls::new(60_000);
    SUPPORTED.store(false, Ordering::SeqCst);
    let d = open(&section());
    let body = call("st_read_file", &json!({}));
    assert_eq!(d.arrive(1, &body).outcome, Outcome::Ready);
    d.piece(1, &Given::attempt(ALICE, "st"));
    let refused = d.piece(1, &Given::caller(ALICE, &body));
    assert_ne!(refused.status, 200, "{}", refused.text());
    assert!(refused.text().contains("Unsupported"), "{}", refused.text());
    assert!(refused.json().get("result").is_none());
}

#[test]
fn a_full_width_retention_overflow_is_refused_on_the_actual_task_door() {
    let _serial = fresh();
    let _controls = Controls::new(u64::MAX);
    let d = open(&section());
    let body = call("st_read_file", &json!({}));
    assert_eq!(d.arrive(1, &body).outcome, Outcome::Ready);
    d.piece(1, &Given::attempt(ALICE, "st"));
    let refused = d.piece(1, &Given::caller(ALICE, &body));
    assert_ne!(refused.status, 200, "{}", refused.text());
    assert!(refused.text().contains("overflows"), "{}", refused.text());
    assert!(refused.json().get("result").is_none());
}

#[test]
fn missing_ttl_inspection_never_prevents_cancelling_existing_work() {
    let _serial = fresh();
    let _controls = Controls::new(60_000);
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    SUPPORTED.store(false, Ordering::SeqCst);
    let body = verb("tasks/cancel", &task, &json!({}));
    assert_eq!(d.arrive(2, &body).outcome, Outcome::Ready);
    assert_eq!(d.piece(2, &Given::caller(ALICE, &body)).status, 200);
    let row = String::from_utf8(settle_of(&task).unwrap()).unwrap();
    assert!(row.starts_with("t1|cancelled|"), "{row}");
}

#[test]
fn cancelling_a_task_inspection_preserves_cleanup_and_rejects_the_late_cycle() {
    let _serial = fresh();
    let _controls = Controls::new(60_000);
    HOLD.store(true, Ordering::SeqCst);
    let d = open(&section());
    let body = call("st_read_file", &json!({}));
    assert_eq!(d.arrive(1, &body).outcome, Outcome::Ready);
    d.piece(1, &Given::attempt(ALICE, "st"));
    assert_eq!(d.piece(1, &Given::caller(ALICE, &body)).status, 0);
    let request = HELD
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap();
    let task = String::from_utf8(inspection_wire::reference(&request).unwrap().to_vec()).unwrap();
    assert_eq!(d.cancel_with(1, 16).0, Outcome::Ready);
    let receipt = receipt(&request);
    let ext = inspection_wire::input(1, Some(&receipt));
    let mut i: OnPieceIn = z();
    i.head = head::<OnPieceIn>(
        slot::ON_PIECE,
        Ticket {
            slot: 1,
            generation: 1,
        },
    );
    i.head.flags |= inspection_wire::RESUME;
    i.head.extensions = octets(&ext);
    i.unit = 1;
    i.from = FROM_CALLER;
    i.caller_ref = str_of(ALICE);
    let mut o: OnPieceOut = z();
    o.head = out_head::<OnPieceOut>();
    // SAFETY: the old cancelled unit is deliberately called with a valid empty piece and receipt.
    // SAFETY: The fixture owns this live door instance; the exact input/output frames and every borrowed buffer remain live throughout the synchronous call.
    let late = unsafe {
        ops().on_piece.unwrap()(
            d.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    assert_eq!(late.outcome(), Outcome::Refused);
    assert!(inspection_wire::request(&o.head).is_none());
    HOLD.store(false, Ordering::SeqCst);
    drop(d);
    let recovered = open(&section());
    create(&recovered, 2, "st", "st_read_file");
    let row =
        String::from_utf8(settle_of(&task).expect("the cancel's durable index survives restart"))
            .unwrap();
    assert!(row.starts_with("t1|cancelled|"), "{row}");
}
