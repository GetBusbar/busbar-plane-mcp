// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

static ENTITLEMENT: AtomicU64 = AtomicU64::new(ENTITLED);

pub(super) fn entitlement() -> u64 {
    ENTITLEMENT.load(Ordering::SeqCst)
}

struct Denied;

impl Denied {
    fn now() -> Self {
        ENTITLEMENT.store(0, Ordering::SeqCst);
        Self
    }
}

impl Drop for Denied {
    fn drop(&mut self) {
        ENTITLEMENT.store(ENTITLED, Ordering::SeqCst);
    }
}

fn updates() -> Vec<Vec<u8>> {
    EMITTED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(_, bytes)| {
            String::from_utf8_lossy(bytes).contains("notifications/resources/updated")
        })
        .map(|(_, bytes)| bytes.clone())
        .collect()
}

fn announce(door: &Door, unit: u64) {
    call_st(door, unit);
    let far = format!(
        "event: message\ndata: {MEMBER_UPDATE}\n\nevent: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{{\"content\":[],\"resultType\":\"complete\"}}}}\n\n"
    );
    assert_eq!(
        door.piece(
            unit,
            &Given::far(
                ALICE,
                200,
                vec![("content-type", "text/event-stream")],
                far.as_bytes()
            )
        )
        .status,
        200
    );
}

fn short_ack(door: &Door, unit: u64, session: u64) {
    assert_eq!(
        door.line(unit, session, LINE_LISTEN).outcome,
        Outcome::Ready
    );
    let mut reply = [0u8; 1];
    let mut arena = vec![0u8; 1 << 14];
    let mut fields = [z::<OutField>(); 16];
    let mut units = [z::<UnitCount>(); 8];
    let mut records = [z::<RecordWrite>(); 16];
    let mut input: OnPieceIn = z();
    input.head = head::<OnPieceIn>(
        slot::ON_PIECE,
        Ticket {
            slot: u32::try_from(unit).unwrap(),
            generation: 1,
        },
    );
    input.unit = unit;
    input.from = FROM_CALLER;
    input.flags = PIECE_LAST;
    input.caller_ref = str_of(ALICE);
    input.bytes = octets(LINE_LISTEN);
    input.reply_buf = reply.as_mut_ptr();
    input.reply_cap = reply.len();
    input.arena_buf = arena.as_mut_ptr();
    input.arena_cap = arena.len();
    input.fields_buf = fields.as_mut_ptr();
    input.fields_cap = fields.len();
    input.units_buf = units.as_mut_ptr();
    input.units_cap = units.len();
    input.records_buf = records.as_mut_ptr();
    input.records_cap = records.len();
    let mut output: OnPieceOut = z();
    output.head = out_head::<OnPieceOut>();
    // SAFETY: all buffers are live and correctly sized for this actual door crossing.
    let ret = unsafe {
        ops().on_piece.unwrap()(
            door.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert_ne!(output.more, 0, "only one acknowledgement byte fit");
}

#[test]
fn a_line_subscription_does_not_emit_before_its_acknowledgement_finishes() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    EMITTED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    let door = open();
    short_ack(&door, 21_000, 71);
    announce(&door, 21_001);
    door.turn();
    assert!(
        updates().is_empty(),
        "an update overtook a partially written acknowledgement"
    );
    let remainder = door.piece(21_000, &Given::caller(ALICE, b""));
    assert!(remainder.done, "the acknowledgement now finishes");
    door.turn();
    assert_eq!(
        updates().len(),
        1,
        "the retained update follows the delivered acknowledgement"
    );
}

#[test]
fn cancelling_a_partial_acknowledgement_removes_its_provisional_subscription() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    EMITTED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    let door = open();
    short_ack(&door, 21_050, 75);
    assert_eq!(door.cancel(21_050).0, Outcome::Ready);
    announce(&door, 21_051);
    door.turn();
    assert!(
        updates().is_empty(),
        "the canceled opening must retain no subscription"
    );
}

#[test]
fn a_late_cancel_of_the_completed_acknowledgement_does_not_cancel_the_subscription() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    EMITTED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    let door = open();
    assert_eq!(door.line(21_070, 76, LINE_LISTEN).outcome, Outcome::Ready);
    let ack = door.piece(21_070, &Given::caller(ALICE, LINE_LISTEN));
    assert!(ack.done && ack.text().contains("acknowledged"));
    assert_eq!(door.cancel(21_070).0, Outcome::Ready);
    announce(&door, 21_071);
    door.turn();
    assert_eq!(
        updates().len(),
        1,
        "a completed subscription outlives its opening unit"
    );
}

#[test]
fn the_real_reconfirm_path_ends_a_line_subscription_after_revocation() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    EMITTED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    let door = open();
    assert_eq!(door.line(21_100, 72, LINE_LISTEN).outcome, Outcome::Ready);
    assert!(door
        .piece(21_100, &Given::caller(ALICE, LINE_LISTEN))
        .text()
        .contains("acknowledged"));
    let _denied = Denied::now();
    let ping = br#"{"jsonrpc":"2.0","id":99,"method":"ping"}"#;
    assert_eq!(door.line(21_101, 72, ping).outcome, Outcome::Ready);
    door.piece(21_101, &Given::caller(ALICE, ping));
    door.turn();
    let emitted = EMITTED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert!(
        emitted.iter().any(|(session, bytes)| *session == 72
            && String::from_utf8_lossy(bytes).contains("identity_not_live")),
        "actual re-confirmation must end the held subscription: {emitted:?}"
    );
}

#[test]
fn instance_subscription_exhaustion_does_not_blame_a_fresh_caller() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let door = open();
    let mut index = 0u64;
    let refusal = loop {
        let owner = format!("{:032x}", index + 1);
        let unit = 25_000 + index;
        assert_eq!(
            door.line(unit, index + 1, LINE_LISTEN).outcome,
            Outcome::Ready
        );
        let answer = door.piece(unit, &Given::caller(&owner, LINE_LISTEN));
        if answer.status != 200 {
            break answer;
        }
        index += 1;
    };
    assert_eq!(refusal.status, 429, "{}", refusal.text());
    assert_eq!(
        refusal.json()["error"]["data"]["reason"],
        "subscription_capacity",
        "the newly introduced caller has no other subscription: {}",
        refusal.text()
    );
    let cancel =
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":5}}"#;
    assert_eq!(door.line(50_000, 1, cancel).outcome, Outcome::Ready);
    door.piece(
        50_000,
        &Given::caller("00000000000000000000000000000001", cancel),
    );
    assert_eq!(
        door.line(50_001, index + 1, LINE_LISTEN).outcome,
        Outcome::Ready
    );
    let owner = format!("{:032x}", index + 1);
    assert_eq!(
        door.piece(50_001, &Given::caller(&owner, LINE_LISTEN))
            .status,
        200
    );
}
