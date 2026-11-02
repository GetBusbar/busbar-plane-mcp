// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::service::TrustSightIn;
use busbar_contract::abi::mechanism::ticket::CompletionHandle;

static SIGHT_FAILS: AtomicBool = AtomicBool::new(false);
pub(super) static ITEM_FAILS: AtomicBool = AtomicBool::new(false);
static STATE_FAILS: AtomicBool = AtomicBool::new(false);
static SIGHTS: Mutex<Vec<(CompletionHandle, String)>> = Mutex::new(Vec::new());
static WAKES: Mutex<Vec<Ticket>> = Mutex::new(Vec::new());

pub(super) fn sighted(i: TrustSightIn, out: *mut ServiceOut) -> RawOutcome {
    SIGHTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((i.head.handle, abi_text(i.counterparty).unwrap_or_default()));
    answer(
        out,
        if SIGHT_FAILS.load(Ordering::SeqCst) {
            Outcome::Failed
        } else {
            Outcome::Ready
        },
        TRUST_NEW,
        0,
    )
}

pub(super) extern "C" fn trust_state(
    _: HostCtx,
    _: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    answer(
        out,
        if STATE_FAILS.load(Ordering::SeqCst) {
            Outcome::Failed
        } else {
            Outcome::Ready
        },
        0,
        0,
    )
}

pub(super) extern "C" fn wake(_: HostCtx, ticket: Ticket) {
    WAKES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(ticket);
}

struct Reset;
impl Reset {
    fn new() -> Self {
        *upstreams() = Some(Upstreams::default());
        SIGHTS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        WAKES.lock().unwrap_or_else(PoisonError::into_inner).clear();
        Self
    }
}
impl Drop for Reset {
    fn drop(&mut self) {
        SIGHT_FAILS.store(false, Ordering::SeqCst);
        ITEM_FAILS.store(false, Ordering::SeqCst);
        STATE_FAILS.store(false, Ordering::SeqCst);
        HOLD_LISTS.store(false, Ordering::SeqCst);
    }
}

fn pending_call(d: &Door, unit: u64) {
    assert_eq!(
        d.arrive(unit, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(unit, &Given::attempt(ALICE, "st"));
    assert_eq!(
        d.piece(unit, &Given::caller(ALICE, ST_CALL)).outcome,
        Some(Outcome::Pending)
    );
}

#[test]
fn cancelling_a_list_fetch_wakes_its_joined_call() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open_with(STRICT_SECTION);
    let _held = HoldLists::on();
    pending_call(&d, 700);
    pending_call(&d, 701);
    assert_eq!(lists_to(STATELESS_URL), 1);
    assert_eq!(d.cancel(700).0, Outcome::Ready);
    assert!(
        WAKES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&Ticket {
                slot: 701,
                generation: 1
            }),
        "the joined caller must resume when its fetch owner leaves"
    );
}

#[test]
fn taking_over_an_expired_fetch_keeps_and_wakes_its_joiners() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open_with(STRICT_SECTION);
    let held = HoldLists::on();
    pending_call(&d, 702);
    pending_call(&d, 703);
    MONO.fetch_add(3_600_000_000_000, Ordering::SeqCst);
    pending_call(&d, 704);
    drop(held);
    assert!(d.pump(704, &Given::caller(ALICE, ST_CALL)).far);
    assert!(
        WAKES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&Ticket {
                slot: 703,
                generation: 1
            }),
        "takeover must retain the old fetch's joined callers"
    );
    let before = lists_to(STATELESS_URL);
    assert!(d.pump(703, &Given::caller(ALICE, ST_CALL)).far);
    assert_eq!(
        lists_to(STATELESS_URL),
        before,
        "the joined caller uses the landed takeover"
    );
}

#[test]
fn a_failed_monotonic_read_does_not_replace_a_live_fetch() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open_with(STRICT_SECTION);
    let _held = HoldLists::on();
    pending_call(&d, 705);
    let _failed = ClockFails::on();
    pending_call(&d, 706);
    assert_eq!(
        lists_to(STATELESS_URL),
        1,
        "an unreadable clock cannot prove the owner's lease expired"
    );
}

#[test]
fn each_attempt_records_its_sighting_on_a_fresh_handle() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open_with(STRICT_SECTION);
    call_st(&d, 707);
    d.piece(
        707,
        &Given {
            attempt: 2,
            ..Given::attempt(ALICE, "st")
        },
    );
    d.piece(707, &Given::caller(ALICE, ST_CALL));
    let sights = SIGHTS.lock().unwrap_or_else(PoisonError::into_inner);
    let handles: Vec<_> = sights
        .iter()
        .filter(|(h, _)| h.ticket.slot == 707)
        .map(|(h, _)| *h)
        .collect();
    assert_eq!(handles.len(), 2);
    assert_ne!(
        handles[0], handles[1],
        "the host caches one answer per completion handle"
    );
}

#[test]
fn a_failed_trust_write_is_not_cached_as_a_successful_verification() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open();
    SIGHT_FAILS.store(true, Ordering::SeqCst);
    call_st(&d, 708);
    SIGHT_FAILS.store(false, Ordering::SeqCst);
    call_st(&d, 709);
    assert_eq!(
        lists_to(STATELESS_URL),
        2,
        "a failed receipt must leave the list stale"
    );
}

#[test]
fn a_failed_item_write_is_not_cached_as_a_successful_verification() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open();
    ITEM_FAILS.store(true, Ordering::SeqCst);
    call_st(&d, 710);
    ITEM_FAILS.store(false, Ordering::SeqCst);
    call_st(&d, 711);
    assert_eq!(
        lists_to(STATELESS_URL),
        2,
        "every item receipt must land before freshness is stamped"
    );
}

#[test]
fn an_admin_trust_read_failure_is_reported_as_unavailable() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open();
    STATE_FAILS.store(true, Ordering::SeqCst);
    let view = d.serve_once(712, 1, "st", false);
    assert_eq!(
        view.status,
        503,
        "a failed trust read must not look like an empty pending trust book: {}",
        String::from_utf8_lossy(&view.body)
    );
}

#[test]
fn a_connect_with_a_failed_trust_write_is_not_reported_applied() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open();
    SIGHT_FAILS.store(true, Ordering::SeqCst);
    let view = d.connect(713, "st");
    assert_eq!(
        view.status, 503,
        "the operator must learn that the sighting was not recorded"
    );
}

fn refresh(d: &Door, generation: u64, section: &str) {
    use busbar_contract::abi::mechanism::lifecycle::RefreshIn;
    use busbar_contract::abi::plane::PlaneRefreshOut;
    let i = RefreshIn {
        head: head::<RefreshIn>(life::REFRESH, Ticket::NONE),
        generation,
        settings: octets(section.as_bytes()),
        secrets: std::ptr::null(),
        secrets_len: 0,
    };
    let mut o: PlaneRefreshOut = z();
    o.head = out_head::<PlaneRefreshOut>();
    // SAFETY: The fixture owns this live door instance; the exact input/output frames and every borrowed buffer remain live throughout the synchronous call.
    let ret = unsafe {
        lifecycle().refresh.expect("refresh")(
            d.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    assert_eq!(ret.outcome(), Outcome::Ready);
}

#[test]
fn reloading_a_server_at_another_endpoint_requires_a_new_fetch() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open();
    call_st(&d, 714);
    assert_eq!(lists_to(STATELESS_URL), 1);
    let next = SECTION.replace("https://up.example/st", "https://up.example/down");
    refresh(&d, 2, &next);
    call_st(&d, 715);
    assert!(
        requests_to(DOWN_URL) > 0,
        "the old endpoint's fresh list must not skip verification of the reloaded endpoint"
    );
}

#[test]
fn an_old_generation_fetch_does_not_publish_into_the_new_endpoint_cache() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open();
    let held = HoldLists::on();
    pending_call(&d, 716);
    let next = SECTION.replace("https://up.example/st", "https://up.example/down");
    refresh(&d, 2, &next);
    drop(held);
    assert!(d.pump(716, &Given::caller(ALICE, ST_CALL)).far);
    call_st(&d, 717);
    assert!(
        requests_to(DOWN_URL) > 0,
        "a held old-generation fetch may only freshen its own registration"
    );
}

#[test]
fn a_breaker_refusal_resolves_the_server_from_the_routed_generation() {
    use busbar_contract::abi::plane::{RefusalCode, RefusalIn, RefusalOut, REFUSAL_KERNEL};
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open();
    assert_eq!(
        d.arrive(718, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(718, &Given::attempt(ALICE, "st"));
    refresh(&d, 2, "{}");
    let mut reply = vec![0_u8; 1 << 12];
    let mut fields = [z::<OutField>(); 8];
    let mut arena = vec![0_u8; 1 << 12];
    let mut records = [z::<RecordWrite>(); 8];
    let mut i: RefusalIn = z();
    i.head = head::<RefusalIn>(
        slot::REFUSAL,
        Ticket {
            slot: 718,
            generation: 1,
        },
    );
    i.cause = REFUSAL_KERNEL;
    i.status = 503;
    i.reason = RefusalCode::BreakerOpen.code();
    i.unit = 718;
    i.retry_after_s = 7;
    i.text = str_of("breaker_open");
    i.target = str_of("/mcp");
    (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
    (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
    (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
    (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
    let mut o: RefusalOut = z();
    o.head = out_head::<RefusalOut>();
    // SAFETY: The fixture owns this live door instance; the exact input/output frames and every borrowed buffer remain live throughout the synchronous call.
    let ret = unsafe {
        ops().refusal.expect("refusal")(
            d.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert_eq!(o.status, 503);
    let body: Value = serde_json::from_slice(&reply[..o.reply_written as usize]).unwrap();
    assert_eq!(body["error"]["data"]["server"], json!("st"));
    assert_eq!(body["error"]["data"]["retry_after_ms"], json!(7000));
}

#[test]
fn two_pending_operator_connects_keep_their_own_negotiation() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open();
    let held = HoldLists::on();
    assert_eq!(d.serve_once(719, 0, "fs", false).outcome, Outcome::Pending);
    assert_eq!(d.serve_once(720, 0, "fs", false).outcome, Outcome::Pending);
    // Both connects already own their greeting/list state. Re-entry should resume those wires;
    // replacing the other ticket's negotiation starts an extra greeting on each turn.
    let before = requests_to("https://up.example/sess");
    for unit in [719, 720, 719, 720] {
        assert_eq!(d.serve_once(unit, 0, "fs", true).outcome, Outcome::Pending);
    }
    let after = requests_to("https://up.example/sess");
    drop(held);
    for unit in [719, 720] {
        let mut view = d.serve_once(unit, 0, "fs", true);
        for _ in 0..32 {
            if view.outcome != Outcome::Pending {
                break;
            }
            d.turn();
            view = d.serve_once(unit, 0, "fs", true);
        }
        assert_eq!(
            view.status,
            200,
            "each negotiation must complete: {}",
            String::from_utf8_lossy(&view.body)
        );
    }
    assert_eq!(
        after, before,
        "pending re-entry must not restart another ticket's completed negotiation hops"
    );
}

#[test]
fn a_fetch_started_without_a_clock_keeps_ownership_when_the_clock_recovers() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = Reset::new();
    let d = open_with(STRICT_SECTION);
    let _held = HoldLists::on();
    {
        let _failed = ClockFails::on();
        pending_call(&d, 721);
    }
    pending_call(&d, 722);
    assert_eq!(
        lists_to(STATELESS_URL),
        1,
        "an unknown lease origin is not the epoch: clock recovery must not steal a live fetch"
    );
}
