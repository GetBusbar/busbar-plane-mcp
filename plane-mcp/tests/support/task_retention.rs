// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

static RETAIN_MS: AtomicU64 = AtomicU64::new(300_000);
static SUPPORTED: AtomicBool = AtomicBool::new(true);
static ABSENT: AtomicBool = AtomicBool::new(false);
static HOLD: AtomicBool = AtomicBool::new(false);
static HELD: Mutex<Option<Vec<u8>>> = Mutex::new(None);

pub(super) fn hold(request: &[u8]) -> bool {
    if !HOLD.load(Ordering::SeqCst) {
        return false;
    }
    *HELD.lock().unwrap_or_else(PoisonError::into_inner) = Some(request.to_vec());
    true
}

pub(super) fn now_ms() -> u64 {
    1_800_000_000_000 + task_state_lifecycle::mono_ns() / 1_000_000
}

pub(super) fn receipt(request: &[u8]) -> Vec<u8> {
    let Some(reference) = inspection_wire::reference(request) else {
        return inspection_wire::failed(request, 4);
    };
    with_book(|b| {
        let ticket = Ticket {
            slot: u32::from_le_bytes(request[1..5].try_into().unwrap()),
            generation: u32::from_le_bytes(request[5..9].try_into().unwrap()),
        };
        match b.works.values().find(|w| {
            w.reference.as_bytes() == reference && b.principals.get(&ticket) == Some(&w.owner)
        }) {
            Some(work) => inspection_wire::work(
                request,
                now_ms(),
                work.opened_ms,
                RETAIN_MS.load(Ordering::SeqCst),
                work.settled_ms,
            ),
            None => inspection_wire::failed(request, 2),
        }
    })
}

pub(super) fn input(receipt: Option<&[u8]>) -> Vec<u8> {
    if SUPPORTED.load(Ordering::SeqCst) {
        inspection_wire::input(1, receipt)
    } else {
        Vec::new()
    }
}

pub(super) fn sweep() {
    let now = now_ms();
    let retain = RETAIN_MS.load(Ordering::SeqCst);
    with_book(|b| {
        b.works.retain(|_, work| {
            work.live
                || work
                    .settled_ms
                    .is_none_or(|at| at.checked_add(retain).is_none_or(|expires| expires > now))
        })
    });
}

pub(super) fn absent(out: *mut ServiceOut) -> Option<RawOutcome> {
    ABSENT.load(Ordering::SeqCst).then(|| ready(out, 0, 0, 0))
}

struct Controls;
impl Controls {
    fn new(retain: u64) -> Self {
        RETAIN_MS.store(retain, Ordering::SeqCst);
        SUPPORTED.store(true, Ordering::SeqCst);
        ABSENT.store(false, Ordering::SeqCst);
        HOLD.store(false, Ordering::SeqCst);
        *HELD.lock().unwrap_or_else(PoisonError::into_inner) = None;
        task_state_lifecycle::find_failure(false);
        task_state_lifecycle::find_pending(false);
        Controls
    }
}
impl Drop for Controls {
    fn drop(&mut self) {
        RETAIN_MS.store(300_000, Ordering::SeqCst);
        SUPPORTED.store(true, Ordering::SeqCst);
        ABSENT.store(false, Ordering::SeqCst);
        HOLD.store(false, Ordering::SeqCst);
        *HELD.lock().unwrap_or_else(PoisonError::into_inner) = None;
        task_state_lifecycle::find_failure(false);
        task_state_lifecycle::find_pending(false);
    }
}

#[test]
fn task_ttl_tracks_host_settlement_and_current_retention_rebinding() {
    let _serial = fresh();
    let _controls = Controls::new(60_000);
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let live = get(&d, 2, &task).json();
    let created_ms = with_book(|b| {
        let work = b.works.values().find(|w| w.reference == task).unwrap();
        String::from_utf8_lossy(&work.record)
            .split('|')
            .nth(2)
            .unwrap()
            .parse::<u64>()
            .unwrap()
    });
    assert!(
        live["result"]["ttlMs"]
            .as_u64()
            .is_some_and(|ttl| (60_000..300_000).contains(&ttl)),
        "{live}"
    );
    let sent = run(&d, 3, "st", &last_nested());
    assert!(sent.far);
    d.piece(3, &Given::far(ALICE, 200, &result_of(&sent, "retained")));
    let settled_ms = with_book(|b| {
        b.works
            .values()
            .find(|w| w.reference == task)
            .unwrap()
            .settled_ms
            .unwrap()
    });
    assert_eq!(
        get(&d, 4, &task).json()["result"]["ttlMs"],
        json!(settled_ms + 60_000 - created_ms)
    );
    RETAIN_MS.store(3_600_000, Ordering::SeqCst);
    assert_eq!(
        get(&d, 5, &task).json()["result"]["ttlMs"],
        json!(settled_ms + 3_600_000 - created_ms)
    );
}

#[test]
fn task_results_outlive_cache_eviction_and_cleanup_recovers_after_restart() {
    let _serial = fresh();
    let _controls = Controls::new(3_600_000);
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let sent = run(&d, 2, "st", &last_nested());
    let result = "one hour".repeat(10_000);
    d.piece(2, &Given::far(ALICE, 200, &result_of(&sent, &result)));
    MONO.fetch_add(301_000_000_000, Ordering::SeqCst);
    create(&d, 3, "st", "st_read_file");
    assert_completed(&get(&d, 4, &task), &result);
    drop(d);
    let after_restart = open(&section());
    create(&after_restart, 5, "st", "st_read_file");
    assert_completed(&get(&after_restart, 6, &task), &result);
    RETAIN_MS.store(7_200_000, Ordering::SeqCst);
    MONO.fetch_add(3_600_000_000_000, Ordering::SeqCst);
    create(&after_restart, 7, "st", "st_read_file");
    assert_completed(&get(&after_restart, 8, &task), &result);
    MONO.fetch_add(3_600_000_000_000, Ordering::SeqCst);
    create(&after_restart, 9, "st", "st_read_file");
    create(&after_restart, 10, "st", "st_read_file");
    assert!(
        with_book(|b| b
            .records
            .keys()
            .any(|key| key.starts_with(format!("{task}/").as_bytes()))),
        "large result cleanup uses the existing chunk batch"
    );
    drop(after_restart);
    let recovery = open(&section());
    create(&recovery, 11, "st", "st_read_file");
    create(&recovery, 12, "st", "st_read_file");
    assert!(with_book(|b| b
        .records
        .keys()
        .all(|key| !key.starts_with(format!("{task}/").as_bytes()))));
}

#[test]
fn cleanup_defers_failed_reads_and_never_uses_another_principals_absence() {
    let _serial = fresh();
    let _controls = Controls::new(3_600_000);
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let sent = run(&d, 2, "st", &last_nested());
    d.piece(2, &Given::far(ALICE, 200, &result_of(&sent, "protected")));
    MONO.fetch_add(301_000_000_000, Ordering::SeqCst);
    task_state_lifecycle::find_failure(true);
    create(&d, 3, "st", "st_read_file");
    task_state_lifecycle::find_failure(false);
    assert_completed(&get(&d, 4, &task), "protected");
    ABSENT.store(true, Ordering::SeqCst);
    let body = call("st_read_file", &json!({}));
    let bob = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
    assert_eq!(d.arrive(5, &body).outcome, Outcome::Ready);
    d.piece(5, &Given::attempt(bob, "st"));
    assert_eq!(d.piece(5, &Given::caller(bob, &body)).status, 200);
    ABSENT.store(false, Ordering::SeqCst);
    assert_completed(&get(&d, 6, &task), "protected");
}

#[test]
fn a_pending_cleanup_lookup_keeps_its_state_and_preserves_retained_results() {
    let _serial = fresh();
    let _controls = Controls::new(3_600_000);
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let sent = run(&d, 2, "st", &last_nested());
    d.piece(
        2,
        &Given::far(ALICE, 200, &result_of(&sent, "pending cleanup")),
    );
    MONO.fetch_add(301_000_000_000, Ordering::SeqCst);
    task_state_lifecycle::find_pending(true);
    let body = call("st_read_file", &json!({}));
    assert_eq!(d.arrive(3, &body).outcome, Outcome::Ready);
    d.piece(3, &Given::attempt(ALICE, "st"));
    assert_eq!(d.piece(3, &Given::caller(ALICE, &body)).status, 0);
    assert!(with_book(|b| b
        .records
        .keys()
        .any(|k| k.starts_with(format!("{task}/").as_bytes()))));
    task_state_lifecycle::find_pending(false);
    assert_eq!(d.piece(3, &Given::caller(ALICE, &body)).status, 200);
    assert_completed(&get(&d, 4, &task), "pending cleanup");
}

#[path = "inspection_task_controls.rs"]
mod inspection_controls;
