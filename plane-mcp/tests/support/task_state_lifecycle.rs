// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const FIND: u64 = 1;
const CLAIM: u64 = 2;
const RESUME: u64 = 4;
const LIVE_LIST: u64 = 8;
const CLAIM_PENDING: u64 = 16;
const RESUME_PENDING: u64 = 32;
const FIND_PENDING: u64 = 64;

static FAIL: AtomicU64 = AtomicU64::new(0);
static RETAIN_MS: AtomicU64 = AtomicU64::new(u64::MAX);
static FIXED_MONO_NS: AtomicU64 = AtomicU64::new(0);

pub(super) fn mono_ns() -> u64 {
    let fixed = FIXED_MONO_NS.load(Ordering::SeqCst);
    if fixed == 0 {
        MONO.load(Ordering::SeqCst)
    } else {
        fixed
    }
}

pub(super) fn find_failure(fail: bool) {
    if fail {
        FAIL.fetch_or(FIND, Ordering::SeqCst);
    } else {
        FAIL.fetch_and(!FIND, Ordering::SeqCst);
    }
}

pub(super) fn find_pending(pending: bool) {
    if pending {
        FAIL.fetch_or(FIND_PENDING, Ordering::SeqCst);
    } else {
        FAIL.fetch_and(!FIND_PENDING, Ordering::SeqCst);
    }
}

struct Controls;

impl Controls {
    fn new() -> Self {
        FAIL.store(0, Ordering::SeqCst);
        RETAIN_MS.store(u64::MAX, Ordering::SeqCst);
        FIXED_MONO_NS.store(0, Ordering::SeqCst);
        Controls
    }
}

impl Drop for Controls {
    fn drop(&mut self) {
        FAIL.store(0, Ordering::SeqCst);
        RETAIN_MS.store(u64::MAX, Ordering::SeqCst);
        FIXED_MONO_NS.store(0, Ordering::SeqCst);
    }
}

pub(super) fn clock(input: *const c_void, out: *mut ServiceOut) -> Option<RawOutcome> {
    let mono = FIXED_MONO_NS.load(Ordering::SeqCst);
    if mono == 0 {
        return None;
    }
    // SAFETY: this hook is called only by clock_now with its SDK-owned reading.
    let i = unsafe { input.cast::<ClockNowIn>().read() };
    // SAFETY: the host owns the writable ClockReading the SDK lent for this call.
    unsafe {
        (*i.reading).wall_ns = 1_800_000_000_000_000_000 + mono;
        (*i.reading).mono_ns = mono;
    }
    Some(ready(out, 0, 0, 0))
}

pub(super) fn fault(
    service: &str,
    input: *const c_void,
    out: *mut ServiceOut,
) -> Option<RawOutcome> {
    let flags = FAIL.load(Ordering::SeqCst);
    if (service == "records.claim" && flags & CLAIM_PENDING != 0)
        || (service == "work.resume" && flags & RESUME_PENDING != 0)
        || (service == "work.find" && flags & FIND_PENDING != 0)
    {
        return Some(answer(out, Outcome::Pending, 0, 0, 0));
    }
    let bit = match service {
        "work.find" => FIND,
        "records.claim" => CLAIM,
        "work.resume" => RESUME,
        "records.list" => {
            // SAFETY: this hook is called only by the corresponding host service.
            let i = unsafe { input.cast::<RecordsListIn>().read() };
            if !str_bytes(i.prefix).ends_with(b"~/") {
                return None;
            }
            LIVE_LIST
        }
        _ => return None,
    };
    if FAIL.load(Ordering::SeqCst) & bit != 0 {
        return Some(answer(out, Outcome::Failed, 0, 0, 0));
    }
    if service == "work.find" {
        let retain = RETAIN_MS.load(Ordering::SeqCst);
        if retain != u64::MAX {
            // SAFETY: this hook is called only by work_find with the SDK's input.
            let i = unsafe { input.cast::<WorkFindIn>().read() };
            let reference = String::from_utf8_lossy(&str_bytes(i.reference)).into_owned();
            let now = 1_800_000_000_000 + MONO.load(Ordering::SeqCst) / 1_000_000;
            with_book(|b| {
                b.works.retain(|_, work| {
                    if work.live || work.reference != reference {
                        return true;
                    }
                    work.settled_ms
                        .is_none_or(|at| now.saturating_sub(at) <= retain)
                });
            });
        }
    }
    None
}

#[test]
fn an_acknowledged_update_survives_a_poll_before_its_records_land() {
    let _serial = fresh();
    let _controls = Controls::new();
    let d = open(&confirm_section());
    let task = create(&d, 1, "st", "st_read_file");
    let parked = run(&d, 2, "st", &last_nested());
    assert!(!parked.far, "{}", parked.text());
    let before = with_book(|b| b.records.clone());
    let update = verb(
        "tasks/update",
        &task,
        &json!({"inputResponses":{"confirm":{"action":"accept","content":{}}}}),
    );
    assert_eq!(d.arrive(3, &update).outcome, Outcome::Ready);
    assert_eq!(d.piece(3, &Given::caller(ALICE, &update)).status, 200);
    let resumed = last_nested();

    with_book(|b| b.records = before);
    assert_eq!(get(&d, 4, &task).json()["result"]["status"], "working");
    let sent = run(&d, 5, "st", &resumed);
    assert!(sent.far, "the acknowledged resume runs: {}", sent.text());
    d.piece(5, &Given::far(ALICE, 200, &result_of(&sent, "resumed")));
    assert_completed(&get(&d, 6, &task), "resumed");
}

#[test]
fn a_same_clock_partial_update_survives_a_poll_of_older_live_records() {
    let _serial = fresh();
    let _controls = Controls::new();
    FIXED_MONO_NS.store(MONO.load(Ordering::SeqCst), Ordering::SeqCst);
    let mut config = confirm_section();
    let confirm = config["st"]["tools_allow"]["read_file"]["task_ask_caller"][0]["confirm"].clone();
    config["st"]["tools_allow"]["read_file"]["task_ask_caller"][0]["second"] = confirm;
    let d = open(&config);
    let task = create(&d, 1, "st", "st_read_file");
    assert!(!run(&d, 2, "st", &last_nested()).far);
    let before = with_book(|b| b.records.clone());
    let first = verb(
        "tasks/update",
        &task,
        &json!({"inputResponses":{"confirm":{"action":"accept","content":{}}}}),
    );
    assert_eq!(d.arrive(3, &first).outcome, Outcome::Ready);
    assert_eq!(d.piece(3, &Given::caller(ALICE, &first)).status, 200);
    with_book(|b| b.records = before);
    let read = get(&d, 4, &task).json();
    assert_eq!(read["result"]["status"], "input_required");
    assert!(
        read["result"]["inputRequests"].get("confirm").is_none(),
        "the acknowledged partial answer was lost: {read}"
    );
    assert!(read["result"]["inputRequests"].get("second").is_some());
    let second = verb(
        "tasks/update",
        &task,
        &json!({"inputResponses":{"second":{"action":"accept","content":{}}}}),
    );
    assert_eq!(d.arrive(5, &second).outcome, Outcome::Ready);
    assert_eq!(d.piece(5, &Given::caller(ALICE, &second)).status, 200);
    let sent = run(&d, 6, "st", &last_nested());
    assert!(
        sent.far,
        "both acknowledged answers allow the run: {}",
        sent.text()
    );
    d.piece(
        6,
        &Given::far(ALICE, 200, &result_of(&sent, "both answers")),
    );
    assert_completed(&get(&d, 7, &task), "both answers");
}

#[test]
fn a_same_clock_update_survives_a_poll_while_its_resume_bind_is_pending() {
    let _serial = fresh();
    let _controls = Controls::new();
    FIXED_MONO_NS.store(MONO.load(Ordering::SeqCst), Ordering::SeqCst);
    let d = open(&confirm_section());
    let task = create(&d, 1, "st", "st_read_file");
    assert!(!run(&d, 2, "st", &last_nested()).far);
    let before = with_book(|b| b.records.clone());
    let update = verb(
        "tasks/update",
        &task,
        &json!({"inputResponses":{"confirm":{"action":"accept","content":{}}}}),
    );
    assert_eq!(d.arrive(3, &update).outcome, Outcome::Ready);
    assert_eq!(d.piece(3, &Given::caller(ALICE, &update)).status, 200);
    FAIL.store(RESUME_PENDING, Ordering::SeqCst);
    let waiting = run(&d, 4, "st", &last_nested());
    assert!(!waiting.far);
    assert_eq!(waiting.status, 0, "work.resume is still pending");
    with_book(|b| b.records = before);
    assert_eq!(get(&d, 5, &task).json()["result"]["status"], "working");
    FAIL.store(0, Ordering::SeqCst);
    let sent = d.piece(4, &Given::caller(ALICE, b""));
    assert!(
        sent.far,
        "the claimed resume binds and runs once: {}",
        sent.text()
    );
    d.piece(
        4,
        &Given::far(ALICE, 200, &result_of(&sent, "pending bind")),
    );
    assert_completed(&get(&d, 6, &task), "pending bind");
}

#[test]
fn host_failures_while_binding_fail_the_owned_task_in_words() {
    for (bit, service) in [(FIND, "work.find"), (RESUME, "work.resume")] {
        let _serial = fresh();
        let _controls = Controls::new();
        let d = open(&section());
        let task = create(&d, 1, "st", "st_read_file");
        FAIL.store(bit, Ordering::SeqCst);
        let sent = run(&d, 2, "st", &last_nested());
        assert!(!sent.far, "{}", sent.text());
        FAIL.store(0, Ordering::SeqCst);
        assert_failed(&get(&d, 3, &task), service);
        assert_failed(&get(&open(&section()), 4, &task), service);
        let row = String::from_utf8(settle_of(&task).expect("the failed run was settled")).unwrap();
        assert!(row.starts_with("t1|failed|"), "{row}");
    }
}

#[test]
fn an_ambiguous_claim_failure_never_settles_another_nodes_running_task() {
    let _serial = fresh();
    let _controls = Controls::new();
    let owner = open(&section());
    let other = open(&section());
    let task = create(&owner, 1, "st", "st_read_file");
    let body = last_nested();
    FAIL.store(CLAIM_PENDING, Ordering::SeqCst);
    let waiting = run(&other, 2, "st", &body);
    assert!(!waiting.far);
    assert_eq!(
        waiting.status, 0,
        "the second node is waiting for its claim"
    );
    FAIL.store(0, Ordering::SeqCst);
    let sent = run(&owner, 3, "st", &body);
    assert!(
        sent.far,
        "the first node owns and runs the task: {}",
        sent.text()
    );
    FAIL.store(CLAIM, Ordering::SeqCst);
    let unavailable = other.piece(2, &Given::caller(ALICE, b""));
    assert_eq!(unavailable.status, 503, "{}", unavailable.text());
    assert_eq!(unavailable.json()["error"]["code"], -32603);
    assert!(unavailable.json()["error"]["message"]
        .as_str()
        .is_some_and(|m| m.contains("records.claim")));
    FAIL.store(0, Ordering::SeqCst);
    assert!(
        settle_of(&task).is_none(),
        "the ambiguous claimant settled nobody's work"
    );
    for (unit, door) in [(4, &owner), (5, &other)] {
        assert_eq!(get(door, unit, &task).json()["result"]["status"], "working");
    }
    owner.piece(
        3,
        &Given::far(ALICE, 200, &result_of(&sent, "exclusive owner")),
    );
    assert_completed(&get(&owner, 6, &task), "exclusive owner");
    assert_completed(&get(&other, 7, &task), "exclusive owner");
}

#[test]
fn a_find_failure_followed_by_an_ambiguous_claim_failure_settles_nothing() {
    let _serial = fresh();
    let _controls = Controls::new();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    FAIL.store(FIND | CLAIM, Ordering::SeqCst);
    let unavailable = run(&d, 2, "st", &last_nested());
    assert_eq!(unavailable.status, 503, "{}", unavailable.text());
    assert_eq!(unavailable.json()["error"]["code"], -32603);
    FAIL.store(0, Ordering::SeqCst);
    assert!(settle_of(&task).is_none());
    assert_eq!(get(&d, 3, &task).json()["result"]["status"], "working");
}

#[test]
fn a_find_failure_never_fails_a_different_or_already_running_call() {
    for different in [false, true] {
        let _serial = fresh();
        let _controls = Controls::new();
        let d = open(&section());
        let task = create(&d, 1, "st", "st_read_file");
        let body = last_nested();
        let mut wrong: Value = serde_json::from_slice(&body).unwrap();
        if different {
            wrong["params"]["arguments"] = json!({"not":"the admitted call"});
        } else {
            assert!(run(&d, 2, "st", &body).far);
        }
        FAIL.store(FIND, Ordering::SeqCst);
        let refused = run(&d, 3, "st", &serde_json::to_vec(&wrong).unwrap());
        assert_eq!(refused.status, 400, "{}", refused.text());
        FAIL.store(0, Ordering::SeqCst);
        assert_eq!(get(&d, 4, &task).json()["result"]["status"], "working");
        assert!(settle_of(&task).is_none());
    }
}

#[test]
fn a_find_failure_on_another_node_never_claims_or_settles_an_unheld_task() {
    let _serial = fresh();
    let _controls = Controls::new();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let other = open(&section());
    FAIL.store(FIND, Ordering::SeqCst);
    let refused = run(&other, 2, "st", &last_nested());
    assert_eq!(refused.status, 400, "{}", refused.text());
    FAIL.store(0, Ordering::SeqCst);
    assert_eq!(get(&d, 3, &task).json()["result"]["status"], "working");
    assert!(settle_of(&task).is_none());
}

#[test]
fn a_failed_find_never_lets_another_principal_fail_or_take_the_local_task() {
    let _serial = fresh();
    let _controls = Controls::new();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let body = last_nested();
    let bob = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
    FAIL.store(FIND, Ordering::SeqCst);
    assert_eq!(d.arrive_run(2, &body).outcome, Outcome::Ready);
    d.piece(2, &Given::attempt(bob, "st"));
    let refused = d.piece(2, &Given::caller(bob, &body));
    assert_eq!(refused.status, 400, "{}", refused.text());
    FAIL.store(0, Ordering::SeqCst);
    assert_eq!(get(&d, 3, &task).json()["result"]["status"], "working");
    assert!(settle_of(&task).is_none());
    assert!(run(&d, 4, "st", &body).far);
}

#[test]
fn an_unreadable_terminal_live_record_is_left_for_a_later_sweep() {
    let _serial = fresh();
    let _controls = Controls::new();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let sent = run(&d, 2, "st", &last_nested());
    assert!(sent.far, "{}", sent.text());
    with_book(|b| b.fail_settles = 1);
    d.piece(2, &Given::far(ALICE, 200, &result_of(&sent, "owed result")));
    assert!(settle_of(&task).is_none());
    drop(d);
    MONO.fetch_add(600_000_000_000, Ordering::SeqCst);
    let other = open(&section());
    FAIL.store(LIVE_LIST, Ordering::SeqCst);
    create(&other, 3, "st", "st_read_file");
    assert!(
        settle_of(&task).is_none(),
        "a failed read must not cancel an owed completion"
    );
    FAIL.store(0, Ordering::SeqCst);
    assert_completed(&get(&other, 4, &task), "owed result");
    create(&other, 5, "st", "st_read_file");
    let row = String::from_utf8(settle_of(&task).expect("the later sweep settles it")).unwrap();
    assert!(row.starts_with("t1|completed|"), "{row}");
    assert_completed(&get(&open(&section()), 6, &task), "owed result");
}

#[test]
fn task_verbs_report_a_host_read_failure_as_internal_and_leave_work_live() {
    let _serial = fresh();
    let _controls = Controls::new();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    FAIL.store(FIND, Ordering::SeqCst);
    for (unit, method) in [(2, "tasks/get"), (3, "tasks/update"), (4, "tasks/cancel")] {
        let body = verb(method, &task, &json!({}));
        assert_eq!(d.arrive(unit, &body).outcome, Outcome::Ready);
        let read = d.piece(unit, &Given::caller(ALICE, &body));
        assert_eq!(read.json()["error"]["code"], -32603, "{}", read.text());
        assert!(read.json()["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("work.find")));
        assert!(settle_of(&task).is_none());
    }
    FAIL.store(0, Ordering::SeqCst);
    assert_eq!(get(&d, 5, &task).json()["result"]["status"], "working");
    assert_eq!(get(&d, 6, "unknown-task").json()["error"]["code"], -32602);
}

#[test]
fn a_locally_held_result_is_unavailable_after_the_hosts_actual_retention() {
    let _serial = fresh();
    let _controls = Controls::new();
    RETAIN_MS.store(60_000, Ordering::SeqCst);
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let sent = run(&d, 2, "st", &last_nested());
    assert!(sent.far, "{}", sent.text());
    d.piece(2, &Given::far(ALICE, 200, &result_of(&sent, "retained")));
    assert_completed(&get(&d, 3, &task), "retained");
    MONO.fetch_add(61_000_000_000, Ordering::SeqCst);
    for (unit, door) in [(4, &d), (5, &open(&section()))] {
        let read = get(door, unit, &task);
        assert_eq!(read.status, 400, "{}", read.text());
        assert_eq!(read.json()["error"]["code"], -32602);
    }
}

#[test]
fn a_remote_cancellation_that_the_host_could_not_settle_is_still_owed() {
    let _serial = fresh();
    let _controls = Controls::new();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let other = open(&section());
    with_book(|b| b.fail_settles = 1);
    let body = verb("tasks/cancel", &task, &json!({}));
    assert_eq!(other.arrive(2, &body).outcome, Outcome::Ready);
    assert_eq!(other.piece(2, &Given::caller(ALICE, &body)).status, 200);
    assert!(settle_of(&task).is_none());
    assert_eq!(
        get(&other, 3, &task).json()["result"]["status"],
        "cancelled"
    );
    create(&other, 4, "st", "st_read_file");
    let row = String::from_utf8(settle_of(&task).expect("the owed cancellation landed")).unwrap();
    assert!(row.starts_with("t1|cancelled|"), "{row}");
}
