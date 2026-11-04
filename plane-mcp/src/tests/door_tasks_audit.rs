// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn ticket() -> Ticket {
    Ticket {
        slot: 3,
        generation: 9,
    }
}

#[test]
fn an_owed_settle_carries_its_terminal_state_into_a_held_live_entry() {
    let plane = McpDoor::default();
    let held = Task::new("task", "alice", 7, "digest", 1_000);
    plane.tasks.insert(held.id.clone(), held.clone());
    let mut cancelled = held.clone();
    assert!(cancelled.cancel(2_000));

    owe(&plane, &cancelled);

    let owed = plane.tasks.get(&held.id).unwrap();
    assert_eq!(
        owed.status(),
        Status::Cancelled,
        "the held entry must take the state the settle that did not land carried"
    );
    assert!(owed.unsettled);
    let swept = plane.tasks.with_all(|m| tasks::sweep(m, 2_001));
    assert_eq!(swept.settle.len(), 1);
    assert_eq!(
        swept.settle[0].1.status(),
        Status::Cancelled,
        "the sweep must re-settle the terminal row, never the stale working one"
    );
}

#[test]
fn an_owed_settle_never_rewrites_an_entry_already_terminal() {
    let plane = McpDoor::default();
    let mut held = Task::new("task", "alice", 7, "digest", 1_000);
    held.complete(json!({"content":[]}), 1_500);
    plane.tasks.insert(held.id.clone(), held.clone());
    let mut cancelled = Task::new("task", "alice", 7, "digest", 1_000);
    cancelled.cancel(2_000);

    owe(&plane, &cancelled);

    let owed = plane.tasks.get(&held.id).unwrap();
    assert_eq!(owed.status(), Status::Completed);
    assert!(owed.unsettled);
}

#[test]
fn remembered_strikes_are_bounded_the_oldest_giving_way() {
    let entry = || Strikes {
        owner: "alice".to_string(),
        chunks: 1,
        live_chunks: 0,
    };
    let mut strikes = std::collections::BTreeMap::new();
    for n in 0..MAX_STRIKE_ENTRIES {
        strike(&mut strikes, format!("t{n:05}"), entry());
    }
    assert_eq!(strikes.len(), MAX_STRIKE_ENTRIES);
    strike(&mut strikes, "u-new".to_string(), entry());
    assert_eq!(
        strikes.len(),
        MAX_STRIKE_ENTRIES,
        "past the bound a new strike must evict, not grow the map"
    );
    assert!(strikes.contains_key("u-new"));
    assert!(!strikes.contains_key("t00000"), "the oldest gave way");
    strike(&mut strikes, "u-new".to_string(), entry());
    assert_eq!(
        strikes.len(),
        MAX_STRIKE_ENTRIES,
        "re-striking a held key evicts nothing"
    );
    assert!(strikes.contains_key("t00001"));
}

#[test]
fn a_task_this_instance_moved_on_is_not_left_behind() {
    let plane = McpDoor::default();
    let read = Task::new("task", "alice", 7, "digest", 1_000);
    assert!(!moved_on(&plane, &read), "no held copy: the records decide");

    plane.tasks.insert(read.id.clone(), read.clone());
    assert!(!moved_on(&plane, &read), "a copy no newer than the records");

    let mut bound = read.clone();
    bound.runner = Some((41, ticket()));
    plane.tasks.insert(read.id.clone(), bound);
    assert!(
        moved_on(&plane, &read),
        "a run bound since the index was read"
    );

    let mut updated = read.clone();
    updated.set_working(5_000);
    plane.tasks.insert(read.id.clone(), updated);
    assert!(moved_on(&plane, &read), "an update newer than the records");
}

#[test]
fn a_failed_listing_of_an_unheld_task_is_retryable_not_unknown() {
    assert!(
        matches!(unlisted(None), Poll::Ready(Err(_))),
        "a host that could not list is not a task that does not exist"
    );
    let held = Task::new("task", "alice", 7, "digest", 1_000);
    let Poll::Ready(Ok(Some(task))) = unlisted(Some(held.clone())) else {
        panic!("a held copy is answered");
    };
    assert_eq!(*task, held);
}

#[test]
fn a_work_open_failure_is_said_as_what_the_host_answered() {
    let full = not_opened(ServiceError::Declined(AbiOutcome::Refused));
    let unserved = not_opened(ServiceError::Unserved);
    let broken = not_opened(ServiceError::Broken);
    assert!(full.contains("as many live tasks"), "{full}");
    assert!(unserved.contains("no store"), "{unserved}");
    assert!(
        !broken.contains("as many live tasks") && !broken.contains("no store"),
        "a host fault is not a capacity refusal: {broken}"
    );
}

#[test]
fn chunk_counts_are_one_past_the_highest_index_and_refuse_strange_keys() {
    let prefix = tasks::chunk_prefix("t");
    let rows = vec![
        (tasks::chunk_key("t", 0), Vec::new()),
        (tasks::chunk_key("t", 2), Vec::new()),
    ];
    assert_eq!(chunk_count(&rows, &prefix), Some(3));
    assert_eq!(chunk_count(&[], &prefix), Some(0));
    let strange = vec![(b"t/x".to_vec(), Vec::new())];
    assert_eq!(chunk_count(&strange, &prefix), None);
}

#[test]
fn task_record_listing_bounds_rows_and_bytes_before_copying() {
    let mut listing = Listing::default();
    for _ in 0..MAX_LISTING_ROWS {
        assert!(listing.push(b"k", b"v"));
    }
    assert!(!listing.push(b"next", b"value"));
    assert_eq!(listing.rows.len(), MAX_LISTING_ROWS);
    let mut listing = Listing {
        bytes: MAX_LISTING_BYTES - 2,
        ..Listing::default()
    };
    assert!(listing.push(b"k", b"v"));
    assert!(!listing.push(b"x", b""));
    assert_eq!(listing.bytes, MAX_LISTING_BYTES);
}

#[test]
fn unrelayed_task_asks_always_have_failure_words() {
    for body in [
        b"{}".as_slice(),
        b"not json",
        br#"{"error":{"message":""}}"#,
    ] {
        assert!(!continuation_ask_error(body).is_empty());
    }
    assert_eq!(
        continuation_ask_error(br#"{"error":{"message":"refused"}}"#),
        "refused"
    );
}
