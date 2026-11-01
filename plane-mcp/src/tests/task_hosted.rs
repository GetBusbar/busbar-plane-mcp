// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_same_timestamp_host_view_cannot_undo_a_pending_resume() {
    let mut local = Task::new("task", "alice", 7, "digest", 100);
    local.asked = Some((0, json!({"name":"tool"})));
    local.status = Status::InputRequired;
    let stale = local.clone();
    local.set_working(100);
    local.answer_round();
    local.hosted(stale);
    assert!(local.take_resume("alice", 0));
    assert!(!local.take_resume("alice", 0));
}

#[test]
fn a_host_terminal_state_overrides_a_pending_resume() {
    let mut local = Task::new("task", "alice", 7, "digest", 100);
    local.asked = Some((0, json!({"name":"tool"})));
    local.answer_round();
    let mut host = local.clone();
    host.cancel(100);
    local.hosted(host);
    assert_eq!(local.status(), Status::Cancelled);
    assert!(!local.take_resume("alice", 0));
}

#[test]
fn a_newer_host_ask_still_replaces_the_local_live_view() {
    let mut local = Task::new("task", "alice", 7, "digest", 100);
    local.runner = Some((8, Ticket::NONE));
    let mut host = local.clone();
    host.status = Status::InputRequired;
    host.updated_ms = 101;
    host.input_requests = vec![(
        "confirm".to_string(),
        json!({"method":"elicitation/create"}),
    )];
    local.hosted(host.clone());
    assert_eq!(local.status(), Status::InputRequired);
    assert_eq!(
        local.detailed()["inputRequests"],
        host.detailed()["inputRequests"]
    );
}

#[test]
fn an_equal_clock_partial_answer_is_not_replaced_by_older_records() {
    let mut local = Task::new("task", "alice", 7, "digest", 100);
    local.status = Status::InputRequired;
    local.input_requests = vec![
        ("one".to_string(), json!({})),
        ("two".to_string(), json!({})),
    ];
    let stale = local.clone();
    let answers = json!({"one":"accepted"}).as_object().unwrap().clone();
    assert!(local.deliver(&answers, 100));
    local.hosted(stale);
    assert_eq!(local.answers().get("one"), Some(&json!("accepted")));
    assert_eq!(local.detailed()["inputRequests"], json!({"two":{}}));
}

#[test]
fn a_taken_resume_keeps_its_equal_clock_acknowledged_state() {
    let mut local = Task::new("task", "alice", 7, "digest", 100);
    local.status = Status::InputRequired;
    local.input_requests = vec![("one".to_string(), json!({}))];
    local.asked = Some((0, json!({"name":"tool"})));
    let stale = local.clone();
    assert!(local.deliver(&json!({"one":"accepted"}).as_object().unwrap().clone(), 100));
    local.answer_round();
    assert!(local.take_resume("alice", 0));
    local.hosted(stale);
    assert_eq!(local.status(), Status::Working);
    assert_eq!(local.answers().get("one"), Some(&json!("accepted")));
}

#[test]
fn equal_clock_host_progress_is_read_when_no_update_was_accepted() {
    let mut local = Task::new("task", "alice", 7, "digest", 100);
    let mut host = local.clone();
    host.status = Status::InputRequired;
    host.input_requests = vec![("one".to_string(), json!({}))];
    local.hosted(host);
    assert_eq!(local.status(), Status::InputRequired);
    assert_eq!(local.detailed()["inputRequests"], json!({"one":{}}));
}
