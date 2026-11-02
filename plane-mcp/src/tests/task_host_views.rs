// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_host_only_view_is_returned_without_retaining_its_result() {
    let plane = McpDoor::default();
    let mut task = Task::new("task", "alice", 7, "digest", 100);
    task.complete(
        json!({"content":[{"type":"text","text":"host result"}]}),
        101,
    );
    let Poll::Ready(Some(view)) = hosted(&plane, "task", task.clone()) else {
        panic!("the host's task is immediately readable");
    };
    assert_eq!(*view, task);
    assert!(plane.tasks.get(&"task".to_string()).is_none());
}

#[test]
fn continuation_refusal_requires_the_bound_handle_digest_and_runner() {
    let plane = McpDoor::default();
    let ticket = Ticket {
        slot: 3,
        generation: 9,
    };
    let mut task = Task::new("task", "alice", 7, "bound-digest", 100);
    task.runner = Some((41, ticket));
    plane.tasks.insert(task.id.clone(), task.clone());

    let wrong_ticket = Ticket {
        generation: ticket.generation + 1,
        ..ticket
    };
    for (unit, receipt) in [
        (41, None),
        (41, Some((8, "bound-digest".to_string(), ticket))),
        (41, Some((7, "other-digest".to_string(), ticket))),
        (41, Some((7, "bound-digest".to_string(), wrong_ticket))),
        (42, Some((7, "bound-digest".to_string(), ticket))),
    ] {
        assert!(continuation_refused(&plane, unit, "task", receipt, "budget refused").is_empty());
        assert_eq!(plane.tasks.get(&task.id).unwrap(), task);
    }

    let receipt = Some((7, "bound-digest".to_string(), ticket));
    let records = continuation_refused(&plane, 41, "task", receipt.clone(), "budget refused");
    assert!(
        !records.is_empty(),
        "a bound refusal must persist its terminal state"
    );
    let ended = plane.tasks.get(&task.id).unwrap();
    assert_eq!(ended.status(), Status::Failed);
    assert!(ended.unsettled);
    assert_eq!(ended.runner, None);
    assert_eq!(ended.digest(), "bound-digest");

    // A short-output retry retains its positive bind receipt after the runner was cleared.
    assert!(!continuation_refused(&plane, 41, "task", receipt, "budget refused").is_empty());
    assert_eq!(plane.tasks.get(&task.id).unwrap().status(), Status::Failed);
}
