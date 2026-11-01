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
