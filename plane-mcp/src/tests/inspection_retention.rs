// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn retention_horizons_use_creation_and_host_settlement() {
    let mut task = Task::new("task", "alice", 7, "digest", 1_000);
    task.retain_at(5_000, 60_000, None).unwrap();
    assert_eq!(task.detailed()["ttlMs"], 64_000);
    task.complete(json!({"content":[]}), 2_000);
    task.retain_at(10_000, 60_000, Some(9_000)).unwrap();
    assert_eq!(task.detailed()["ttlMs"], 68_000);
    task.retain_at(10_001, 3_600_000, Some(9_000)).unwrap();
    assert_eq!(task.detailed()["ttlMs"], 3_608_000);
}

#[test]
fn invalid_integer_horizons_are_refused_without_changing_the_wire_ttl() {
    let mut task = Task::new("task", "alice", 7, "digest", 1_000);
    task.retain_at(5_000, 60_000, None).unwrap();
    assert!(task.retain_at(u64::MAX, 1, None).is_err());
    assert!(task.retain_at(1, 1, Some(1)).is_err());
    assert_eq!(task.detailed()["ttlMs"], 64_000);
    let mut unrepresentable = Task::new("task", "alice", 7, "digest", u64::MAX);
    assert!(unrepresentable.retain_at(u64::MAX, 0, None).is_err());
}

#[test]
fn cache_capacity_eviction_retains_the_durable_cleanup_owner() {
    let mut tasks = BTreeMap::new();
    for n in 0..MAX_RETAINED_TASKS {
        let id = format!("w{n}");
        tasks.insert(
            id.clone(),
            Task::new(&id, "working", n as u64, "digest", 1_000),
        );
    }
    let mut terminal = Task::new("terminal", "alice", 7, "digest", 1_000);
    terminal.complete(json!({"content":[]}), 1_000);
    terminal.chunks = 2;
    tasks.insert(terminal.id.clone(), terminal);
    let swept = sweep(&mut tasks, 1_001);
    assert!(!tasks.contains_key("terminal"));
    assert_eq!(swept.strike, vec![("terminal".to_string(), 2)]);
    assert_eq!(
        swept.owners.get("terminal").map(String::as_str),
        Some("alice")
    );
}
