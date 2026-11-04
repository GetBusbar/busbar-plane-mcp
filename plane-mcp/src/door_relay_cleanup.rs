// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A child's abandoned work stays owned until its durable settlement is confirmed.

use std::task::Poll;

use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::services::ServiceError;

use super::{door_legacy::Driver, door_listen, McpDoor, CHILD_LAPSED};

/// A work handle and any outstanding driver's settlement of it.
pub(super) struct Work {
    until_ms: u64,
    pending: Option<CompletionHandle>,
    applied: bool,
}

/// Retain a new child work handle; zero means cleanup is already owed.
pub(super) fn hold(plane: &McpDoor, handle: u64, until_ms: u64) {
    plane.relays.insert(
        handle,
        Work {
            until_ms,
            pending: None,
            applied: false,
        },
    );
    door_listen::wake_driver(plane);
}

/// On a terminal failure the host may have restored the work to live. Keep custody and retry on
/// a fresh, unconsumed completion handle. Pending always polls the exact original full handle.
pub(super) fn drive(plane: &McpDoor, ticket: Ticket, driver: &mut Driver) -> bool {
    let Some(services) = plane.services else {
        return !plane.relays.is_empty();
    };
    if plane.relays.is_empty() {
        return false;
    }
    let mut clock_handle = None;
    let now_ms = driver
        .host_handle(ticket, &mut clock_handle)
        .and_then(|handle| {
            let now = services
                .clock_now(handle)
                .ok()
                .map(|now| now.wall_ns / 1_000_000);
            driver.host_consumed(&mut clock_handle);
            now
        });
    plane.relays.with_all(|works| {
        let mut done = Vec::new();
        let mut due = false;
        for (&handle, work) in works.iter_mut() {
            if work.until_ms != 0
                && work.pending.is_none()
                && !work.applied
                && now_ms.is_none_or(|now| now < work.until_ms)
            {
                continue;
            }
            due = true;
            if !work.applied {
                let Some(completion) = driver.host_handle(ticket, &mut work.pending) else {
                    continue;
                };
                match services.work_settle(completion, handle, CHILD_LAPSED) {
                    Poll::Pending => continue,
                    Poll::Ready(settled) => work.applied = confirmed(settled),
                }
            }
            if driver.host_consumed(&mut work.pending) && work.applied {
                done.push(handle);
            }
        }
        for handle in done {
            works.remove(&handle);
        }
        due && !works.is_empty()
    })
}

/// Only a successful settlement confirms durable completion. REFUSED can also mean that the
/// work is still live under another owner, or that another settlement is merely in flight and
/// may yet fail. Neither permits abandoning custody; retry after this completion is retired.
fn confirmed(settled: Result<(), ServiceError>) -> bool {
    settled.is_ok()
}

#[cfg(test)]
#[path = "tests/door_relay_cleanup_audit.rs"]
mod door_relay_cleanup_audit;
