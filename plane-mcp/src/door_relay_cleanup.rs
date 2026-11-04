// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A child's abandoned work stays owned until its durable settlement is confirmed.

use std::task::Poll;

use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::services::{ServiceError, WorkStatus};

use super::{door_legacy::Driver, door_listen, McpDoor, CHILD_LAPSED};

/// A work handle and any outstanding driver's settlement of it.
pub(super) struct Work {
    reference: String,
    until_ms: u64,
    pending: Option<CompletionHandle>,
    phase: Phase,
    terminal: Option<Next>,
    terminal_seq: Option<u32>,
    settled_elsewhere: bool,
    retry_at_ns: u64,
    retry_delay_ns: u64,
}

#[derive(Clone, Copy)]
enum Phase {
    Settle,
    Probe,
}
#[derive(Clone, Copy)]
enum Next {
    Probe,
    Retry,
    Done,
}
const RETRY_MIN_NS: u64 = 250_000_000;
const RETRY_MAX_NS: u64 = 30_000_000_000;

impl Work {
    fn defer(&mut self, mono_ns: Option<u64>) {
        self.retry_at_ns = mono_ns.unwrap_or(0).saturating_add(self.retry_delay_ns);
        self.retry_delay_ns = self.retry_delay_ns.saturating_mul(2).min(RETRY_MAX_NS);
    }
}

/// Retain a new child work handle; zero means cleanup is already owed.
pub(super) fn hold(plane: &McpDoor, handle: u64, reference: &str, until_ms: u64) {
    plane.relays.insert(
        handle,
        Work {
            reference: reference.to_owned(),
            until_ms,
            pending: None,
            phase: Phase::Settle,
            terminal: None,
            terminal_seq: None,
            settled_elsewhere: false,
            retry_at_ns: 0,
            retry_delay_ns: RETRY_MIN_NS,
        },
    );
    door_listen::wake_driver(plane);
}

/// A caller durably settled the work. Keep any maintenance operation until its original
/// completion has been polled, consumed and acknowledged; never drop an in-flight probe.
pub(super) fn settled(plane: &McpDoor, handle: u64) {
    plane.relays.with_all(|works| {
        if let Some(work) = works.get_mut(&handle) {
            if work.pending.is_none() && work.terminal.is_none() {
                works.remove(&handle);
            } else {
                work.settled_elsewhere = true;
            }
        }
    });
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
    // Gate only this clock's receipt. Legacy reads may queue unrelated completions
    // before every cleanup drive and must not starve nonzero wall-clock expiries.
    let retired = driver.cleanup_clock_seq.is_none();
    let mut clock_handle = None;
    let clock = retired
        .then(|| driver.host_handle(ticket, &mut clock_handle))
        .flatten()
        .and_then(|handle| match services.clock_now(handle) {
            Err(ServiceError::Unserved) => {
                driver.host_unserved(&mut clock_handle);
                None
            }
            result => {
                driver.cleanup_clock_seq = clock_handle.map(|handle| handle.seq);
                driver.host_consumed(&mut clock_handle);
                result.ok()
            }
        });
    let now_ms = clock.as_ref().map(|now| now.wall_ns / 1_000_000);
    // The regular 250ms maintenance tick wakes held cleanup and is monotonic even when
    // clock.now is unavailable. Unrelated wakes never bypass the retry deadline.
    let mono_ns = clock
        .as_ref()
        .map(|now| now.mono_ns)
        .or_else(|| plane.driver.get(&()).map(|(_, now)| now));
    plane.relays.with_all(|works| {
        let mut done = Vec::new();
        let mut due = false;
        for (&handle, work) in works.iter_mut() {
            if let Some(next) = work.terminal {
                due = true;
                if work.pending.is_some() {
                    driver.host_consumed(&mut work.pending);
                    continue;
                }
                if work
                    .terminal_seq
                    .is_some_and(|seq| !driver.retired_hosts.contains(&seq))
                {
                    continue;
                }
                work.terminal_seq = None;
                work.terminal = None;
                match if work.settled_elsewhere {
                    Next::Done
                } else {
                    next
                } {
                    Next::Done => {
                        done.push(handle);
                        continue;
                    }
                    Next::Probe => work.phase = Phase::Probe,
                    Next::Retry => {
                        work.phase = Phase::Settle;
                        work.defer(mono_ns);
                        continue;
                    }
                }
            }
            if work.pending.is_none()
                && work.retry_at_ns != 0
                && mono_ns.is_none_or(|now| now < work.retry_at_ns)
            {
                due = true;
                continue;
            }
            if work.until_ms != 0
                && work.pending.is_none()
                && work.retry_at_ns == 0
                && matches!(work.phase, Phase::Settle)
                && now_ms.is_none_or(|now| now < work.until_ms)
            {
                continue;
            }
            due = true;
            let Some(completion) = driver.host_handle(ticket, &mut work.pending) else {
                continue;
            };
            let next = match work.phase {
                Phase::Settle => match services.work_settle(completion, handle, CHILD_LAPSED) {
                    Poll::Pending => continue,
                    Poll::Ready(Err(ServiceError::Unserved)) => {
                        driver.host_unserved(&mut work.pending);
                        Next::Probe
                    }
                    Poll::Ready(result) if confirmed(result) => Next::Done,
                    Poll::Ready(_) => Next::Probe,
                },
                Phase::Probe => match services.work_status(completion, &work.reference) {
                    Poll::Pending => continue,
                    Poll::Ready(Ok(WorkStatus::Settled)) => Next::Done,
                    Poll::Ready(Err(ServiceError::Unserved)) => {
                        driver.host_unserved(&mut work.pending);
                        Next::Retry
                    }
                    Poll::Ready(_) => Next::Retry,
                },
            };
            work.terminal = Some(if work.settled_elsewhere {
                Next::Done
            } else {
                next
            });
            work.terminal_seq = work.pending.map(|handle| handle.seq);
            driver.host_consumed(&mut work.pending);
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
