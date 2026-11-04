// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HOST INSPECTION ON THE DOOR: a task unit's question of the host's work book (whether a task's
//! handle is still retained, and for how long), and the maintenance driver's sweep of which carrier
//! sessions the host still holds live.

use std::collections::btree_map::Entry;
use std::task::Poll;

use busbar_contract::abi::mechanism::inspection::{
    self, InspectionError, InspectionObservation, InspectionQuery, InspectionResult,
    WorkObservation,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};
use busbar_contract::abi::sdk::exchange::{Inspection, Op};
use busbar_contract::abi::sdk::{Instance, Lent, Out};

use super::{door_line, McpDoor};

/// The bytes the extension entries of `extensions` other than inspection's own take, each counted as
/// the contract's extensions codec encodes it.
pub(super) fn retained_bytes(extensions: &[u8]) -> usize {
    use busbar_contract::abi::mechanism::extensions;
    extensions::entries(extensions)
        .filter(|(key, _)| {
            ![
                inspection::EXT_CAPABILITY,
                inspection::EXT_REQUEST,
                inspection::EXT_REPLY,
            ]
            .iter()
            .any(|known| *key == known.as_bytes())
        })
        .map(|(key, value)| extensions::entry_len("", value) + key.len())
        .sum()
}

/// One unit's inspection of a task's work: the unit's ticket, the caller it asks for, the query's
/// id and the query, the crossing's state, and the host's answer once it came.
pub(super) struct Unit {
    ticket: Ticket,
    caller: String,
    id: u64,
    query: InspectionQuery,
    state: Inspection,
    result: Option<InspectionResult>,
}

/// The maintenance driver's sweep of the carrier sessions this instance knows: the ticket it runs
/// on, when it began, every session it asks about and how far it got, and the query in flight.
pub(super) struct Maintenance {
    ticket: Ticket,
    now_ns: u64,
    sessions: Vec<u64>,
    cursor: usize,
    id: u64,
    query: InspectionQuery,
    state: Inspection,
}

/// The next inspection id of this instance (one counter for every inspection it makes).
fn next_id(plane: &McpDoor) -> Result<u64, InspectionError> {
    plane.inspection_serial.with_all(|m| {
        let last = m.entry(()).or_insert(0);
        *last = last.checked_add(1).ok_or(InspectionError::Invalid)?;
        Ok(*last)
    })
}

/// THE HOST'S VIEW of task `reference`'s work for `principal`, asked on unit `key`: PENDING until
/// the unit's inspection crossing answers ([`poll_unit`]), then the observation, or why there is
/// none in words a caller may read.
pub(super) fn work(
    plane: &McpDoor,
    key: u64,
    ticket: Ticket,
    principal: &str,
    reference: &str,
) -> Poll<Result<WorkObservation, String>> {
    let query = InspectionQuery::Work {
        reference: reference.as_bytes().to_vec(),
    };
    plane.inspection_units.with_all(|m| {
        let unit = match m.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let id = match next_id(plane) {
                    Ok(id) => id,
                    Err(error) => {
                        return Poll::Ready(Err(format!("host task inspection failed: {error}")))
                    }
                };
                entry.insert(Unit {
                    ticket,
                    caller: if principal == crate::ask::UNGOVERNED {
                        String::new()
                    } else {
                        principal.to_string()
                    },
                    id,
                    query: query.clone(),
                    state: Inspection::default(),
                    result: None,
                })
            }
        };
        if unit.ticket != ticket || unit.query != query {
            return Poll::Ready(Err("host task inspection changed while pending".to_string()));
        }
        match &unit.result {
            None => Poll::Pending,
            Some(Ok(InspectionObservation::Work(observation))) => Poll::Ready(Ok(*observation)),
            Some(Ok(_)) => Poll::Ready(Err(
                "host task inspection returned a different fact".to_string()
            )),
            Some(Err(error)) => Poll::Ready(Err(format!(
                "host task retention inspection is unavailable: {error}"
            ))),
        }
    })
}

/// Drives unit `key`'s inspection crossing: PENDING while the host's answer is out, then the caller
/// it was asked for (`None`: the unit holds no inspection).
pub(super) fn poll_unit<I: AbiIn, O: AbiOut>(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    input: Lent<'_, I>,
    out: &mut Out<'_, O>,
    key: u64,
) -> Poll<Option<String>> {
    plane.inspection_units.with(&key, |unit| {
        let Some(unit) = unit else {
            return Poll::Ready(None);
        };
        if unit.result.is_none() {
            let op = Op::new(instance, plane.host.as_ref());
            match op.inspect(
                input,
                out,
                &plane.inspection_leases,
                &mut unit.state,
                unit.id,
                &unit.query,
            ) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => unit.result = Some(result),
            }
        }
        Poll::Ready(Some(unit.caller.clone()))
    })
}

/// Begins the maintenance sweep on `ticket` at `now_ns`, when none runs and this instance knows
/// carrier sessions: the first query takes as many as fit beside `existing_bytes` of extensions.
pub(super) fn begin_maintenance(
    plane: &McpDoor,
    ticket: Ticket,
    now_ns: u64,
    existing_bytes: usize,
) -> Result<(), InspectionError> {
    plane.inspection_driver.with_all(|m| {
        let Entry::Vacant(entry) = m.entry(()) else {
            return Ok(());
        };
        let sessions = door_line::known_sessions(plane);
        if sessions.is_empty() {
            return Ok(());
        }
        let room = inspection::max_carrier_sessions(existing_bytes);
        if room == 0 {
            return Err(InspectionError::Invalid);
        }
        let query = InspectionQuery::CarrierSessions {
            sessions: sessions.iter().take(room).copied().collect(),
        };
        entry.insert(Maintenance {
            ticket,
            now_ns,
            sessions,
            cursor: 0,
            id: next_id(plane)?,
            query,
            state: Inspection::default(),
        });
        Ok(())
    })
}

/// Drives the maintenance sweep: every session the host says is no longer live is retired, page by
/// page; READY with when the sweep began once every session was asked (`None`: no sweep runs).
pub(super) fn maintain<I: AbiIn, O: AbiOut>(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    input: Lent<'_, I>,
    out: &mut Out<'_, O>,
    existing_bytes: usize,
) -> Poll<Result<Option<u64>, InspectionError>> {
    let result = plane.inspection_driver.with(&(), |kept| {
        let Some(kept) = kept else {
            return Poll::Ready(Ok(None));
        };
        if kept.ticket != instance.ticket() {
            return Poll::Ready(Err(InspectionError::Correlation));
        }
        let op = Op::new(instance, plane.host.as_ref());
        loop {
            let rows = match op.inspect(
                input,
                out,
                &plane.inspection_leases,
                &mut kept.state,
                kept.id,
                &kept.query,
            ) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(InspectionObservation::CarrierSessions(rows))) => rows,
                Poll::Ready(Ok(_)) => return Poll::Ready(Err(InspectionError::Correlation)),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            };
            let InspectionQuery::CarrierSessions { sessions } = &kept.query else {
                return Poll::Ready(Err(InspectionError::Correlation));
            };
            if rows.len() != sessions.len()
                || !rows
                    .iter()
                    .zip(sessions)
                    .all(|(row, id)| row.session == *id)
            {
                return Poll::Ready(Err(InspectionError::Correlation));
            }
            for row in &rows {
                if !row.live {
                    door_line::retire_session(plane, row.session);
                }
            }
            kept.cursor += sessions.len();
            if kept.cursor == kept.sessions.len() {
                return Poll::Ready(Ok(Some(kept.now_ns)));
            }
            let room = inspection::max_carrier_sessions(existing_bytes);
            if room == 0 {
                return Poll::Ready(Err(InspectionError::Invalid));
            }
            kept.id = match next_id(plane) {
                Ok(id) => id,
                Err(error) => return Poll::Ready(Err(error)),
            };
            kept.query = InspectionQuery::CarrierSessions {
                sessions: kept.sessions[kept.cursor..]
                    .iter()
                    .take(room)
                    .copied()
                    .collect(),
            };
        }
    });
    if result.is_ready() {
        plane.inspection_driver.remove(&());
    }
    result
}

/// The unit on `ticket` (`key`, `0`: any) was cancelled: its inspections, and a sweep it ran, end.
pub(super) fn cancelled(plane: &McpDoor, ticket: Ticket, key: u64) {
    plane.inspection_units.with_all(|m| {
        m.retain(|unit_key, unit| unit.ticket != ticket && (key == 0 || *unit_key != key))
    });
    plane
        .inspection_driver
        .with_all(|m| m.retain(|_, state| state.ticket != ticket));
}

#[cfg(test)]
#[path = "tests/door_inspection_audit.rs"]
mod door_inspection_audit;
