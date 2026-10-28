// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINE CARRIER'S UNITS (ARCHITECT Q1a, round 4 Q-L3B-STDIO-SHAPE (B)): the host holds the
//! process's own stdin/stdout open as ONE carrier session and opens a unit per line; what a line
//! MEANS is [`crate::line`]'s, and how a unit answers it is here. What the plane writes unsolicited
//! (busbar's own asks of its caller, a subscription's changes and keepalives) it writes with the
//! host's `session.emit` on the session every line names
//! ([`busbar_contract::abi::host::service::CARRIER_SESSION_FIELD`]).
//!
//! - A REQUEST goes on through the one dispatch under the fields its body implies; its answer is
//!   one line.
//! - An `input_required` answer — busbar's OWN ask, or an UPSTREAM's ask relayed (Law 11) — is
//!   LIVENED ([`liven`]): its first ask is emitted as busbar's own request (`busbar:<n>`), the unit
//!   answers nothing, and the caller's answers are lines of their own: each answer but the round's
//!   last emits the next ask; the last is the RETRY, the request as the caller sent it with the
//!   answers and the sealed state, dispatched as that unit (its own admission). An answer that is an
//!   error hands the caller the `input_required` result itself. The exceptions: a line whose carrier
//!   session negotiated a SESSION revision (`2025-06-18`, `2025-11-25`) has its answer lowered into
//!   that revision first, which turns an `input_required` result into the revision's error (it has
//!   no such result, as predev lowered it), so there is nothing left to liven; a round past the
//!   round cap, or past [`MAX_LIVE_ASKS_PER_SESSION`] live on its session, is handed on as it is.
//! - A SUBSCRIPTION (`subscriptions/listen`) is answered with its acknowledgement and kept on the
//!   session ([`listen`]): the tick ([`tick`]) steps it, emitting what changed, a `ping` when it has
//!   been quiet and its last frame at its bound.
//! - The STDIO-ERA VERBS are answered here, and a notification — or a line answering nothing busbar
//!   asked — is answered with nothing at all.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{door_listen, CallUnit, McpDoor, Pending};
use crate::catalogue::Catalogue;
use crate::line::{self, Era, LiveAsk, Reply};
use crate::subscribe::{Listen, Standing, Step as ListenStep, KEEPALIVE_NS};
use busbar_contract::abi::mechanism::ticket::Ticket;

/// What a line unit is to the carrier.
#[derive(Debug, Clone, Default)]
pub(super) struct LineUnit {
    /// The carrier session it arrived over.
    pub(super) session: u64,
    /// The request this unit dispatches, as JSON: its own line, or the retry it became.
    pub(super) original: Option<Value>,
    /// What it answers without the dispatch: an era verb's answer, a failed ask's fallback, or
    /// nothing at all (an empty answer is written as no line).
    pub(super) preset: Option<Vec<u8>>,
    /// The live round (by its ask number) whose next ask this unit emits.
    pub(super) next_ask: Option<u64>,
    /// The live round this unit's retry is: `0` for a request the caller sent itself.
    pub(super) round: u32,
    /// Its line was raised from the session revision its carrier session negotiated
    /// ([`crate::adapt::raise`]): its answer is lowered back into it.
    pub(super) raised: bool,
}

/// After this long with no unit of its caller re-asking its standing and grants (two pings went
/// unanswered, or the kernel admitted none of its caller's lines, as it admits none of a revoked
/// caller's), a line subscription's permission is not re-confirmed and it ends on its frame.
const UNCONFIRMED_NS: u64 = 3 * KEEPALIVE_NS;

/// One subscription kept on a carrier session.
#[derive(Debug, Clone)]
pub(super) struct LineListen {
    listen: Box<Listen>,
    /// The entitlement answers the last unit of its caller re-asked (at open, the opener's).
    entitled: BTreeMap<String, bool>,
    /// The caller that opened it: the principal whose units re-ask it, and the quota counts under.
    owner: String,
    /// Its caller's standing, as the last unit of its caller re-asked it.
    standing: Standing,
    /// When a unit of its caller last re-asked its standing and grants.
    confirmed_ns: u64,
    /// When busbar last asked its caller a `ping`.
    pinged_ns: u64,
    /// The upstream announcements `(server, uri)` heard since its last step.
    updates: Vec<(String, String)>,
}

impl LineListen {
    /// Its caller's standing at `now_ns`: the last unit's answer, or lapsed when none re-confirmed
    /// it for [`UNCONFIRMED_NS`].
    fn standing_at(&self, now_ns: u64) -> Standing {
        if matches!(self.standing, Standing::Lapsed { .. }) {
            return self.standing.clone();
        }
        if now_ns.saturating_sub(self.confirmed_ns) > UNCONFIRMED_NS {
            return Standing::Lapsed {
                message: format!(
                    "`{}` answered nothing on its carrier session for {} s, so the standing \
                     decision it was admitted under is not re-confirmed",
                    self.owner,
                    UNCONFIRMED_NS / 1_000_000_000
                ),
                reason: busbar_contract::vocab::REASON_IDENTITY_NOT_LIVE.to_string(),
            };
        }
        Standing::Live
    }

    /// ONE STEP at `now_ns` over the live `catalogue`, under the grants and the standing its
    /// caller's units last re-asked (on either carrier the permission is re-asked, never the one
    /// captured at open), relaying the upstream announcements held since its last step.
    fn step_at(&mut self, catalogue: &Catalogue, now_ns: u64) -> ListenStep {
        let standing = self.standing_at(now_ns);
        let updates = std::mem::take(&mut self.updates);
        let admit = super::admit(&self.entitled);
        self.listen
            .step(catalogue, &admit, &standing, &updates, now_ns)
    }

    /// Whether busbar asks its caller a `ping` at `now_ns` to have its standing re-asked (the
    /// answer is a line, so a unit, and the unit re-asks): none re-confirmed it, and none was
    /// asked, for [`KEEPALIVE_NS`]. Asked, it is noted.
    fn wants_ping(&mut self, now_ns: u64) -> bool {
        let due = now_ns.saturating_sub(self.confirmed_ns) >= KEEPALIVE_NS
            && now_ns.saturating_sub(self.pinged_ns) >= KEEPALIVE_NS;
        if due {
            self.pinged_ns = now_ns;
        }
        due
    }
}

/// THE PERMISSION, RE-ASKED ON A LINE: a unit of the carrier session's caller (any line it sends,
/// the answer to busbar's `ping` among them) re-asks the kernel its standing and the catalogue's
/// grants on its own ticket, and every subscription that caller holds on the session takes the
/// answers. The kernel answers them only for a unit in flight, which a kept subscription is not.
pub(super) fn reconfirm(plane: &McpDoor, ticket: Ticket, principal: &str, unit: &mut CallUnit) {
    let Some(session) = unit.line.as_ref().map(|l| l.session) else {
        return;
    };
    let holds = plane.line_listens.with_all(|m| {
        m.iter()
            .any(|((s, _), l)| *s == session && l.owner == principal)
    });
    if !holds {
        return;
    }
    let Some(held) = plane.current().or_else(|| unit.held.clone()) else {
        return;
    };
    door_listen::entitled_afresh(plane, ticket, unit, &held);
    let standing = door_listen::standing(plane, ticket, principal, unit);
    let now = door_listen::mono_ns(plane.services, ticket, unit);
    let entitled = unit.entitled.clone();
    plane.line_listens.with_all(|m| {
        for ((s, _), l) in m.iter_mut() {
            if *s == session && l.owner == principal {
                // A clock that cannot be read is never a time (P-M4): the re-asked grants and
                // standing still apply, but the confirmation is not moved to a time never read.
                l.confirmed_ns = now.unwrap_or(l.confirmed_ns);
                l.entitled.clone_from(&entitled);
                l.standing = standing.clone();
            }
        }
    });
}

/// AN UPSTREAM ANNOUNCED that `uri` of its registration `server` changed: every subscription kept
/// on a carrier session holds it for its next step, which relays it to one that asked for the uri.
pub(super) fn announced(plane: &McpDoor, server: &str, uri: &str) {
    plane.line_listens.with_all(|m| {
        for kept in m.values_mut() {
            door_listen::hold_update(&mut kept.updates, server, uri);
        }
    });
}

/// One line as `arrive` read it: what the unit is to the carrier, and the bytes the one dispatch
/// decides on (`None` = the unit answers its preset, the dispatch decides nothing).
pub(super) struct Arrival {
    pub(super) unit: LineUnit,
    pub(super) dispatch: Option<Vec<u8>>,
}

/// READ ONE LINE of carrier session `session`: an answer to one of busbar's own asks (its round
/// moved on, or its retry), a cancel, a stdio-era verb, or a request for the one dispatch.
pub(super) fn arrive(plane: &McpDoor, session: u64, body: &[u8]) -> Arrival {
    let mut unit = LineUnit {
        session,
        ..LineUnit::default()
    };
    let dispatch = read(plane, session, body, &mut unit);
    Arrival { unit, dispatch }
}

/// [`arrive`]'s reading of the line into `unit`: the bytes the one dispatch decides on, `None` when
/// the unit answers its preset.
fn read(plane: &McpDoor, session: u64, body: &[u8], unit: &mut LineUnit) -> Option<Vec<u8>> {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Some(body.to_vec());
    };
    if let Some(reply) = line::reply(&value) {
        let n = match &reply {
            Reply::Answered(n, _) | Reply::Failed(n) => *n,
        };
        // An answer to nothing busbar asked on this session: nothing to say.
        unit.preset = Some(Vec::new());
        let mut live = plane.live_asks.remove(&(session, n))?;
        match reply {
            Reply::Failed(_) => unit.preset = Some(live.fallback),
            Reply::Answered(_, result) => {
                live.answered(result);
                if !live.queued.is_empty() {
                    plane.live_asks.insert((session, n), live);
                    unit.next_ask = Some(n);
                } else if let Some(retry) = live.retry() {
                    unit.preset = None;
                    unit.round = live.round.saturating_add(1);
                    let dispatch = serde_json::to_vec(&retry).unwrap_or_default();
                    unit.original = Some(retry);
                    return Some(dispatch);
                } else {
                    unit.preset = Some(live.fallback);
                }
            }
        }
        return None;
    }
    if let Some(id) = line::cancelled(&value) {
        let key = line::id_key(&id);
        plane.live_asks.with_all(|m| {
            m.retain(|(s, _), live| {
                *s != session || live.original.get("id").map(line::id_key) != Some(key.clone())
            });
        });
    }
    let answer = match line::era(&value) {
        Era::Dispatch => None,
        // THE CARRIER SESSION NOW SPEAKS `revision` (revision by negotiation, THE DESIGN section 2).
        // The table is bounded and evicts nothing: a full one answers the stateless revision.
        Era::Opened(revision, answer) => Some(
            if plane.line_revisions.with_all(|m| {
                let full = m.len() >= super::MAX_UNITS && !m.contains_key(&session);
                if !full {
                    m.insert(session, revision);
                }
                !full
            }) {
                answer
            } else {
                line::initialize_result(value.get("id").unwrap_or(&Value::Null))
            },
        ),
        Era::Answer(answer) => Some(answer),
    };
    if let Some(answer) = answer {
        unit.preset = Some(serde_json::to_vec(&answer).unwrap_or_default());
        return None;
    }
    // A LINE OF A SESSION REVISION carries no stateless `_meta`: it is raised into the one
    // dispatch's shape, and its answer lowered back ([`crate::adapt`]).
    let stateless = value
        .pointer("/params/_meta")
        .and_then(|m| m.get(crate::codec::META_PROTOCOL_VERSION))
        .is_some();
    if !stateless && plane.line_revisions.get(&session).is_some() {
        let mut raised = value.clone();
        if crate::adapt::raise(&mut raised).is_some() {
            unit.raised = true;
            let dispatch = serde_json::to_vec(&raised).unwrap_or_default();
            unit.original = Some(raised);
            return Some(dispatch);
        }
    }
    unit.original = Some(value);
    Some(body.to_vec())
}

/// Whether a line that the one dispatch refused is a notification: a notification is never
/// answered, refused or not.
pub(super) fn is_notification(v: &Value) -> bool {
    v.get("method").is_some_and(Value::is_string) && v.get("id").is_none()
}

/// The next number busbar spells one of its own requests in.
fn next_ask(plane: &McpDoor) -> u64 {
    plane.ask_seq.with_all(|m| {
        let n = m.entry(()).or_insert(0);
        *n = n.saturating_add(1);
        *n
    })
}

/// `bytes` emitted on carrier session `session`, on a fresh handle of `ticket`: whether it went.
fn emit(plane: &McpDoor, ticket: Ticket, seq: u32, session: u64, bytes: &[u8]) -> bool {
    let Some(services) = plane.services else {
        return false;
    };
    services
        .session_emit(super::handle_at(ticket, seq), session, bytes)
        .is_ok()
}

/// THE PRESET ANSWER of a line unit, or the next ask of its round emitted (the unit then answers
/// nothing): `None` for a unit the one dispatch answers.
pub(super) fn preset(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit) -> Option<Pending> {
    let line_unit = unit.line.as_mut()?;
    let session = line_unit.session;
    if let Some(n) = line_unit.next_ask.take() {
        let now = door_listen::mono_ns(plane.services, ticket, unit);
        let line_unit = unit.line.as_mut()?;
        if let Some(mut live) = plane.live_asks.remove(&(session, n)) {
            let fresh = next_ask(plane);
            // A clock that cannot be read arms no lapse: the caller is handed the result itself.
            if let (Some(now), Some(ask)) = (now, live.issue(fresh)) {
                live.arm(now);
                // Kept before it is asked: its answer may arrive before the emit returns.
                let fallback = live.fallback.clone();
                plane.live_asks.insert((session, fresh), live);
                if !emit(plane, ticket, unit.issued, session, &ask) {
                    plane.live_asks.remove(&(session, fresh));
                    line_unit.preset = Some(fallback);
                }
            } else {
                // The next ask cannot be put to the caller: it is handed the result itself.
                line_unit.preset = Some(live.fallback);
            }
            unit.issued += 1;
        }
    }
    let line_unit = unit.line.as_mut()?;
    let bytes = line_unit.preset.take()?;
    Some(Pending::answer(200, bytes, None, &[]))
}

/// The most live ask rounds one carrier session holds at once ([`liven`]).
pub(super) const MAX_LIVE_ASKS_PER_SESSION: usize = 64;

/// LIVEN a line unit's answer: an `input_required` result (busbar's own ask, or an upstream's
/// relayed) is put to the caller as live requests on the session, its first ask emitted now, and
/// the unit answers nothing. Any other answer, or one that cannot be emitted, is left as it is.
pub(super) fn liven(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit) {
    let Some(line_unit) = unit.line.as_ref() else {
        return;
    };
    let session = line_unit.session;
    let round = line_unit.round;
    // The round cap: past it the `input_required` result is handed to the caller as it is (its
    // sealed `requestState` makes that a continuation), never put live again.
    if round >= line::MAX_LIVE_ASK_ROUNDS {
        return;
    }
    let Some(original) = line_unit.original.clone() else {
        return;
    };
    let Some(pending) = unit.pending.as_mut() else {
        return;
    };
    if pending.request.is_some() || pending.status != 200 || pending.bytes.is_empty() {
        return;
    }
    let Ok(answer) = serde_json::from_slice::<Value>(&pending.bytes) else {
        return;
    };
    let Some(result) = answer.get("result") else {
        return;
    };
    if result.get("resultType").and_then(Value::as_str)
        != Some(crate::codec::RESULT_TYPE_INPUT_REQUIRED)
    {
        return;
    }
    // THE LIVE ASKS OF ONE CARRIER SESSION ARE BOUNDED: past [`MAX_LIVE_ASKS_PER_SESSION`] the
    // answer is handed to the caller as it is (its sealed `requestState` makes that a continuation),
    // as past the round cap.
    let held = plane
        .live_asks
        .with_all(|m| m.keys().filter(|(s, _)| *s == session).count());
    if held >= MAX_LIVE_ASKS_PER_SESSION {
        return;
    }
    let Some(mut live) = LiveAsk::of(original, pending.bytes.clone(), result, round) else {
        return;
    };
    // A clock that cannot be read arms no lapse: the answer is left as it is.
    let Some(now) = door_listen::mono_ns(plane.services, ticket, unit) else {
        return;
    };
    live.arm(now);
    let n = next_ask(plane);
    let Some(ask) = live.issue(n) else {
        return;
    };
    let seq = unit.issued;
    unit.issued += 1;
    // KEPT BEFORE IT IS ASKED: the caller's answer is a line of its own, and may arrive before
    // the emit returns.
    plane.live_asks.insert((session, n), live);
    if !emit(plane, ticket, seq, session, &ask) {
        plane.live_asks.remove(&(session, n));
        return;
    }
    if let Some(pending) = unit.pending.as_mut() {
        pending.bytes.clear();
        pending.fields.clear();
    }
}

/// OPEN a subscription on the carrier session: refused in its own words, or answered with its
/// acknowledgement and kept on the session. `None` for a unit that is not a line's
/// `subscriptions/listen`.
pub(super) fn listen(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
) -> Option<Pending> {
    let session = unit.line.as_ref()?.session;
    let id = door_listen::listen_id(unit)?;
    let held = plane.current().or_else(|| unit.held.clone())?;
    let (mut listen, now) = match door_listen::open_listen(plane, ticket, unit, &held, id.clone()) {
        Ok(opened) => opened,
        Err(refused) => return Some(*refused),
    };
    let admit = super::admit(&unit.entitled);
    let frames = match listen.step(&held.catalogue, &admit, &Standing::Live, &[], now) {
        ListenStep::Frames(frames) | ListenStep::End(frames) => frames,
        _ => Vec::new(),
    };
    let key = (session, line::id_key(&id));
    let kept = LineListen {
        listen: Box::new(listen),
        entitled: unit.entitled.clone(),
        owner: principal.to_string(),
        standing: Standing::Live,
        confirmed_ns: now,
        pinged_ns: now,
        updates: Vec::new(),
    };
    // THE QUOTA REFUSES THE NEW SUBSCRIPTION, never evicts a held one, as on the HTTP carrier.
    let admitted = plane.line_listens.with_all(|m| {
        let full = door_listen::quota_full(m.values().map(|l| &l.owner), principal);
        if !m.contains_key(&key) && full {
            return false;
        }
        m.insert(key, kept);
        true
    });
    if !admitted {
        let refusal = door_listen::quota_refusal(id);
        return Some(Pending::answer(refusal.status, refusal.body(), None, &[]));
    }
    Some(Pending::answer(200, lines(&frames), None, &[]))
}

/// Frames as lines: one JSON-RPC message per line.
fn lines(frames: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in frames {
        if !out.is_empty() {
            out.push(b'\n');
        }
        out.extend(serde_json::to_vec(frame).unwrap_or_default());
    }
    out
}

/// THE LAPSE of live asks: a round whose ask in flight went [`line::ASK_TIMEOUT_NS`] unanswered is
/// dropped and the caller is handed the `input_required` result itself, emitted on its session (the
/// unit that put the ask answered nothing, so the fallback is a line of its own).
fn lapse_asks(plane: &McpDoor, ticket: Ticket, now_ns: u64, seq: &mut u32) {
    let lapsed: Vec<(u64, Vec<u8>)> = plane.live_asks.with_all(|m| {
        let keys: Vec<(u64, u64)> = m
            .iter()
            .filter(|(_, live)| live.lapsed(now_ns))
            .map(|(key, _)| *key)
            .collect();
        keys.iter()
            .filter_map(|key| m.remove(key).map(|live| (key.0, live.fallback)))
            .collect()
    });
    for (session, mut fallback) in lapsed {
        fallback.push(b'\n');
        emit(plane, ticket, *seq, session, &fallback);
        *seq = seq.wrapping_add(1);
    }
}

/// Busbar's own `ping`, as one line: its answer is a line of the caller's, so a unit.
fn ping(plane: &McpDoor) -> Vec<u8> {
    let n = next_ask(plane);
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": format!("{}{n}", line::ASK_ID_PREFIX),
        "method": crate::adapt::METHOD_PING,
    }))
    .unwrap_or_default()
}

/// THE TICK, for the subscriptions kept on carrier sessions: each stepped over the live catalogue
/// under the standing and grants its caller's units last re-asked ([`reconfirm`]), what it says
/// emitted on its session (a `ping` when it has been quiet, or when its standing is due to be
/// re-asked), and a subscription whose session can take nothing more, or that ended (its
/// permission lapsed, or not re-confirmed), dropped.
pub(super) fn tick(plane: &McpDoor, ticket: Ticket, now_ns: u64) {
    let mut seq: u32 = 0;
    lapse_asks(plane, ticket, now_ns, &mut seq);
    let Some(held) = plane.current() else {
        return;
    };
    plane.line_listens.with_all(|m| {
        let mut gone = Vec::new();
        for ((session, key), kept) in m.iter_mut() {
            let (mut bytes, ended) = match kept.step_at(&held.catalogue, now_ns) {
                ListenStep::Frames(frames) => (lines(&frames), false),
                ListenStep::Keepalive => {
                    kept.pinged_ns = now_ns;
                    (ping(plane), false)
                }
                ListenStep::Quiet => (Vec::new(), false),
                ListenStep::End(frames) => (lines(&frames), true),
                ListenStep::Closed => (Vec::new(), true),
            };
            if !ended && kept.wants_ping(now_ns) {
                if !bytes.is_empty() {
                    bytes.push(b'\n');
                }
                bytes.extend(ping(plane));
            }
            let went = bytes.is_empty() || emit(plane, ticket, seq, *session, &bytes);
            seq = seq.wrapping_add(1);
            if ended || !went {
                gone.push((*session, key.clone()));
            }
        }
        for key in &gone {
            m.remove(key);
        }
    });
}

#[cfg(test)]
#[path = "tests/door_line_tests.rs"]
mod tests;
