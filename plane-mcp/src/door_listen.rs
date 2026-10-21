// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `subscriptions/listen` ON THE HTTP CARRIER: A K6 SESSION (ARCHITECT round 4 Q-L3B-SURFACES (a),
//! confirmed round 5 Q-L3B-K6-HTTP (a)). `arrive` states `ROUTE_SESSION` for it, so the driver
//! serves the unit as a duplex session whose caller leg is the long-lived response; every rule of
//! the subscription is [`crate::subscribe`]'s, the same state machine the line carrier drives.
//!
//! - THE CALLER'S PIECE (the request's body, read once) OPENS the subscription ([`Listen::open`]):
//!   a request that can deliver nothing is refused `400` with its JSON-RPC error; one that opens is
//!   answered `200` as an event stream (`content-type: text/event-stream`,
//!   `cache-control: no-cache, no-store`) whose first event is the acknowledgement.
//! - THE TICK ([`tick`]) is the subscription's clock: every [`POLL_NS`] each held subscription is
//!   named on the instance's driver ticket (`drive`, [`drive`]), and the session collects
//!   (`FROM_KERNEL`): one step, its permission re-asked through the kernel's live re-resolution
//!   ([`standing`]), a change frame when the catalogue its caller can see moved, a
//!   keepalive comment (`: keepalive`) when it has been quiet for
//!   [`crate::subscribe::KEEPALIVE_NS`], and its last frame at its bound or on a lapsed permission,
//!   after which the session is done. A new generation (`refresh`) names them at once ([`wake_all`]).
//! - Every frame is one `message` event (`event: message`, `data: <json>`), as predev wrote them.
//! - THE SESSION'S ONE LINE carries the request's fee unit, reported with the acknowledgement.
//! - A `resourceSubscriptions` uri DELIVERS: before the acknowledgement, each accepted uri no
//!   watcher of the instance holds yet has busbar send `resources/subscribe` to the member that
//!   declares it ([`subscribe_upstream`]); a uri its member does not take is narrowed out of the
//!   acknowledgement. When the last watcher of a uri goes, its member is owed
//!   `resources/unsubscribe` ([`super::door_sessions::release`]).

use std::task::Poll;

use super::{
    ask_entitlements, door_sessions, write, CallUnit, Held, McpDoor, Pending, Written, MAX_UNITS,
};
use crate::catalogue::{Catalogue, Lookup};
use crate::framing::{events, CACHE_CONTROL, CONTENT_TYPE, EVENT_STREAM, NO_STORE};
use crate::subscribe::{Listen, Standing, Step as ListenStep, KEEPALIVE_NS, MAX_LIFETIME_NS};
use crate::tool_arrival::Disposition;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::plane::{
    OnPieceIn, OnPieceOut, PlaneDriveIn, PlaneDriveOut, UnitCount, FROM_CALLER, FROM_KERNEL,
    PIECE_LAST, UNITS_REPORTED,
};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Services};
use serde_json::Value;

/// How often the instance's tick steps its held subscriptions (predev re-read the generation and
/// re-asked the permission every 250 ms of a stream's life).
pub(super) const POLL_NS: u64 = 250_000_000;

/// The most subscriptions one caller holds open at once. A caller at it is refused its next one:
/// a quota is a refusal its caller can act on (close one, then open), where an eviction of another
/// caller's stream is not.
pub(super) const MAX_LISTENS_PER_OWNER: usize = 64;

/// What an idle stream writes to say it is alive: an event-stream comment, which every reader
/// drops, so an intermediary does not reclaim a working connection.
const KEEPALIVE: &[u8] = b": keepalive\n\n";

/// The status an invalid `subscriptions/listen` is refused with.
const STATUS_INVALID: u32 = 400;

/// The status a `subscriptions/listen` is refused with when its caller is at its quota.
const STATUS_QUOTA: u32 = 429;

/// The status a `subscriptions/listen` is refused with when the host's clock cannot be read.
const STATUS_CLOCK: u32 = 503;

/// The status a `subscriptions/listen` is refused with when it asked only for resources and no
/// member that declares them took busbar's subscription.
pub(super) const STATUS_UNTAKEN: u32 = 502;

/// One held subscription, by its session's stream.
#[derive(Debug, Clone)]
pub(super) struct Listening {
    /// The caller that opened it, by the reference the kernel lends every piece of its units (the
    /// one the quota counts under).
    owner: String,
    /// The subscription.
    listen: Box<Listen>,
    /// The session's caller-side ticket.
    ticket: Ticket,
    /// The tick clock's reading at its first tick (`0` before one): a subscription its session
    /// never ended (its caller went away while it was idle, which nothing tells the door) is dropped
    /// once it is past its bound.
    first_tick: u64,
    /// The tick asked for a step it has not collected.
    due: bool,
    /// The stream's head is written.
    headed: bool,
    /// The upstream announcements `(server, uri)` heard since its last step: its next step relays
    /// those it watches, under the grant it re-asks that frame.
    updates: Vec<(String, String)>,
    /// The members busbar subscribes to for its uris before it is acknowledged, as
    /// `(server, uri)`, one exchange at a time on its caller-side ticket (empty once it is).
    subscribing: Vec<(String, String)>,
    /// How many of those exchanges it made: each numbers its connector handles apart.
    exchanged: u32,
}

/// The uris `listen` watches: its accepted `resourceSubscriptions`.
pub(super) fn uris(listen: &Listen) -> Vec<String> {
    listen.accepted().resources.clone().unwrap_or_default()
}

/// Whether `listen` watches `uri`.
pub(super) fn watching(listen: &Listen, uri: &str) -> bool {
    listen
        .accepted()
        .resources
        .as_ref()
        .is_some_and(|r| r.iter().any(|u| u == uri))
}

/// Whether a subscription held on the HTTP carrier watches `uri`.
pub(super) fn watches(plane: &McpDoor, uri: &str) -> bool {
    plane
        .listens
        .with_all(|m| m.values().any(|l| watching(&l.listen, uri)))
}

/// THE FIRST WATCHERS: the uris `listen` accepted that nothing of the instance watches yet, each
/// with the member that declares it under the caller's grants `admit` (as the narrowing resolved
/// it): those busbar subscribes to upstream before the acknowledgement.
pub(super) fn unwatched(
    plane: &McpDoor,
    listen: &Listen,
    catalogue: &Catalogue,
    admit: &impl Fn(&str, &str) -> bool,
) -> Vec<(String, String)> {
    uris(listen)
        .into_iter()
        .filter(|uri| !door_sessions::watched(plane, uri))
        .filter_map(|uri| match catalogue.resource_by_uri(admit, &uri) {
            Lookup::One(entry) => Some((entry.server.clone(), uri)),
            _ => None,
        })
        .collect()
}

/// The refusal of subscription `id` that asked only for resources no member took busbar's
/// subscription to: it has nothing to deliver.
pub(super) fn untaken(id: Value) -> Vec<u8> {
    let body = busbar_contract::jsonrpc::error_body(
        id,
        crate::codec::CODE_INTERNAL,
        "no MCP server that declares the uris in `params.notifications.resourceSubscriptions` \
         took busbar's subscription to them, so this subscription has nothing to deliver",
        None,
    );
    serde_json::to_vec(&body).unwrap_or_default()
}

/// The most announcements one held subscription keeps between two of its steps (the oldest go).
pub(super) const MAX_HELD_UPDATES: usize = 64;

/// Holds `(server, uri)` for the next step of `updates`, at most [`MAX_HELD_UPDATES`] of them.
pub(super) fn hold_update(updates: &mut Vec<(String, String)>, server: &str, uri: &str) {
    if updates.len() >= MAX_HELD_UPDATES {
        updates.remove(0);
    }
    updates.push((server.to_string(), uri.to_string()));
}

/// AN UPSTREAM ANNOUNCED that `uri` of its registration `server` changed: every held subscription on
/// the HTTP carrier is asked for a step that relays it (the step relays it only to a subscription
/// that asked for the uri, under the caller's grant re-asked that frame), and so is every one kept
/// on a line carrier ([`super::door_line::announced`]).
pub(super) fn announced(plane: &McpDoor, server: &str, uri: &str) {
    let any = plane.listens.with_all(|m| {
        for l in m.values_mut() {
            hold_update(&mut l.updates, server, uri);
            l.due = true;
        }
        !m.is_empty()
    });
    super::door_line::announced(plane, server, uri);
    if any {
        wake_driver(plane);
    }
}

/// A frame of the stream: its head (status, fields and the request's fee unit) with the first.
pub(super) fn frame(bytes: Vec<u8>, done: bool, headed: bool) -> Pending {
    let (fields, units) = if headed {
        (Vec::new(), Vec::new())
    } else {
        (
            vec![
                (CONTENT_TYPE.to_string(), EVENT_STREAM.to_string()),
                (CACHE_CONTROL.to_string(), NO_STORE.to_string()),
            ],
            vec![UnitCount {
                class: crate::door::CLASS_FEE_INDEX,
                source: UNITS_REPORTED,
                amount: 1,
            }],
        )
    };
    Pending {
        status: 200,
        fields,
        request: None,
        bytes,
        sent: 0,
        headed,
        done,
        records: Vec::new(),
        audits: Vec::new(),
        lane: None,
        units,
    }
}

/// ONE PIECE OF A LISTEN SESSION (`stream != 0`): the caller's piece opens it, a collection steps
/// it, and the caller's side ending ends it. A re-call after `more = 1` writes what is pending.
pub(super) fn piece(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> Outcome {
    let given = input.get();
    let (key, ticket) = (given.unit, given.head.ticket);
    let caller = input
        .field(|i| &i.caller_ref)
        .as_str()
        .unwrap_or_default()
        .to_string();
    let principal = if caller.is_empty() {
        crate::ask::UNGOVERNED
    } else {
        caller.as_str()
    };
    let step = plane.units.with(&key, |unit| {
        let unit = unit?;
        unit.ticket = Some(ticket);
        if unit.pending.is_some() {
            return Some(Poll::Ready(true));
        }
        match given.from {
            // The caller went away: the session ends with nothing more to say.
            FROM_CALLER if given.flags & PIECE_LAST != 0 => {
                unit.pending = Some(frame(Vec::new(), true, true));
                Some(Poll::Ready(true))
            }
            FROM_CALLER => open(instance, plane, ticket, principal, unit),
            FROM_KERNEL if given.attempt_no == 0 => {
                if plane.listens.with(&key, |l| l.is_none()) {
                    return Some(Poll::Ready(false));
                }
                step(plane, ticket, principal, unit).map(Poll::Ready)
            }
            // A listen session dials nothing: an ATTEMPT carries nothing.
            FROM_KERNEL => Some(Poll::Ready(false)),
            _ => None,
        }
    });
    match step {
        None => Outcome::Refused,
        Some(Poll::Pending) => Outcome::Pending,
        Some(Poll::Ready(false)) => Outcome::Ready,
        Some(Poll::Ready(true)) => {
            let written = plane.units.with(&key, |unit| {
                let pending = unit?.pending.as_mut()?;
                Some(write(&input, out, pending))
            });
            match written {
                None | Some(Err(())) => Outcome::Failed,
                Some(Ok(Written::More)) => Outcome::Ready,
                Some(Ok(Written::Sent)) => {
                    plane.units.with(&key, |unit| {
                        if let Some(unit) = unit {
                            unit.pending = None;
                        }
                    });
                    Outcome::Ready
                }
                Some(Ok(Written::Done)) => {
                    plane.units.remove(&key);
                    // Its uris are released: what their last watcher owes is carried by a unit.
                    if let Some(l) = plane.listens.remove(&key) {
                        door_sessions::release(plane, uris(&l.listen));
                    }
                    Outcome::Ready
                }
            }
        }
    }
}

/// OPEN the subscription the unit's request asks for: refused `400` in its own words, or held,
/// subscribed upstream for the uris no watcher holds yet ([`subscribe_upstream`], PENDING while an
/// exchange does), and stepped once (the acknowledgement). `None` for a unit that is not a
/// `subscriptions/listen`.
fn open(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
) -> Option<Poll<bool>> {
    let Disposition::Request { row, id } = &unit.disposition else {
        return None;
    };
    if row.op != crate::tool_ops::OP_SUBSCRIPTIONS_LISTEN {
        return None;
    }
    let id = id.clone();
    let held = plane.current().or_else(|| unit.held.clone())?;
    // AN OPEN UNDER WAY goes on with its subscriptions upstream; one held and acknowledged has
    // nothing more to open.
    match plane
        .listens
        .with(&unit.key, |l| l.map(|l| !l.subscribing.is_empty()))
    {
        Some(true) => {
            return Some(subscribe_upstream(
                instance, plane, ticket, principal, unit, &held,
            ))
        }
        Some(false) => return Some(Poll::Ready(false)),
        None => {}
    }
    entitled_afresh(plane, ticket, unit, &held);
    // A subscription opened at a clock read that failed is refused, never opened at the epoch
    // (row 159 finding P-M4): its lifetime and keepalive are judged against this reading.
    let Some(now) = mono_ns(plane.services, ticket, unit) else {
        let refusal = crate::tool_arrival::Refusal {
            status: STATUS_CLOCK,
            id: Some(id),
            code: crate::codec::CODE_REFUSED,
            message: super::CLOCK_UNREAD.to_string(),
            data: None,
        };
        unit.pending = Some(Pending::answer(refusal.status, refusal.body(), None, &[]));
        return Some(Poll::Ready(true));
    };
    let opened = {
        let entitled = &unit.entitled;
        let admit = |kind: &str, name: &str| {
            entitled
                .get(&format!("{kind}:{name}"))
                .copied()
                .unwrap_or(false)
        };
        Listen::open(unit.params.as_ref(), id, now, |uri| {
            matches!(held.catalogue.resource_by_uri(&admit, uri), Lookup::One(_))
        })
        .map(|listen| {
            let first = unwatched(plane, &listen, &held.catalogue, &admit);
            (listen, first)
        })
    };
    match opened {
        Err(refusal) => {
            let body = serde_json::to_vec(&refusal).unwrap_or_default();
            unit.pending = Some(Pending::answer(STATUS_INVALID, body, None, &[]));
            Some(Poll::Ready(true))
        }
        Ok((listen, first)) => {
            let id = listen.id.clone();
            let listening = Listening {
                owner: principal.to_string(),
                listen: Box::new(listen),
                ticket,
                first_tick: 0,
                due: false,
                headed: false,
                updates: Vec::new(),
                subscribing: Vec::new(),
                exchanged: 0,
            };
            // THE QUOTA REFUSES THE NEW STREAM, never evicts a held one: this caller at its own
            // bound, or the instance at its total, is told so.
            let admitted = plane.listens.with_all(|held| {
                let full = held.len() >= MAX_UNITS
                    || held.values().filter(|l| l.owner == principal).count()
                        >= MAX_LISTENS_PER_OWNER;
                if !full {
                    held.insert(unit.key, listening);
                }
                !full
            });
            if !admitted {
                let refusal = quota_refusal(id);
                unit.pending = Some(Pending::answer(refusal.status, refusal.body(), None, &[]));
                return Some(Poll::Ready(true));
            }
            // A uri whose last watcher went while its unsubscribe was still owed keeps busbar's
            // subscription: nothing is sent for it.
            let owing: Vec<(String, String)> = first
                .into_iter()
                .filter(|(_, uri)| !door_sessions::unowe(plane, uri))
                .collect();
            plane.listens.with(&unit.key, |l| {
                if let Some(l) = l {
                    l.subscribing = owing;
                }
            });
            Some(subscribe_upstream(
                instance, plane, ticket, principal, unit, &held,
            ))
        }
    }
}

/// BUSBAR'S SUBSCRIPTIONS UPSTREAM for the subscription the unit is opening: for each
/// `(server, uri)` it still owes, `resources/subscribe` sent to that member over the plane's own
/// reach ([`door_sessions::upstream`]) on the unit's ticket, one exchange at a time; a uri its
/// member does not take is narrowed out of the acknowledgement, never acknowledged as watched. Then
/// the acknowledgement, or, with nothing left to deliver, the refusal ([`untaken`]). PENDING while
/// an exchange does.
fn subscribe_upstream(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    held: &Held,
) -> Poll<bool> {
    let key = unit.key;
    loop {
        let next = plane.listens.with(&key, |l| {
            let l = l?;
            Some((l.subscribing.first().cloned()?, l.exchanged))
        });
        let Some(((server, uri), exchanged)) = next else {
            break;
        };
        let verb = crate::client::verb::UpstreamVerb::ResourcesSubscribe { uri: uri.clone() };
        let base = door_sessions::subscribe_base(exchanged);
        let slot = &mut unit.negotiating;
        let Poll::Ready(taken) =
            door_sessions::upstream(instance, plane, slot, base, held, &server, &verb)
        else {
            return Poll::Pending;
        };
        let delivers = plane.listens.with(&key, |l| {
            let l = l?;
            l.subscribing.remove(0);
            l.exchanged = l.exchanged.saturating_add(1);
            Some(taken.is_ok() || l.listen.drop_resource(&uri))
        });
        if delivers == Some(false) {
            if let Some(l) = plane.listens.remove(&key) {
                let id = l.listen.id.clone();
                door_sessions::release(plane, uris(&l.listen));
                unit.pending = Some(Pending::answer(STATUS_UNTAKEN, untaken(id), None, &[]));
                return Poll::Ready(true);
            }
        }
    }
    Poll::Ready(step(plane, ticket, principal, unit).unwrap_or(false))
}

/// THE QUOTA'S REFUSAL of subscription `id`, on either carrier: its caller holds the most open
/// subscriptions one caller may, or the instance its total.
pub(super) fn quota_refusal(id: Value) -> crate::tool_arrival::Refusal {
    crate::tool_arrival::Refusal {
        status: STATUS_QUOTA,
        id: Some(id),
        code: crate::codec::CODE_REFUSED,
        message: format!(
            "this caller holds {MAX_LISTENS_PER_OWNER} open subscriptions, the most one caller may \
             hold; close one and open again"
        ),
        data: Some(serde_json::json!({ "reason": "subscription_quota" })),
    }
}

/// ONE STEP of the unit's subscription over the live catalogue, its permission re-asked: what it
/// writes, if anything. `Some(false)` when it has nothing to say.
fn step(plane: &McpDoor, ticket: Ticket, principal: &str, unit: &mut CallUnit) -> Option<bool> {
    // One still subscribing upstream says nothing yet: its acknowledgement comes first.
    if plane
        .listens
        .with(&unit.key, |l| l.is_some_and(|l| !l.subscribing.is_empty()))
    {
        return Some(false);
    }
    let held = plane.current().or_else(|| unit.held.clone())?;
    entitled_afresh(plane, ticket, unit, &held);
    // A step whose clock read failed says nothing: the next one reads it again.
    let Some(now) = mono_ns(plane.services, ticket, unit) else {
        return Some(false);
    };
    let standing = standing(plane, ticket, principal, unit);
    let entitled = &unit.entitled;
    let admit = |kind: &str, name: &str| {
        entitled
            .get(&format!("{kind}:{name}"))
            .copied()
            .unwrap_or(false)
    };
    let (stepped, headed) = plane.listens.with(&unit.key, |l| {
        let l = l?;
        l.due = false;
        let updates = std::mem::take(&mut l.updates);
        let stepped = l
            .listen
            .step(&held.catalogue, &admit, &standing, &updates, now);
        Some((stepped, l.headed))
    })?;
    let (bytes, done) = match stepped {
        ListenStep::Frames(frames) => (events(&frames), false),
        ListenStep::Keepalive => (KEEPALIVE.to_vec(), false),
        ListenStep::Quiet => return Some(false),
        ListenStep::End(frames) => (events(&frames), true),
        ListenStep::Closed => (Vec::new(), true),
    };
    // The head goes with the stream's first frame (its acknowledgement, or the last frame of a
    // stream whose permission lapsed before it).
    plane.listens.with(&unit.key, |l| {
        if let Some(l) = l {
            l.headed = true;
        }
    });
    unit.pending = Some(frame(bytes, done, headed));
    Some(true)
}

/// THE TICK: the instance's driver ticket and the tick clock noted, every held subscription asked
/// for a step (a subscription past its bound that never ended is dropped), and the driver ticket
/// woken when any is held. The next tick is [`POLL_NS`] on.
pub(super) fn tick(plane: &McpDoor, driver: Ticket, now_ns: u64) -> u64 {
    plane.driver.insert((), (driver, now_ns));
    let stale = MAX_LIFETIME_NS.saturating_add(KEEPALIVE_NS);
    let (gone, released, any) = plane.listens.with_all(|m| {
        let mut gone = Vec::new();
        for (key, l) in m.iter_mut() {
            if l.first_tick == 0 {
                l.first_tick = now_ns.max(1);
            }
            if now_ns.saturating_sub(l.first_tick) > stale {
                gone.push(*key);
            }
            l.due = true;
        }
        let mut released = Vec::new();
        for key in &gone {
            if let Some(l) = m.remove(key) {
                released.extend(uris(&l.listen));
            }
        }
        (gone, released, !m.is_empty())
    });
    for key in gone {
        plane.units.remove(&key);
    }
    door_sessions::release(plane, released);
    // A held 2024-11-05 stream is read on the driver ticket too.
    if any || super::door_legacy::any(plane) {
        wake_driver(plane);
    }
    now_ns.saturating_add(POLL_NS)
}

/// A new generation: every held subscription is asked for a step at once.
pub(super) fn wake_all(plane: &McpDoor) {
    let any = plane.listens.with_all(|m| {
        for l in m.values_mut() {
            l.due = true;
        }
        !m.is_empty()
    });
    if any {
        wake_driver(plane);
    }
}

/// `drive`: the sessions whose step is due, by stream, as many as the host's buffer takes; each one
/// named collects on its caller-side ticket.
pub(super) fn drive(
    plane: &McpDoor,
    input: Lent<'_, PlaneDriveIn>,
    out: &mut Out<'_, PlaneDriveOut>,
) -> Outcome {
    // One still subscribing upstream is not collected: its own piece pends on the exchange.
    let mut due: Vec<u64> = plane.listens.with_all(|m| {
        m.iter()
            .filter(|(_, l)| l.due && l.subscribing.is_empty())
            .map(|(stream, _)| *stream)
            .collect()
    });
    // The session revisions' held streams owe their collections on the same driver ticket.
    let streams = super::door_sessions::due_streams(plane);
    due.extend(&streams);
    let mut buf = input.sessions_buf();
    for stream in &due {
        buf.push(*stream);
    }
    if !buf.fits() {
        out.set(|o| &o.sessions_needed, buf.needed() as u32);
        return Outcome::Failed;
    }
    out.set(|o| &o.sessions_written, buf.written() as u32);
    plane.listens.with_all(|m| {
        for stream in &due {
            if let Some(l) = m.get_mut(stream) {
                l.due = false;
            }
        }
    });
    super::door_sessions::taken(plane, &streams);
    Outcome::Ready
}

/// The op on `ticket` was cancelled: the subscription it carried is dropped, its uris released.
pub(super) fn cancelled(plane: &McpDoor, ticket: Ticket) {
    let released: Vec<String> = plane.listens.with_all(|m| {
        let gone: Vec<u64> = m
            .iter()
            .filter(|(_, l)| l.ticket == ticket)
            .map(|(key, _)| *key)
            .collect();
        gone.iter()
            .filter_map(|key| m.remove(key))
            .flat_map(|l| uris(&l.listen))
            .collect()
    });
    door_sessions::release(plane, released);
}

/// Name the instance's driver ticket (as its last tick handed it): a held subscription owes a step.
pub(super) fn wake_driver(plane: &McpDoor) {
    let driver = plane.driver.get(&()).map(|(ticket, _)| ticket);
    if let (Some(wake), Some(ticket)) = (plane.wake, driver) {
        if ticket != Ticket::NONE {
            wake.wake(ticket);
        }
    }
}

// ── what a held unit re-asks each frame, and the round busbar's own ask costs ──────────────────

/// Whether a request asks busbar's own round before it is answered: a `prompts/get` of a prompt
/// whose operator asks its caller first, presenting no answers yet (the served engine charged that
/// round on the caller's budget).
pub(super) fn asks_a_round(
    op: busbar_contract::ids::OpClassId,
    held: &Held,
    value: &Value,
) -> bool {
    if op != crate::tool_ops::OP_PROMPT_GET {
        return false;
    }
    let params = value.get("params");
    let retried = params
        .is_some_and(|p| p.get("inputResponses").is_some() || p.get("requestState").is_some());
    let asks = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .and_then(|name| held.catalogue.prompt_for(&|_: &str, _: &str| true, name))
        .is_some_and(|p| !p.ask_caller.is_empty());
    asks && !retried
}

/// The host's monotonic clock on a fresh handle of the unit's ticket; `None` with no clock or a
/// failed read, which is never a time (row 159 finding P-M4): no timer is armed at it.
pub(super) fn mono_ns(
    services: Option<Services>,
    ticket: Ticket,
    unit: &mut CallUnit,
) -> Option<u64> {
    let services = services?;
    let handle = CompletionHandle {
        ticket,
        seq: unit.issued,
        _reserved: 0,
    };
    unit.issued += 1;
    services.clock_now(handle).ok().map(|r| r.mono_ns)
}

/// The catalogue's every grant, entitled afresh for this frame: a held unit re-asks what its caller
/// may see each time it looks.
pub(super) fn entitled_afresh(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit, held: &Held) {
    unit.entitled.clear();
    ask_entitlements(plane.services, ticket, unit, &held.catalogue.grants());
}

/// Whether the unit's principal still stands: the kernel's live re-resolution
/// (`entitlement.check` of [`busbar_contract::abi::host::service::ENTITLEMENT_STANDING`]). A host
/// that serves no entitlement stands nothing.
fn stands(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit) -> bool {
    let Some(services) = plane.services else {
        return false;
    };
    let handle = CompletionHandle {
        ticket,
        seq: unit.issued,
        _reserved: 0,
    };
    unit.issued += 1;
    services
        .entitled(
            handle,
            busbar_contract::abi::host::service::ENTITLEMENT_STANDING,
        )
        .unwrap_or(false)
}

/// THE PERMISSION, RE-ASKED THIS FRAME: the kernel re-resolves the unit's principal live
/// ([`stands`]); one that no longer stands is lapsed, in predev's words, and ends the subscription on
/// this frame (on either carrier).
pub(super) fn standing(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
) -> Standing {
    if stands(plane, ticket, unit) {
        Standing::Live
    } else {
        Standing::Lapsed {
            message: format!(
                "`{principal}` is no longer live, so the standing decision it was admitted under \
                 no longer applies"
            ),
            reason: busbar_contract::vocab::REASON_IDENTITY_NOT_LIVE.to_string(),
        }
    }
}
