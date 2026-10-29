// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S DOOR, SERVED: the slots the kernel calls over the plane ABI, on the SDK's safe
//! surface. [`door`] is the LINKED door; the same function is the DROPPED door once a `cdylib`
//! exports it (`busbar_contract::export_door!`), so the two cannot answer differently.
//!
//! The lifecycle is this plane's own:
//!
//! * `validate` reads the settings blob as the `tools:` section ([`door::read_tools_section`]) and
//!   refuses in the grammar's words;
//! * `open` judges the same section, reads the deployment's public base URL, keeps the host
//!   services it was handed and publishes the first generation's snapshot
//!   ([`door::snapshot_spec_with`]); `refresh` judges the new section and publishes the next generation
//!   over the base URL `open` was given; `retire` drops a generation's snapshot, and what the plane
//!   held for it ([`Held`]) with it. A request is answered from the newest live generation
//!   ([`McpDoor::current`]);
//! * `tick` is the clock of the subscriptions held as K6 sessions on the HTTP carrier and `drive`
//!   names the ones whose step is due ([`door_listen`]), `cancel` drops the cancelled unit, and
//!   `release`/`close` hold nothing the SDK does not already drop.
//!
//! The request path (the plane driver):
//!
//! * `arrive` decides what the arrival is ([`crate::tool_arrival::decide`]) and keeps it, with the
//!   generation it arrived under and how its answer is framed ([`crate::framing::Framing`]),
//!   keyed by the unit. A refused arrival states its refusal in its own words.
//! * `on_piece` answers. The kernel's ATTEMPT piece names the member its walk picked; the caller's
//!   body then either is answered from what the plane holds ([`crate::answer`]) or, for a
//!   `tools/call` the caller may make ([`crate::call::admit_call`]), becomes the request bound for that
//!   member ([`crate::call::outbound`]). The far end's answer is settled into the caller's
//!   ([`crate::call::settle_call_as`]). An answer the reply buffer cannot hold is written over several
//!   calls (`more = 1`).
//! * Every visibility question a request asks is the kernel's ENTITLEMENT answer for the unit's
//!   principal (`entitlement.check`), asked once per grant per unit: nothing is visible to a unit
//!   the kernel did not entitle.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{
    GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneCancelIn, PlaneCancelOut,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot,
    ProjectIn, ProjectOut, RecordWrite, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount,
    AUDIT_APPLIED, AUDIT_REJECTED, CANCEL_ABORTED, CANCEL_OK_PARTIAL, EMIT_DONE, EMIT_TO_FAR_END,
    FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED,
    RECORD_AUDIT, RECORD_PUT, REFUSAL_ARRIVE, REFUSAL_GATE, REFUSAL_KERNEL, ROUTE_DIRECT,
    ROUTE_POOL, UNITS_REPORTED, VERDICT_RETRY,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::exchange::{REPLY_MAX, REPLY_OVER_BOUND};
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::publish::{Generations, Keyed};
use busbar_contract::abi::sdk::services::ServiceError;
use busbar_contract::abi::sdk::{
    HostBuf, Instance, Lent, LentList, Out, Safe, SafeSlot, Services, StaticServices,
};
use serde_json::Value;

use crate::answer::Answer;
use crate::ask::AskDecision;
use crate::call::{Admission, AdmittedCall, Settled};
use crate::catalogue::Catalogue;
use crate::door::{self};
use crate::framing::{
    Framing, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, EVENT_STREAM, JSON, NO_STORE,
};
use crate::tool_arrival::Disposition;
use crate::tools_config::ToolsCfg;

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// The names of the diagnostics the door raises, as its Statement's diagnostic ids spell them
/// (`door_sessions::DIAG_NAMES`): what the tests hold `declares.json` to.
#[cfg(test)]
pub(crate) const DIAG_NAMES: &[&str] = door_sessions::DIAG_NAMES;

/// How many diagnostic ids the Statement states.
#[cfg(test)]
pub(crate) const DIAG_IDS_LEN: usize = door_sessions::DIAG_IDS.len();

/// THE STATEMENT: the plane's name and version, the settings sections it declares
/// ([`door::SECTIONS`]), its outbound needs ([`door::NEEDS`]) and its tail ([`door::TAIL`]).
pub const STATEMENT: Statement = {
    // At most 64 calls in flight on one instance, as the transport doors state it.
    let mut s = statement(crate::PLANE_KEY, VERSION, 64)
        .with_sections(door::SECTIONS)
        .with_needs(door::NEEDS)
        .with_secret_refs(door::SECRET_REFS)
        // The instance's own diagnostic: an ungoverned chain's sessions are unisolated
        // ([`door_sessions::UNGOVERNED_LEGACY_STREAM`]).
        .with_diag_ids(door_sessions::DIAG_IDS)
        .with_kind_tail(door::TAIL);
    s.extensions = EXTENSIONS;
    s
};

busbar_contract::statement_extensions!(
    /// The Statement's extensions: this plugin's whole `declares` document,
    /// the one `declares.json` the release also signs into a dropped-in plane's manifest. It states
    /// the plane's breaker fact (one transient failure below the trip threshold never
    /// benches a member), the codes it
    /// raises (`diagnostics::DIAGNOSTICS`; the tests hold the two equal) and the carriers it needs.
    /// Why no bench: an MCP call's errors are mostly the tool's own answer (a tool says no), not a
    /// sign the server is unhealthy, so only a trip benches it.
    EXTENSIONS: [(
        busbar_contract::abi::mechanism::extensions::EXT_DECLARES,
        include_bytes!("../declares.json")
    )]
);

/// WHAT THE PLANE HOLDS FOR ONE GENERATION: the catalogue built from its section, and the section
/// itself (each member's registration).
#[derive(Debug)]
pub struct Held {
    /// The catalogue.
    pub catalogue: Catalogue,
    /// The section it was built from.
    pub section: ToolsCfg,
    /// The pools its servers are members of ([`door::read_open`]).
    pub pools: BTreeMap<String, door::ToolPool>,
}

impl Held {
    /// What a generation holds over `section`.
    #[must_use]
    pub fn of(generation: u64, section: ToolsCfg) -> Self {
        Held {
            catalogue: Catalogue::build(generation, &section),
            section,
            pools: BTreeMap::new(),
        }
    }

    /// The pool `server` is a member of, by name, when it is one (the first in name order).
    #[must_use]
    pub fn pool_of(&self, server: &str) -> Option<(&str, &door::ToolPool)> {
        self.pools
            .iter()
            .find(|(_, p)| p.members.iter().any(|m| m == server))
            .map(|(name, p)| (name.as_str(), p))
    }
}

/// One instance: the public base URL `open` was given, the host services, every live generation's
/// snapshot with what the plane holds for it, and the units in flight.
#[derive(Default)]
pub struct McpDoor {
    /// The endpoint its claims are stated under: its audience and metadata document
    /// ([`door::admitted`]).
    admitted: Option<(String, String)>,
    /// Its protected-resource facts ([`door::resource_facts`]).
    facts: Option<Vec<u8>>,
    /// The browser origins it admits beyond loopback ([`door::allowed_origins`]).
    origins: Vec<String>,
    services: Option<StaticServices>,
    generations: Generations<PlaneSnapshot, Held>,
    units: Keyed<u64, CallUnit>,
    /// Each principal's roots epoch: moved by its `notifications/roots/list_changed`, sealed into
    /// an exchange that asks for roots. Bounded at [`MAX_ROOTS_PRINCIPALS`]; past it a principal's
    /// change moves the shared epoch ([`Self::roots_shared`]) instead.
    roots: Keyed<String, u64>,
    /// The epoch every principal's roots epoch is read beside: moved by a change the full
    /// [`Self::roots`] table could not record for its own principal, so that change invalidates
    /// every sealed exchange rather than none.
    roots_shared: Keyed<(), u64>,
    /// The host tables `open` handed it: the connector a `connect` reaches its server through.
    host: Option<busbar_contract::abi::sdk::conn::StaticHost>,
    /// Each registered server's last sighting (`connect`): what the trust views and the dispatch
    /// gate judge against the section's approval.
    sightings: Keyed<String, crate::trust::Sighting>,
    /// THE LOCAL HALF OF THE SPENT-APPROVAL LEDGER: each nonce this instance redeemed, until the
    /// state it records lapses. Consulted before the host's one-time claim, so a node refuses its
    /// own replay without a round trip, and the whole gate where the host binds no store.
    spent: Keyed<String, u64>,
    /// When each registered server's tool list was last fetched (Unix ms, the kernel's clock): what
    /// verify-on-call reads its `verify_ttl` against.
    checked: Keyed<String, u64>,
    /// When each server's last ACCEPTED `list_changed` marked its list stale (the kernel's
    /// monotonic clock, ms): what the notifications' rate limit is read against
    /// ([`door_sessions::list_changed`]).
    list_noticed: Keyed<String, u64>,
    /// The host's wake (`HostTables::wake`): a task's continuation and a held subscription are woken
    /// through it when what they wait for moves.
    wake: Option<busbar_contract::abi::sdk::StaticWake>,
    /// The subscriptions held as K6 sessions on the HTTP carrier, by stream ([`door_listen`]).
    listens: Keyed<u64, door_listen::Listening>,
    /// The instance's driver ticket and the tick clock, as its last `tick` handed them.
    driver: Keyed<(), (Ticket, u64)>,
    /// THE STDIO SERVERS' GREETINGS: the generation of each member's child the door ran
    /// `initialize` on ([`door_program`]), once per generation.
    greeted: Keyed<String, u64>,
    /// The requests of a stdio child's own the door decided, by member, generation and id: the call
    /// a granted ask was put to, or `None` = busbar answered it, decided once by whichever exchange
    /// read it first.
    answered: Keyed<(), door_program::Answered>,
    /// The line of calls relayed to stdio children: which call a child serves, so whose its ask
    /// is ([`door_program::Relaying`]).
    relaying: door_program::Relaying,
    /// THE TASKS this instance holds, by `taskId` (SEP-2663, [`door_tasks`]).
    tasks: Keyed<String, crate::tool_tasks::Task>,
    /// The result chunks of dropped tasks still to strike, by `taskId`: how many.
    strikes: Keyed<String, u32>,
    /// THE LIVE ASK ROUNDS on carrier sessions, by `(session, ask number)` ([`door_line`]).
    live_asks: Keyed<(u64, u64), crate::line::LiveAsk>,
    /// The subscriptions kept on carrier sessions, by `(session, request id)` ([`door_line`]).
    line_listens: Keyed<(u64, String), door_line::LineListen>,
    /// The last number busbar spelled one of its own requests on a carrier session in.
    ask_seq: Keyed<(), u64>,
    /// THE WORK HANDLES stdio children's relayed asks are correlated under, by handle: when each
    /// lapses (Unix ms). One the caller never came back for is settled by the next relay's sweep,
    /// so an abandoned ask does not hold a live handle forever.
    relays: Keyed<u64, u64>,
    /// THE SESSIONS of the session revisions and the `2024-11-05` stream: this process's, bounded
    /// per owner in count and bytes ([`crate::tool_sessions::SessionTable`], [`door_sessions`]).
    sessions: Keyed<(), crate::tool_sessions::SessionTable>,
    /// Each session's own state beside its table row: its subscriptions, its log floor, the
    /// updates announced for it.
    session_state: Keyed<String, door_sessions::SessionState>,
    /// The held GET streams of the sessions, by unit.
    streams: Keyed<u64, door_sessions::Stream>,
    /// WHAT BUSBAR REMEMBERS ABOUT EACH UPSTREAM as a client: the revision it negotiated and its
    /// session ([`crate::tool_sessions::UpstreamTable`]).
    upstreams: Keyed<(), crate::tool_sessions::UpstreamTable>,
    /// THE HELD `2024-11-05` EVENT STREAMS busbar reaches legacy-only servers over, by member and
    /// caller binding ([`door_legacy`]).
    legacy: Keyed<String, door_legacy::Link>,
    /// The tick cycle the held streams' driver-ticket handles are numbered in, and how many they
    /// issued in it, all links together ([`door_legacy::drive`]).
    legacy_seq: Keyed<(), (u64, u32)>,
    /// Whether this instance said its ungoverned chain's sessions are unisolated (once).
    said_ungoverned: Keyed<(), ()>,
    /// The session revision each line-carrier session negotiated with `initialize`.
    line_revisions: Keyed<u64, crate::revision::Revision>,
    /// THE OPERATOR `connect`S UNDER WAY, by server: the ticket each runs on and its negotiated
    /// fetch, kept while it pends (an operator verb has no unit to keep it on). One per server: a
    /// newer `connect` of the same server takes its place.
    connecting: Keyed<String, (Ticket, Box<door_sessions::Negotiating>)>,
}

impl McpDoor {
    /// What a request arriving now is answered from: the newest live generation's.
    #[must_use]
    pub fn current(&self) -> Option<Arc<Held>> {
        self.generations.current()
    }
}

/// One slot body on the SDK's safe surface, over this plane's [`McpDoor`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = McpDoor;
            fn call($inst: Instance<'_, McpDoor>, $input: Lent<'_, $in>, $o: Out<'_, $out>)
                -> Outcome $body
        }
    };
}

slot!(
    /// `validate`: the settings read as the section, or refused in the grammar's words.
    Validate, ValidateIn, OutHead, |_, input, mut out| {
        match door::read_dealt_tools(input.settings().bytes()) {
            Ok(_) => Outcome::Ready,
            Err(text) => out.fail(Refusal::refused(text)),
        }
    }
);

slot!(
    /// `open`: the instance over the section, the public base URL and the host services, and the
    /// first generation's snapshot.
    Open, PlaneOpenIn, PlaneOpenOut, |instance, input, mut out| {
        let (cfg, pools) = match door::read_open(input.open().settings().bytes()) {
            Ok(opened) => opened,
            Err(text) => return out.fail(Refusal::refused(text)),
        };
        let generation = input.open().generation();
        let owned = input.owned().bytes();
        let admitted = match door::admitted_endpoint(
            input.public_url().stated().as_deref(),
            owned,
        ) {
            Ok(admitted) => admitted,
            Err(text) => return out.fail(Refusal::refused(text)),
        };
        let facts = match door::resource_facts(owned) {
            Ok(facts) => facts,
            Err(text) => return out.fail(Refusal::refused(text)),
        };
        let origins = match door::allowed_origins(owned) {
            Ok(origins) => origins,
            Err(text) => return out.fail(Refusal::refused(text)),
        };
        let open = input.field(|i| &i.open);
        let host = open.host();
        let plane = McpDoor {
            admitted,
            facts,
            origins,
            services: host.and_then(|h| Services::of(&h)),
            host: host.map(|h| busbar_contract::abi::sdk::conn::Host::of(&h)),
            wake: host.and_then(|h| busbar_contract::abi::sdk::services::Wake::of(&h)),
            ..McpDoor::default()
        };
        plane.sessions.insert(
            (),
            crate::tool_sessions::SessionTable::new(crate::tool_sessions::Bounds::default()),
        );
        plane.upstreams.insert(
            (),
            // The upstreams busbar remembers a negotiated revision for, and their bytes: forgetting
            // one costs one renegotiation.
            crate::tool_sessions::UpstreamTable::new(1024, 1 << 20),
        );
        let spec = door::snapshot_spec_with(plane.admitted.clone(), plane.facts.clone());
        let held = Held {
            pools,
            ..Held::of(generation, cfg)
        };
        out.publish_with(|o| &o.snapshot, &plane.generations, generation, &spec, held);
        instance.open(plane);
        Outcome::Ready
    }
);

slot!(
    /// `refresh`: the new section judged, and the next generation's snapshot over the same public base
    /// URL.
    Refresh, RefreshIn, PlaneRefreshOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let (cfg, pools) = match door::read_open(input.settings().bytes()) {
            Ok(opened) => opened,
            Err(text) => return out.fail(Refusal::refused(text)),
        };
        let generation = input.generation();
        let spec = door::snapshot_spec_with(plane.admitted.clone(), plane.facts.clone());
        let held = Held {
            pools,
            ..Held::of(generation, cfg)
        };
        out.publish_with(|o| &o.snapshot, &plane.generations, generation, &spec, held);
        // A subscription held as a session compares what its caller can see on the move.
        door_listen::wake_all(plane);
        Outcome::Ready
    }
);

slot!(
    /// `retire`: the generation's snapshot is dropped.
    Retire, GenIn, OutHead, |instance, input, _| {
        if let Some(plane) = instance.get() {
            plane.generations.retire(input.generation());
        }
        Outcome::Ready
    }
);

slot!(
    /// `tick`: the clock of the subscriptions held as sessions ([`door_listen::tick`]), every
    /// [`door_listen::POLL_NS`].
    Tick, TickIn, TickOut, |instance, input, mut out| {
        let given = input;
        let next = instance.get().map_or(0, |plane| {
            door_line::tick(plane, given.head().ticket(), given.now_ns());
            let next = door_listen::tick(plane, given.head().ticket(), given.now_ns());
            door_sessions::tick(plane);
            next
        });
        out.set(|o| &o.next_tick_ns, next);
        Outcome::Ready
    }
);

slot!(
    /// `drive`: the subscriptions held as sessions whose step is due ([`door_listen::drive`]).
    Drive, PlaneDriveIn, PlaneDriveOut, |instance, input, mut out| {
        match instance.get() {
            Some(plane) => {
                // The held 2024-11-05 streams are read on this ticket first: what they hand on
                // wakes the calls waiting for it.
                door_legacy::drive(&instance, plane);
                door_listen::drive(plane, input, &mut out)
            }
            None => Outcome::Ready,
        }
    }
);

slot!(
    /// `cancel`: the cancelled unit's state is dropped, found by its ticket or, cancelled before any
    /// piece reached it, by the unit the host names. Answered `CANCEL_OK_PARTIAL` when the far end
    /// had begun its answer, so the units it reported bill when its answer was streamed (the
    /// ledger records what the dialect did), else `CANCEL_ABORTED`.
    Cancel, PlaneCancelIn, PlaneCancelOut, |instance, input, mut out| {
        let mut stopped = Vec::new();
        let mut answered = false;
        if let Some(plane) = instance.get() {
            let ticket = input.cancel().ticket();
            // THE UNIT THE HOST NAMES: `arrive` keyed it, and a unit cancelled before its first
            // piece (a deadline, a reload, a shutdown) carries no ticket yet, so it is found by
            // its key alone (`0`: the driver ticket, or an op in flight that names its own unit).
            let unit = input.unit();
            let cancelled =
                |key: &u64, u: &CallUnit| u.ticket == Some(ticket) || (unit != 0 && *key == unit);
            // A task's continuation the kernel cancelled leaves its task cancelled, audited as the
            // a task its shutdown stopped is audited.
            stopped = door_tasks::cancelled(plane, ticket);
            plane.units.with_all(|m| {
                answered = m.iter().any(|(k, u)| {
                    cancelled(k, u) && u.relay.as_ref().is_some_and(|r| r.status != 0)
                });
                m.retain(|k, u| !cancelled(k, &*u));
            });
            door_listen::cancelled(plane, ticket);
            door_sessions::cancelled(plane, ticket);
            door_legacy::cancelled(plane, ticket);
        }
        // The rows ride the one cancel answer: it may not pend and is never re-called, so rows the
        // host's buffers cannot hold are a FAULT the host is told of, never dropped unsaid.
        let (mut records, mut arena) = (input.records_buf(), input.arena_buf());
        for id in &stopped {
            records.push(audit_write(&mut arena, &crate::call::AuditRow::task_cancel(id)));
        }
        if !(records.fits() && arena.fits()) {
            return Outcome::Fault;
        }
        let (rw, _) = records.settle(false);
        let (aw, _) = arena.settle(false);
        out.set(|o| &o.records_written, rw as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(
            |o| &o.cancel.disposition,
            if answered { CANCEL_OK_PARTIAL } else { CANCEL_ABORTED },
        );
        Outcome::Ready
    }
);

slot!(
    /// `release`: this plane answers under no lease.
    Release, ReleaseIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `close`: the SDK drops the instance and every snapshot it still holds.
    Close, InHead, OutHead, |_, _, _| { Outcome::Ready }
);

// ── the request path ──────────────────────────────────────────────────────────────────────────

/// The most units the instance keeps state for at once; past it, a new arrival is refused.
pub const MAX_UNITS: usize = 4096;

/// The most principals the instance keeps a roots epoch of its own for ([`McpDoor::roots`]).
pub const MAX_ROOTS_PRINCIPALS: usize = MAX_UNITS;

/// `principal`'s roots changed (`notifications/roots/list_changed`): its epoch moves, or, the
/// table full and `principal` not in it, the shared epoch every principal is read beside, so the
/// change is never lost (a stale roots answer sealed under the old epoch is refused either way).
fn roots_changed(plane: &McpDoor, principal: &str) {
    let recorded = plane.roots.with_all(|m| {
        if let Some(epoch) = m.get_mut(principal) {
            *epoch = epoch.wrapping_add(1);
            true
        } else if m.len() < MAX_ROOTS_PRINCIPALS {
            m.insert(principal.to_string(), 1);
            true
        } else {
            false
        }
    });
    if !recorded {
        plane
            .roots_shared
            .with_all(|m| *m.entry(()).or_insert(0) += 1);
    }
}

/// `principal`'s roots epoch, as an exchange seals it: its own, beside the shared one.
fn roots_epoch(plane: &McpDoor, principal: &str) -> u64 {
    let own = plane.roots.get(&principal.to_string()).unwrap_or(0);
    let shared = plane.roots_shared.get(&()).unwrap_or(0);
    own.wrapping_add(shared.wrapping_shl(32))
}
/// One unit's state, from its arrival to its end.
struct CallUnit {
    /// The unit's own key, as the kernel minted it.
    key: u64,
    /// What the plane held for the generation it arrived under.
    held: Option<Arc<Held>>,
    /// What the arrival is.
    disposition: Disposition,
    /// The request's `params`.
    params: Option<Value>,
    /// How its answer is framed; `None` = one JSON document.
    framing: Option<Framing>,
    /// The caller's `Mcp-Param-*` head fields, kept from the arrival (the head crosses once).
    param_fields: Vec<(String, String)>,
    /// The ticket its pieces cross on, once one has.
    ticket: Option<Ticket>,
    /// The host services its pieces have issued on the ticket, so every handle is fresh.
    issued: u32,
    /// The kernel's entitlement answers, by `"<scope kind>:<name>"`.
    entitled: BTreeMap<String, bool>,
    /// The member the kernel's walk picked for the current attempt.
    member: Option<String>,
    /// Which attempt of the walk is current (`0` before the first ATTEMPT piece): each attempt's
    /// verify-on-call fetch numbers its handles apart from the last's.
    attempt: u32,
    /// The relayed call, once admitted.
    relay: Option<Relay>,
    /// What it is writing, part way through.
    pending: Option<Pending>,
    /// The approval it is claiming on the host's ledger: the nonce, the handle the claim was
    /// issued under and the `ttl_ms` it was issued with, re-issued as it was when the unit is
    /// called again after the claim pended.
    claim: Option<(String, u32, u64)>,
    /// Verify-on-call's sighting, kept while the kernel's trust book stamps it.
    verified: Option<crate::trust::Sighting>,
    /// The door's own exchange with a stdio member's child, while it pends ([`door_program`]).
    program: Option<(door_program::Purpose, crate::tool_program::ProgramExchange)>,
    /// The attempt whose stdio member the door greeted ([`door_program::ready`]).
    readied: Option<u32>,
    /// What the unit is to the tasks extension ([`door_tasks`]).
    task: Option<door_tasks::TaskUnit>,
    /// What the unit is to the line carrier: its session and what its line was ([`door_line`]).
    line: Option<door_line::LineUnit>,
    /// The retry of a stdio child's relayed ask: its work handle found, bound and settled.
    child_work: ChildWork,
    /// What the unit is to the session revisions ([`door_sessions`]).
    session: Option<door_sessions::SessionUnit>,
    /// An upstream conversation under negotiation, parked across PENDING entries
    /// ([`door_sessions::Negotiating`]).
    negotiating: Option<Box<door_sessions::Negotiating>>,
}

/// The retry of a stdio child's relayed ask, binding the work handle the ask is correlated under
/// the handle numbers its host calls were issued under (a call that pends
/// is re-issued under its first number), the handle found, and whether it is done.
#[derive(Debug, Default)]
struct ChildWork {
    find: Option<u32>,
    resume: Option<u32>,
    settle: Option<u32>,
    handle: u64,
    resumed: bool,
    done: bool,
}

/// A relayed `tools/call`: what was admitted, the round in flight and the far end's answer so far.
struct Relay {
    admitted: AdmittedCall,
    round: u32,
    /// The far end's status, from its answer's first piece.
    status: u32,
    /// The far end's answer is an event stream.
    sse: bool,
    /// The far end's answer, gathered until its last piece.
    far: Vec<u8>,
    /// The progress the stdio member's answer carried ahead of it.
    frames: Vec<Value>,
    /// A call relayed to a stdio member: its answer read by id among its child's messages.
    program: Option<door_program::ProgramRelay>,
    /// A stdio child's relayed ask, held while the work handle it is correlated under is opened:
    /// its `input_required` result, the round and the child's leg.
    asked: Option<(Value, u32, crate::ask::ChildLeg)>,
    /// The handle number that opening was issued under.
    work_slot: Option<u32>,
    /// When the round's request was handed to the kernel's walk, on the kernel's monotonic clock
    /// (ms): what tells a walk that spent the server's `timeout:` on a dispatched call from one
    /// that dispatched nothing ([`timed_out`]).
    dispatched_ms: Option<u64>,
    /// A stdio call waiting its turn on its member's child ([`door_program::in_line`]): its
    /// request, and the instant its deadline passes (the kernel's monotonic clock, ms; `0` = none).
    queued: Option<(crate::call::OutboundCall, u64)>,
}

/// An answer part way through being written: its head (written with its first bytes), its bytes
/// and how many went, and where it goes.
#[derive(Default)]
struct Pending {
    /// The status the caller's answer starts with; `0` for a request bound for the far end.
    status: u32,
    /// The head fields, written with the first call.
    fields: Vec<(String, String)>,
    /// For the far end: the verb and the target.
    request: Option<(&'static str, String)>,
    bytes: Vec<u8>,
    sent: usize,
    /// The head is written.
    headed: bool,
    /// The unit's reply ends with these bytes.
    done: bool,
    /// The record writes that ride with its first call: `(kind, key, value)`.
    records: Vec<(u32, Vec<u8>, Vec<u8>)>,
    /// The unit's admin audit rows, written with its first call as `RECORD_AUDIT` writes (the
    /// kernel folds them into its own audit chain under the principal it verified).
    audits: Vec<crate::call::AuditRow>,
    /// The unit's ledger lane, named with its first call: the registered SERVER the call resolved
    /// to, as `mcp_server:<server>` ([`server_lane`]), the key the rate card prices and the usage
    /// rows read; `None` = the route entry the walk picked.
    lane: Option<String>,
    /// The counts its first call reports (the unit's cumulative usage, read off the far end).
    units: Vec<UnitCount>,
}

/// The ledger lane of a call to `server`: the plane bills each
/// call under its registered server, `mcp_server:<server>` (the door's first scope kind and the
/// registration's name), as the a2a plane bills an agent under `agent:<id>` and as the kernel holds
/// a present `tools.rate_card` to every registration at boot. A per-tool key names no lane.
pub(crate) fn server_lane(server: &str) -> String {
    format!("{}:{server}", door::SCOPE)
}

/// The kernel's one clock (`clock.now`) on a fresh handle of the unit's ticket; `None` when the
/// host serves none or the read fails (a failed read is never a time).
fn clock(
    services: Option<StaticServices>,
    ticket: Ticket,
    issued: &mut u32,
) -> Option<busbar_contract::abi::host::service::ClockReading> {
    services?
        .clock_now(door_tasks::handle(ticket, issued, &mut None))
        .ok()
}

/// The call log's `ts`: the kernel's wall clock in whole Unix seconds. `None` = no call record is
/// written (a record never carries a time the plane made up).
fn clock_s(services: Option<StaticServices>, ticket: Ticket, unit: &mut CallUnit) -> Option<u64> {
    clock(services, ticket, &mut unit.issued).map(|r| r.wall_ns / 1_000_000_000)
}

/// The kernel's wall clock in Unix milliseconds; `None` with no clock or a failed read, which is
/// never a time: its caller refuses, stamps nothing or keeps its last time.
fn wall_ms(services: Option<StaticServices>, ticket: Ticket, issued: &mut u32) -> Option<u64> {
    clock(services, ticket, issued).map(|r| r.wall_ns / 1_000_000)
}

/// The kernel's monotonic clock, whole milliseconds.
fn mono_ms(services: Option<StaticServices>, ticket: Ticket, unit: &mut CallUnit) -> Option<u64> {
    clock(services, ticket, &mut unit.issued).map(|r| r.mono_ns / 1_000_000)
}

/// Whether the walk spent the server's `timeout:` on a dispatched call: the unit handed its relayed request to the walk, and at least the server's
/// own attempt bound has passed since — the member was dialled and did not answer within it. A walk
/// that refused at its first pick dispatched nothing (no request was handed over), and a dial that
/// failed fails at once, well inside the bound: both keep the not-dispatched words.
fn timed_out(services: Option<StaticServices>, ticket: Ticket, unit: &mut CallUnit) -> bool {
    let Some((sent, server)) = unit
        .relay
        .as_ref()
        .and_then(|r| Some((r.dispatched_ms?, r.admitted.entry.server.clone())))
    else {
        return false;
    };
    let Some(bound) = unit
        .held
        .as_ref()
        .and_then(|h| h.section.servers.get(&server))
        .map(crate::tools_config::McpServerDefCfg::timeout_ms)
    else {
        return false;
    };
    mono_ms(services, ticket, unit).is_some_and(|now| now.saturating_sub(sent) >= bound)
}

impl Pending {
    /// With the call log's record of `line`, under `scope` and `generation`, at `ts` (the host
    /// clock's reading; none, no record).
    fn logged(
        mut self,
        line: Option<&crate::call::CallLine>,
        scope: &str,
        generation: u64,
        ts: Option<u64>,
    ) -> Self {
        // THE CALL LOG RECORD, keyed by the caller's chain scope ([`crate::record::call_suffix`]).
        let Some(line) = line else {
            return self;
        };
        if let Some(ts) = ts {
            self.records.push((
                door::RECORD_CALL,
                scope.as_bytes().to_vec(),
                crate::record::call_suffix(
                    ts,
                    &line.server,
                    &line.tool,
                    line.outcome,
                    &line.reason,
                    &line.tool_digest,
                    generation,
                ),
            ));
        }
        self.audits.extend(line.audit.clone());
        if !line.server.is_empty() {
            self.lane = Some(server_lane(&line.server));
        }
        self
    }

    /// Answered with NO FEE UNIT: the answer of a call that was never sent, which delivered nothing
    /// and so earns none ([`never_sent_answer`]). A unit that reports no fee unit has its
    /// admission's fee given back (the kernel's `FeeRefund::PlaneFeeUnits`).
    fn unbilled(mut self) -> Self {
        self.units.retain(|u| u.class != door::CLASS_FEE_INDEX);
        self
    }

    /// With the admin audit row `row`.
    pub(super) fn audited(mut self, row: crate::call::AuditRow) -> Self {
        self.audits.push(row);
        self
    }

    /// Laned by the registered server `server` ([`server_lane`]).
    fn laned(mut self, server: &str) -> Self {
        self.lane = Some(server_lane(server));
        self
    }

    /// The caller's answer `(status, body)` in `framing`, with `progress` ahead of it, done.
    fn answer(status: u32, body: Vec<u8>, framing: Option<&Framing>, progress: &[Value]) -> Self {
        let (bytes, streamed) = match framing {
            Some(f) => f.frame(status, body, progress),
            None => (body, false),
        };
        let fields = if streamed {
            vec![
                (CONTENT_TYPE.to_string(), EVENT_STREAM.to_string()),
                (CACHE_CONTROL.to_string(), NO_STORE.to_string()),
            ]
        } else if bytes.is_empty() {
            Vec::new()
        } else {
            // A whole answer states its length (an event stream is relayed piece by piece and
            // states none).
            vec![
                (CONTENT_TYPE.to_string(), JSON.to_string()),
                (CONTENT_LENGTH.to_string(), bytes.len().to_string()),
            ]
        };
        // The fee unit: earned by an answer the caller is served with a success (the per-request
        // fee of an end whose caller status was not a success is refunded).
        let units = if (200..=299).contains(&status) {
            vec![UnitCount {
                class: door::CLASS_FEE_INDEX,
                source: UNITS_REPORTED,
                amount: 1,
            }]
        } else {
            Vec::new()
        };
        Pending {
            status,
            fields,
            bytes,
            done: true,
            units,
            ..Pending::default()
        }
    }

    /// Reporting the one tool call a server answered, and the `answered` bytes of the document it
    /// answered with: the call is counted once the upstream has answered the round, never for a
    /// refused, unreachable or failed leg (both classes are response classes, `tool_meta.rs`: a call
    /// that never reached a server is not a call this node made, and the byte class is "the length
    /// of the document it just read back"). The plane states its counts; the kernel prices them
    /// (the plane reports; the kernel writes).
    /// Classes by [`door::TAIL`] index: `0` tool calls, `1` bytes.
    fn counted(mut self, answered: usize) -> Self {
        self.units.push(UnitCount {
            class: 0,
            source: UNITS_REPORTED,
            amount: 1,
        });
        self.units.push(UnitCount {
            class: 1,
            source: UNITS_REPORTED,
            amount: u64::try_from(answered).unwrap_or(u64::MAX),
        });
        self
    }

    /// The request bound for the far end.
    fn far(outbound: crate::call::OutboundCall) -> Self {
        Pending {
            fields: outbound.fields,
            request: Some((outbound.verb, outbound.target)),
            bytes: outbound.body,
            ..Pending::default()
        }
    }
}

/// The operation class a disposition is counted under: its row's, or the notification class. A
/// refused arrival is counted under none.
fn op_class(disposition: &Disposition) -> Option<u32> {
    match disposition {
        Disposition::Request { row, .. } => door::op_class_index(row.op),
        Disposition::Notice { .. } => door::op_class_index(crate::tool_ops::OP_NOTIFICATION),
        Disposition::Refused(_) => None,
    }
}

/// A refusal as the text a refused arrival carries: the plane's own words, read back by
/// [`RefusalSlot`].
fn refusal_text(refusal: &crate::tool_arrival::Refusal) -> String {
    serde_json::json!({
        "status": refusal.status,
        "id": refusal.id,
        "code": refusal.code,
        "message": refusal.message,
        "data": refusal.data,
    })
    .to_string()
}

/// [`ArriveOut::refusal`]: the arrival names the discovery document, which is not answered on the
/// request path.
pub const UNSERVED: u32 = 2;

/// REFUSED in the plane's own `text`, at `status` ([`ArriveOut::refusal`] `1`): `refusal` renders
/// them.
fn refused_arrival(out: &mut Out<'_, ArriveOut>, status: u32, text: String) -> Outcome {
    out.set(|o| &o.refusal, 1);
    out.set(|o| &o.refusal_status, status);
    out.fail(Refusal::refused(text))
}

/// The words of an arrival on a verb the endpoint does not serve.
const NOT_ALLOWED_TEXT: &str = r#"{"allow":"POST"}"#;

/// The words of an arrival from a browser origin the deployment does not admit.
const FORBIDDEN_ORIGIN_TEXT: &str = r#"{"origin":"forbidden"}"#;

/// Why a unit that needs a time is refused when the host's clock read fails: a failed read is never
/// a time, so nothing is stamped, armed or judged at the epoch.
const CLOCK_UNREAD: &str = "the host's clock could not be read, and busbar never stamps, arms or \
                            judges anything at a time it made up";

/// The value of head field `name` (ASCII case-insensitive), where it is UTF-8.
fn head<'a>(
    fields: LentList<'a, busbar_contract::abi::mechanism::call::Field>,
    name: &str,
) -> Option<&'a str> {
    fields
        .iter()
        .find(|f| {
            f.field(|f| &f.name)
                .as_str()
                .is_ok_and(|n| n.eq_ignore_ascii_case(name))
        })
        .and_then(|f| f.field(|f| &f.value).as_str().ok())
}

/// The head-field name prefix of SEP-2243's custom parameter headers.
const PARAM_FIELD_PREFIX: &str = "mcp-param-";

slot!(
    /// `arrive`: the arrival decided and kept with its generation and its framing; a refused one
    /// refused in its own words.
    Arrive, ArriveIn, ArriveOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let claim = door::ROUTES.get(input.claim() as usize);
        let body = input.body().bytes();
        let fields = input.fields();
        if claim.is_some_and(|r| r.open) {
            // The discovery document is not answered on the request path.
            out.set(|o| &o.refusal, UNSERVED);
            out.set(|o| &o.refusal_status, crate::tool_arrival::STATUS_NOT_FOUND);
            return out.fail(Refusal::bare());
        }
        // The origin first (who may speak at all, one field read): a
        // browser origin that is neither loopback nor on the operator's allowlist is refused, the
        // DNS-rebinding defence. A request with no `Origin` is not a browser's, and goes on.
        let origin = head(fields, "origin");
        if origin.is_some_and(|o| !busbar_contract::jsonrpc::origin_admitted(o, &plane.origins)) {
            return refused_arrival(
                &mut out,
                door::STATUS_FORBIDDEN_ORIGIN,
                FORBIDDEN_ORIGIN_TEXT.to_string(),
            );
        }
        // The endpoint's three verbs: the stateless revision's
        // POST is the path it always was; `initialize`, a session's messages and streams, DELETE
        // and the `2024-11-05` stream are the session revisions' ([`door_sessions`]); a GET or
        // DELETE naming no session (and no legacy stream) is `405`.
        let endpoint = claim.is_some_and(|r| {
            r.target == crate::tool_claims::DEFAULT_MOUNT
                && r.carrier == crate::tool_claims::CARRIER_HTTP
        });
        let head_field = |name: &str| head(fields, name).map(str::to_string);
        let arrived = if endpoint {
            let held = plane.current();
            door_sessions::arrive(
                held.as_deref(),
                claim.map_or("POST", |r| r.verb),
                input.target().as_str().unwrap_or_default(),
                body,
                &head_field,
            )
        } else if claim.is_some_and(|r| r.verb != "POST") {
            door_sessions::SessionArrived::NotAllowed
        } else {
            door_sessions::SessionArrived::Stateless
        };
        let (mut session_unit, session_body, session_mirror) = match arrived {
            door_sessions::SessionArrived::NotAllowed => {
                return refused_arrival(
                    &mut out,
                    door::STATUS_METHOD_NOT_ALLOWED,
                    NOT_ALLOWED_TEXT.to_string(),
                )
            }
            door_sessions::SessionArrived::Stateless => (None, None, Vec::new()),
            door_sessions::SessionArrived::Session(a) => {
                let a = *a;
                (Some(a.unit), a.dispatch, a.mirror)
            }
        };
        // A session unit the session answers itself: nothing for the one dispatch to decide.
        let session_local = session_unit.is_some() && session_body.is_none();
        // A task's continuation: the task it runs, and the
        // call it carries, decided below as the `tools/call` it is.
        let task_run = (input.claim() as usize == door::TASK_RUN_ROUTE)
            .then(|| door_tasks::run_arrival(body));
        if let Some(None) = task_run {
            let refusal = door_tasks::unknown_arrival();
            return refused_arrival(&mut out, refusal.status, refusal_text(&refusal));
        }
        let task_run = task_run.flatten();
        // A task's continuation carries its call in its body: it is decided under the fields that
        // call implies.
        let task_body = task_run.as_ref().map(|(_, _, call, _)| call.clone());
        // ADMISSION BOUNDS LIVE WORK; NOTHING EVICTS IT: a full table refuses the new arrival, before
        // anything else is stated of it, and every unit it holds goes on. Arrivals racing the last
        // free places overshoot by no more than the instance's in-flight bound. It is judged before
        // a line of the line carrier is read: reading one moves its carrier session (a live ask's
        // answer is taken, a revision kept, a cancel applied), and a line the cap refuses has moved
        // nothing.
        let at_cap = plane
            .units
            .with_all(|held| held.len() >= MAX_UNITS && !held.contains_key(&input.unit()));
        if at_cap {
            let refusal = crate::tool_arrival::Refusal {
                status: 429,
                id: None,
                code: crate::codec::CODE_REFUSED,
                message: format!(
                    "this server holds {MAX_UNITS} requests in flight, the most it will; retry \
                     when some have finished"
                ),
                data: Some(serde_json::json!({ "reason": "capacity" })),
            };
            return refused_arrival(&mut out, refusal.status, refusal_text(&refusal));
        }
        // A line of the line carrier: what it is to the carrier session it arrived
        // over, and the bytes the one dispatch decides on (none: the unit answers its preset).
        let line_route = input.claim() as usize == door::LINE_ROUTE;
        // A SHORT ANSWER APPLIES NOTHING, and the re-call reads what was stored: reading a line
        // moves its carrier session (a live ask's answer is taken, a revision kept, a cancel
        // applied), so the one buffer a line's arrival can come up short on (the units buffer its
        // admission estimate rides) is judged before the line is read.
        if line_route && input.units_cap() < 1 {
            out.set(|o| &o.units_written, 0);
            out.set(|o| &o.units_needed, 1);
            return Outcome::Failed;
        }
        let line_arrival = line_route.then(|| {
            let session = head(fields, busbar_contract::abi::host::service::CARRIER_SESSION_FIELD)
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0);
            door_line::arrive(plane, session, body)
        });
        if line_arrival.as_ref().is_some_and(|a| a.unit.session == 0) {
            // The host states a carrier session on every line it opens a unit for.
            let text = r#"{"status":400,"id":null,"code":-32600,"message":"a line of the line carrier names no carrier session"}"#;
            return refused_arrival(&mut out, 400, text.to_string());
        }
        let line_dispatch = line_arrival.as_ref().map(|a| a.dispatch.clone());
        let line_silent = matches!(line_dispatch, Some(None));
        let line_body = line_dispatch.flatten();
        let line_unit = line_arrival.map(|a| a.unit);
        // A line raised from its carrier session's negotiated revision is lowered back.
        if line_unit.as_ref().is_some_and(|u| u.raised) {
            session_unit = Some(door_sessions::SessionUnit::Line);
        }
        let own_body = line_body.as_deref().or(task_body.as_deref());
        let body: &[u8] = own_body.or(session_body.as_deref()).unwrap_or(body);
        // THE BODY IS PARSED ONCE: decided, framed, routed and kept from this one document.
        let value = serde_json::from_slice::<Value>(body).ok();
        // A line's or a continuation's own body implies the fields it is decided under.
        let mirrored = match (own_body, value.as_ref()) {
            (Some(_), Some(v)) => crate::codec::mirrored(v),
            _ => Vec::new(),
        };
        // A raised session message is decided under the fields its raised body implies, ahead of
        // the caller's own (which name its session revision).
        let field = |name: &str| {
            session_mirror
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
                .or_else(|| head(fields, name))
                .or_else(|| {
                    mirrored
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.as_str())
                })
        };
        let mut disposition = if line_silent {
            // A line the carrier answers itself: nothing for the one dispatch to decide.
            Disposition::Notice {
                method: String::new(),
            }
        } else if let Some(unit) = session_unit.as_ref().filter(|_| session_local) {
            door_sessions::disposition(unit)
        } else {
            match crate::tool_arrival::decide(value.as_ref(), field) {
                // A notification is never answered on the line, refused or not.
                Disposition::Refused(_)
                    if line_route && value.as_ref().is_some_and(door_line::is_notification) =>
                {
                    Disposition::Notice {
                        method: String::new(),
                    }
                }
                decided => decided,
            }
        };
        // A session message the one dispatch refused is answered once its session is the caller's
        // (a mismatch answers `404` on every path), never at its arrival.
        let refused = match &disposition {
            Disposition::Refused(r) => Some(r.clone()),
            _ => None,
        };
        if let (Some(refusal), Some(unit)) = (refused, session_unit.as_mut()) {
            if door_sessions::refused_in_session(unit, &refusal) {
                disposition = door_sessions::disposition(unit);
            }
        }
        if let Disposition::Refused(refusal) = &disposition {
            return refused_arrival(&mut out, refusal.status, refusal_text(refusal));
        }
        let Some(op_class) = op_class(&disposition) else {
            return Outcome::Failed;
        };
        out.set(|o| &o.op_class, op_class);
        out.set(|o| &o.principal_need, PRINCIPAL_REQUIRED);
        out.set(|o| &o.dialect, 0);
        // A line's answer is one line, and a session's is one document: never an event stream.
        let framing = match (&disposition, value.as_ref()) {
            (Disposition::Request { row, .. }, Some(v)) if !line_route && session_unit.is_none() => {
                Framing::of(field("accept"), row.method, v)
            }
            _ => None,
        };
        let mut param_fields: Vec<(String, String)> = fields
            .iter()
            .filter_map(|f| {
                let name = f.name().as_str().ok()?.to_ascii_lowercase();
                let value = f.value().as_str().ok()?;
                name.starts_with(PARAM_FIELD_PREFIX).then(|| (name, value.to_string()))
            })
            .collect();
        // A raised `tools/call` carries the parameter mirror its session revision could not.
        for (name, value) in &session_mirror {
            if name.starts_with(PARAM_FIELD_PREFIX) {
                param_fields.retain(|(n, _)| n != name);
                param_fields.push((name.clone(), value.clone()));
            }
        }
        // The route: a relayed call names the one registered server its
        // published tool is served by, a DIRECT entry of the `tools:` section; the kernel resolves
        // (plane key, entry) and never parses the name.
        let held = plane.current();
        let called = match (&disposition, held.as_deref(), value.as_ref()) {
            (Disposition::Request { row, .. }, Some(held), Some(v))
                if row.op == crate::tool_ops::OP_TOOL_CALL =>
            {
                v.pointer("/params/name")
                    .and_then(Value::as_str)
                    .and_then(|name| held.catalogue.tool(name).map(|entry| (held, entry)))
            }
            _ => None,
        };
        // Every other arrival (a listing, a read, a notice, a call naming no published tool) is the
        // plane's own to answer: it names no entry and is admitted with no walk (Q-L3B-LOCAL).
        // A server that is a member of a pool routes over the pool: the kernel's one walk fails it over, under the breaker; a tool the
        // pool does not name `repeatable:` is performed at most once.
        match called {
            Some((held, entry)) => match held.pool_of(&entry.server) {
                Some((pool, members)) => {
                    out.route(ROUTE_POOL, pool);
                    if !members.repeatable.contains(&entry.tool) {
                        out.once();
                    }
                }
                None => out.route(ROUTE_DIRECT, &entry.server),
            },
            None => out.local(),
        }
        // The subscription on the HTTP carrier: a session,
        // the long-lived response its caller leg ([`door_listen`]).
        // On the line carrier the subscription is kept on the carrier session instead
        // ([`door_line::listen`]).
        if !line_route
            && matches!(&disposition, Disposition::Request { row, .. }
                if row.op == crate::tool_ops::OP_SUBSCRIPTIONS_LISTEN)
        {
            out.session();
        }
        // THE ADMISSION ESTIMATE of busbar's own ask: a prompt whose operator asks its caller first
        // costs the round it asks, on the caller's budget (a
        // retry carrying the answers asks nothing, and is charged nothing).
        if let (Disposition::Request { row, .. }, Some(held), Some(v)) =
            (&disposition, held.as_ref(), value.as_ref())
        {
            if door_listen::asks_a_round(row.op, held, v) {
                let mut units = input.units_buf();
                units.push(UnitCount {
                    class: door::CLASS_FEE_INDEX,
                    source: busbar_contract::abi::plane::UNITS_ESTIMATED,
                    amount: 1,
                });
                let short = !units.fits();
                let (uw, und) = units.settle(short);
                out.set(|o| &o.units_written, uw as u32);
                out.set(|o| &o.units_needed, und as u32);
                if short {
                    return Outcome::Failed;
                }
            }
        }
        let unit = CallUnit {
            key: input.unit(),
            held,
            disposition,
            params: value.and_then(|mut v| v.get_mut("params").map(Value::take)),
            framing,
            param_fields,
            ticket: None,
            issued: 0,
            entitled: BTreeMap::new(),
            member: None,
            attempt: 0,
            relay: None,
            pending: None,
            claim: None,
            verified: None,
            program: None,
            readied: None,
            task: task_run.map(|(reference, params, _, retry)| {
                door_tasks::TaskUnit::run(reference, params, retry)
            }),
            line: line_unit,
            child_work: ChildWork::default(),
            session: session_unit,
            negotiating: None,
        };
        plane.units.insert(input.unit(), unit);
        Outcome::Ready
    }
);

/// THE KERNEL'S ENTITLEMENT ANSWERS for `unit`'s principal, one per grant in `grants` not yet
/// asked: `entitlement.check` of `"<kind>:<name>"`. Every handle the unit issues on its ticket is
/// fresh. No host services, a refused or failed call: not entitled.
fn ask_entitlements(
    services: Option<StaticServices>,
    ticket: Ticket,
    unit: &mut CallUnit,
    grants: &[(&'static str, &str)],
) {
    for (kind, name) in grants {
        let target = format!("{kind}:{name}");
        if unit.entitled.contains_key(&target) {
            continue;
        }
        let answer = services.is_some_and(|s| {
            s.entitled(
                door_tasks::handle(ticket, &mut unit.issued, &mut None),
                &target,
            )
            .unwrap_or(false)
        });
        unit.entitled.insert(target, answer);
    }
}

/// The kernel's destination judge on a host a call's arguments name (`dest.judge`, called where
/// the argument guard runs): the deployment's egress rules
/// under its default class, private reach refused outright for a registration that was granted
/// none (`allow_private`, as `DEST_REFUSE_PRIVATE`). The name alone is judged, never resolved, so
/// it never pends (the B.2 row: "may pend: no"); a host that serves no judge, pends or fails
/// gives no verdict, and the argument guard refuses (fail closed).
fn dest_verdict(
    services: StaticServices,
    handle: CompletionHandle,
    held: &Held,
    entry: &crate::catalogue::ToolEntry,
    dest: &str,
) -> Option<u64> {
    let reach = held
        .section
        .servers
        .get(&entry.server)
        .is_some_and(|d| d.allow_private);
    let flags = if reach {
        0
    } else {
        busbar_contract::abi::host::service::DEST_REFUSE_PRIVATE
    };
    let class = busbar_contract::abi::host::conn::connector::EGRESS_DEFAULT;
    match services.dest_judge_as(handle, dest, class, flags, None) {
        std::task::Poll::Ready(Ok(judged)) => Some(judged.verdict),
        _ => None,
    }
}

/// Whether the kernel's entitlement answers hold `"<kind>:<name>"` (never asked = no), as a
/// catalogue lookup asks it.
fn admit(entitled: &BTreeMap<String, bool>) -> impl Fn(&str, &str) -> bool + '_ {
    |kind, name| {
        entitled
            .get(&format!("{kind}:{name}"))
            .copied()
            .unwrap_or(false)
    }
}

/// The principal a caller reference names: the ungoverned chain's when it is empty.
fn principal_of(caller: &str) -> &str {
    if caller.is_empty() {
        crate::ask::UNGOVERNED
    } else {
        caller
    }
}

/// What one piece came to.
enum Step {
    /// Nothing to write: the piece was taken.
    Taken,
    /// The plane declines the piece.
    Declined,
    /// Write what is pending.
    Write,
    /// A host service pended (the approval's claim): called again on its wake.
    Pending,
    /// Held open (a stdio call waiting for its turn behind the call ahead of it): called again on a
    /// wake, or at this instant of the host's monotonic clock (`0` = on a wake only).
    Wait(u64),
    /// The walk's member is one this unit may not be sent to: declined, the walk moves on.
    Decline,
}

/// THE DOOR'S SEAL ([`crate::ask::Seal`]) over the host's services for one unit: the state signed
/// by the host's `sign` under the door's signing domain ([`crate::seal`]), a nonce from its
/// `random.fill`, and a completed exchange's approval spent once, first against the instance's own
/// ledger and then by the host's one-time `records.claim` of [`crate::tool_records::KIND_APPROVAL`]. A claim that
/// pends leaves [`Self::pending`] set; the unit answers PENDING and decides again on the wake, the
/// claim re-issued under the handle it was first issued under.
#[doc(hidden)]
pub struct DoorSeal<'a> {
    pub services: StaticServices,
    pub ticket: Ticket,
    pub issued: &'a mut u32,
    pub claim: &'a mut Option<(String, u32, u64)>,
    pub spent: &'a Keyed<String, u64>,
    pub pending: bool,
}

impl DoorSeal<'_> {
    /// A fresh handle on the unit's ticket.
    fn handle(&mut self) -> CompletionHandle {
        door_tasks::handle(self.ticket, self.issued, &mut None)
    }

    /// The host's signature of `data` under the door's signing domain; `None` when it signs none.
    fn sign(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let handle = self.handle();
        let (mut buf, mut spans) = (
            [0u8; 256],
            [busbar_contract::abi::host::service::ItemSpan {
                key: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 },
                value: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 },
            }; 1],
        );
        self.services
            .sign(handle, data, &mut buf, &mut spans)
            .ok()
            .map(|s| s.signature.to_vec())
    }

    /// The kernel's wall clock, in Unix seconds; `None` when the host's clock cannot be read. A
    /// sealed state's window is judged against this, so a failed read is never a time (the state
    /// would be judged at the epoch and every lapsed one would stand): the caller refuses.
    fn now(&mut self) -> Option<u64> {
        clock(Some(self.services), self.ticket, self.issued).map(|r| r.wall_ns / 1_000_000_000)
    }
}

/// THE HOST A SEALED STATE IS MINTED AND JUDGED AGAINST: its signature and its wall clock, beside
/// the [`crate::ask::Seal`] that mints, opens, draws nonces and spends approvals. The door's is
/// [`DoorSeal`], over the host's services; the ask decision and the relayed state's seal take any,
/// so their logic is tested in the crate over a host that is a plain Rust value (a clock that fails
/// is a `None` there, as it is here).
pub trait SealHost: crate::ask::Seal {
    /// The host's signature of `data`; `None` when it signs none.
    fn sign(&mut self, data: &[u8]) -> Option<Vec<u8>>;
    /// The kernel's wall clock, in Unix seconds; `None` when it cannot be read.
    fn now(&mut self) -> Option<u64>;
}

impl SealHost for DoorSeal<'_> {
    fn sign(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        DoorSeal::sign(self, data)
    }

    fn now(&mut self) -> Option<u64> {
        DoorSeal::now(self)
    }
}

impl crate::ask::Seal for DoorSeal<'_> {
    fn mint(&mut self, state: &crate::ask::AskState) -> Option<String> {
        crate::seal::seal_state(state, &mut |data| self.sign(data))
    }

    fn open(&mut self, blob: &str) -> Result<crate::ask::AskState, crate::ask::Rejected> {
        crate::seal::unseal_state(blob, &mut |data| self.sign(data))
    }

    fn nonce(&mut self) -> Option<String> {
        let handle = self.handle();
        let mut bytes = [0u8; 16];
        self.services.random_fill(handle, &mut bytes).ok()?;
        Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    fn redeem(&mut self, nonce: &str, expires_at: u64, now: u64) -> bool {
        // THE LOCAL HALF, test-and-set: a nonce this instance already took is refused here. Taken
        // on the first call only: a re-call after the claim pended re-issues the claim, AS IT WAS
        // FIRST ISSUED. Its window is fixed then too: `now` is read afresh on the re-call, and a
        // claim re-issued on its handle with another `ttl_ms` is another request on a used handle,
        // which the host refuses by quarantining the instance (the replay rule).
        let (seq, ttl_ms) = match self.claim.as_ref() {
            Some((claimed, seq, ttl_ms)) if claimed == nonce => (*seq, *ttl_ms),
            _ => {
                let fresh = self.spent.with_all(|seen| {
                    seen.retain(|_, expiry| *expiry >= now);
                    seen.insert(nonce.to_string(), expires_at).is_none()
                });
                if !fresh {
                    return false;
                }
                let seq = self.handle().seq;
                let ttl_ms = expires_at.saturating_sub(now).max(1).saturating_mul(1000);
                *self.claim = Some((nonce.to_string(), seq, ttl_ms));
                (seq, ttl_ms)
            }
        };
        let handle = handle_at(self.ticket, seq);
        match self.services.records_claim(
            handle,
            crate::tool_records::KIND_APPROVAL,
            nonce.as_bytes(),
            ttl_ms,
        ) {
            std::task::Poll::Pending => {
                self.pending = true;
                false
            }
            // THE HOST'S LEDGER answered: its word is final.
            std::task::Poll::Ready(Ok(won)) => won,
            // No store bound (or no claim served): the local half was the whole gate.
            std::task::Poll::Ready(Err(
                ServiceError::Declined(Outcome::Refused) | ServiceError::Unserved,
            )) => true,
            // A ledger that cannot say whether the approval was spent is not read as "it was not".
            std::task::Poll::Ready(Err(_)) => false,
        }
    }
}

/// The answer to the caller's body: from what the plane holds, or the relayed call admitted.
/// What verify-on-call came to.
enum Looked {
    /// The sighting the gate reads is fresh: judge the call.
    Fresh,
    /// A host service pended (the fetch, or the stamp): called again on its wake.
    Pending,
}

/// VERIFY-ON-CALL (the rug-pull defence, before the call): the called server's live tool list is
/// fetched over the door's own need when its last fetch is older than its `verify_ttl` (default
/// [`crate::tools_config::DEFAULT_MCP_VERIFY_TTL`]; `0` = every call; never fetched = now), digested,
/// stamped on the kernel's trust book and kept, so the trust gate judges the call against what the
/// server serves NOW. A fetch that fails is the `error` state, which serves nothing (fail closed).
/// A registration with no `url:` has nothing to fetch, and a host that lends the door no connector
/// relays nothing either. The fetch carries the member's binding, as its relayed calls do: a `passthrough` registration's is lent the unit's caller
/// credential, a `token_exchange:` registration's exchanges for its approved set
/// ([`crate::tool_scope::registration_scope`]).
fn verify_on_call(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    held: &Held,
    (server, caller): (&str, &str),
) -> Looked {
    use crate::trust::Sighting;
    let Some(def) = held.section.servers.get(server) else {
        return Looked::Fresh;
    };
    // A `transport: stdio` member is fetched from its own child ([`door_program::tools_listed`]).
    let program = door_program::is_program(def);
    if (def.url.is_empty() && !program) || !plane.host.is_some_and(|h| h.lends_connector()) {
        return Looked::Fresh;
    }
    let Some(services) = plane.services else {
        return Looked::Fresh;
    };
    // A failed read is never a time: the cached list is then stale and
    // fetched again, and what that fetch landed is not stamped.
    let now_ms = wall_ms(Some(services), ticket, &mut unit.issued);
    let sighting = match unit.verified.take() {
        Some(kept) => kept,
        None => {
            let ttl_ms = busbar_contract::duration::parse_duration_secs(
                def.verify_ttl
                    .as_deref()
                    .unwrap_or(crate::tools_config::DEFAULT_MCP_VERIFY_TTL),
            )
            .unwrap_or(0)
            .saturating_mul(1000);
            let fresh = now_ms.is_some_and(|now_ms| {
                plane
                    .checked
                    .get(&server.to_string())
                    // A clock that reads earlier than the fetch went backwards: stale, never fresh.
                    .is_some_and(|at| ttl_ms > 0 && now_ms >= at && now_ms - at < ttl_ms)
            });
            if fresh {
                return Looked::Fresh;
            }
            let base = VERIFY_SEQ.saturating_add(unit.attempt.saturating_mul(ROUND_SEQ_SPAN));
            if program {
                let std::task::Poll::Ready(answer) =
                    door_program::tools_listed(plane, ticket, unit, def, server, base)
                else {
                    return Looked::Pending;
                };
                match answer {
                    Ok((response, id)) => sighting_of(Ok(response), id),
                    Err(reason) => sighting_of(Err(reason), 0),
                }
            } else {
                // The verify fetch carries the member's down-scope (token_exchange) or the caller's
                // lent credential (passthrough) through the connector binding (Q-L3B-DOOR-EXCHANGE).
                // The fetch is bounded by the server's own `timeout:`:
                // an upstream is not trusted to answer.
                let timeout_ms = def.timeout_ms();
                // The fetch is the stateless `tools/list` first, NEGOTIATED with an upstream that
                // requires a session ([`door_sessions::fetch_in`]), every hop on the connector.
                let request = list_request(held, server, def);
                let answer = door_sessions::fetch_in(
                    instance,
                    plane,
                    &mut unit.negotiating,
                    (base, server, caller, timeout_ms),
                    request,
                );
                let std::task::Poll::Ready(answer) = answer else {
                    return Looked::Pending;
                };
                sighting_of(answer, CONNECT_REQUEST_ID)
            }
        }
    };
    // An unreachable re-fetch is reported as such: the kernel keeps its last
    // verdict, and the call fails as an upstream failure (`trust_of`).
    if record_sighting(
        &services,
        ticket,
        &mut unit.issued,
        &held.catalogue,
        server,
        &sighting,
    ) {
        unit.verified = Some(sighting);
        return Looked::Pending;
    }
    // THE FRESHNESS CLOCK starts only on a list that LANDED, read at a time the clock gave: an
    // unreachable server is fetched again on its next call, and a failed
    // clock read stamps nothing.
    let landed = matches!(sighting, Sighting::Seen(_));
    plane.sightings.insert(server.to_string(), sighting);
    match now_ms {
        Some(now_ms) if landed => {
            plane.checked.insert(server.to_string(), now_ms);
        }
        _ => {
            plane.checked.remove(&server.to_string());
        }
    }
    Looked::Fresh
}

/// THE SIGHTING ON THE KERNEL'S TRUST BOOK (`trust.sight` of the observed catalogue, or
/// `trust.unreachable`, on [`SIGHT_SEQ`]); `true` when it pended. A landed list then sights EACH TOOL
/// The digest it offers each of `server`'s catalogue tools at, under the tool's
/// trust key, on fresh handles from `seq`; never pends, and an unserved book leaves the item
/// unsighted, which `trust.serves` refuses.
fn record_sighting(
    services: &Services,
    ticket: Ticket,
    seq: &mut u32,
    catalogue: &Catalogue,
    server: &str,
    sighting: &crate::trust::Sighting,
) -> bool {
    use crate::trust::Sighting;
    let handle = handle_at(ticket, SIGHT_SEQ);
    let sighted = match sighting {
        Sighting::Seen(obs) => {
            services.trust_sight(handle, server, &crate::trust::catalogue_hash(obs))
        }
        Sighting::Failed(_) => services.trust_unreachable(handle, server),
        Sighting::Never => std::task::Poll::Ready(Ok(0)),
    };
    if sighted.is_pending() {
        return true;
    }
    if let Sighting::Seen(obs) = sighting {
        for entry in catalogue.tools_of(server) {
            if let Some(digest) = obs.capabilities.get(&entry.tool) {
                let handle = door_tasks::handle(ticket, seq, &mut None);
                let _ = services.trust_sight_item(handle, server, &entry.tool, digest);
            }
        }
    }
    false
}

/// The completion handle `seq` on `ticket`.
fn handle_at(ticket: Ticket, seq: u32) -> CompletionHandle {
    CompletionHandle {
        ticket,
        seq,
        _reserved: 0,
    }
}

/// THE KERNEL'S TRUST STATE of registration `server` (`trust.state`), item by item, as the admin
/// views render it. A host that answers no trust service holds nothing.
fn kernel_items(plane: &McpDoor, ticket: Ticket, server: &str) -> Vec<crate::trust::KernelItem> {
    use busbar_contract::abi::sdk::services::ServiceError;
    let Some(services) = plane.services else {
        return Vec::new();
    };
    let handle = handle_at(ticket, SIGHT_SEQ + 2);
    let read = |bytes: usize, spans: usize| {
        let mut buf = vec![0_u8; bytes];
        let mut items = vec![door_tasks::blank(); spans];
        services
            .trust_state(handle, server, &mut buf, &mut items)
            .map(|state| {
                state
                    .items()
                    .map(|i| crate::trust::KernelItem {
                        item: i.item.to_string(),
                        word: i.state.to_string(),
                        approved: i.approved.map(str::to_string),
                    })
                    .collect::<Vec<_>>()
            })
    };
    match read(16 * 1024, 128) {
        Ok(items) => items,
        // The short-buffer rule: once more, at the size the host asked for.
        Err(ServiceError::Short { bytes, items }) => read(
            usize::try_from(bytes).unwrap_or(usize::MAX),
            usize::try_from(items).unwrap_or(usize::MAX),
        )
        .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// The kernel's Approve on one tool, as the route leg asks it: `trust.serves` over the tool's registration (the counterparty) and its trust key
/// (the tool as `tools_allow` names it, the upstream's own spelling), at its last sighting. The door
/// judges nothing: the one fact it renders on its own is that its last re-fetch could not reach
/// the server (the call then fails as an upstream failure). A host that answers no trust service
/// serves nothing (fail closed).
fn trust_of(
    plane: &McpDoor,
    ticket: Ticket,
    issued: &mut u32,
    entry: &crate::catalogue::ToolEntry,
) -> crate::call::Trust {
    use crate::call::Trust;
    if let Some(crate::trust::Sighting::Failed(reason)) = plane.sightings.get(&entry.server) {
        return Trust::Unreached(reason);
    }
    let Some(services) = plane.services else {
        return Trust::Verdict(busbar_contract::abi::host::service::DISTRUST_UNKNOWN);
    };
    let handle = door_tasks::handle(ticket, issued, &mut None);
    match services.trust_serves(handle, &entry.server, Some(&entry.tool), None) {
        Ok(code) => Trust::Verdict(code),
        // A book that does not answer serves nothing (fail closed).
        Err(_) => Trust::Verdict(busbar_contract::abi::host::service::DISTRUST_UNKNOWN),
    }
}

/// A QUEUED STDIO CALL'S TURN, the synchronous call's and a task's continuation's alike: `Ok` the
/// step it takes (sent once it is first in line, else waiting on within its deadline); `Err` its
/// deadline passed while it waited, and it was never sent. `None` for a unit that is not waiting.
fn queued_turn(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit) -> Option<Result<Step, ()>> {
    let deadline = unit.relay.as_ref()?.queued.as_ref()?.1;
    let now = mono_ms(plane.services, ticket, unit);
    let relay = unit.relay.as_mut()?;
    let first = relay
        .program
        .as_ref()
        .is_none_or(|p| door_program::in_line(plane, p, now, ticket));
    if first {
        let (outbound, _) = relay.queued.take()?;
        relay.dispatched_ms = now;
        unit.pending = Some(Pending::far(outbound).laned(&relay.admitted.entry.server));
        return Some(Ok(Step::Write));
    }
    if deadline == 0 || now.is_none_or(|now| now < deadline) {
        return Some(Ok(Step::Wait(deadline.saturating_mul(1_000_000))));
    }
    relay.queued = None;
    relay.program = None;
    Some(Err(()))
}

/// A stdio call waiting its turn, called again on the wake of the call ahead of it
/// leaving its member's line or at its deadline: sent once it is first in line; answered busy,
/// never sent, once its deadline passed while it waited. `None` for a unit that is not waiting.
fn take_turn(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    generation: u64,
    unit: &mut CallUnit,
) -> Option<Step> {
    if let Ok(step) = queued_turn(plane, ticket, unit)? {
        return Some(step);
    }
    let relay = unit.relay.as_ref()?;
    let Settled::Answer { status, body, line } =
        crate::call::never_sent(&relay.admitted, door_program::BUSY)
    else {
        return None;
    };
    let ts = clock_s(plane.services, ticket, unit);
    unit.pending = Some(never_sent_answer(
        status,
        body,
        &line,
        unit.framing.as_ref(),
        (principal, generation, ts),
    ));
    Some(Step::Write)
}

/// THE ANSWER OF A CALL THAT NEVER LEFT: one that never left its queue
/// ([`crate::call::never_sent`]), or one whose server the door's live tool-list check could not
/// reach ([`Admission::Unreached`]). It is `status` and `body` (the upstream-failure tool error), and
/// `line` (the call log's `refused` line, under its fixed reason), logged under `(scope, generation,
/// ts)`, with NO FEE UNIT. A call that was never sent delivered nothing, so it earns no fee and the
/// kernel gives back the one its admission counted (bill what was delivered; a hop
/// refused before the socket is refunded).
fn never_sent_answer(
    status: u32,
    body: Vec<u8>,
    line: &crate::call::CallLine,
    framing: Option<&Framing>,
    (scope, generation, ts): (&str, u64, Option<u64>),
) -> Pending {
    Pending::answer(status, body, framing, &[])
        .logged(Some(line), scope, generation, ts)
        .unbilled()
}

fn answer_body(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
) -> Option<Step> {
    let services = plane.services;
    // An empty caller reference is the ungoverned chain alone: the kernel never lends one to a
    // principal it verified on a governed chain (`door_sessions::owner_of`).
    let principal = principal_of(caller);
    // Every line of a carrier session's caller re-asks the standing and grants its subscriptions on
    // that session are stepped under ([`door_line::reconfirm`]).
    door_line::reconfirm(plane, ticket, principal, unit);
    // A session revision's unit: its session checked against its owner first (a mismatch is `404`
    // on every path); what the session answers itself is answered here.
    if let Some(step) = door_sessions::answer(plane, ticket, caller, unit) {
        return Some(step);
    }
    // A LINE the carrier answers itself (an era verb, an answer busbar asked for), and a line's
    // subscription, kept on its carrier session ([`door_line`]).
    if let Some(pending) = door_line::preset(plane, ticket, unit) {
        unit.pending = Some(pending);
        return Some(Step::Write);
    }
    if let Some(pending) = door_line::listen(plane, ticket, principal, unit) {
        unit.pending = Some(pending);
        return Some(Step::Write);
    }
    // A TASK'S CONTINUATION runs its own phases; a `tasks/*` verb is answered from the task.
    if door_tasks::is_run(unit) {
        return Some(door_tasks::begin(plane, ticket, principal, unit));
    }
    if let Disposition::Request { row, id } = &unit.disposition {
        if [
            crate::tool_ops::OP_TASK_GET,
            crate::tool_ops::OP_TASK_UPDATE,
            crate::tool_ops::OP_TASK_CANCEL,
        ]
        .contains(&row.op)
        {
            let (op, id) = (row.op, id.clone());
            return Some(door_tasks::verb(plane, ticket, principal, unit, op, &id));
        }
    }
    let held = unit.held.clone()?;
    if let Some(step) = take_turn(plane, ticket, principal, held.catalogue.generation(), unit) {
        return Some(step);
    }
    let mut params = unit.params.clone();
    let disposition = unit.disposition.clone();
    // The pool's twin: the kernel's walk picked another
    // member of the called tool's pool. The call is that member's own tool, admitted as its own
    // (its grants, its trust state, its argument guard), and interchangeable only when its approved
    // digest is the primary's; a member with no such twin is declined, and the walk moves on.
    if let (Disposition::Request { row, .. }, Some(member)) = (&disposition, unit.member.clone()) {
        if row.op == crate::tool_ops::OP_TOOL_CALL {
            match twin_of(&held, params.as_ref(), &member) {
                Twin::Same => {}
                Twin::Declined => return Some(Step::Decline),
                Twin::Call(published) => {
                    if let Some(p) = params.as_mut().and_then(Value::as_object_mut) {
                        p.insert("name".to_string(), Value::String(published));
                    }
                }
            }
        }
    }
    if let Disposition::Notice { method } = &disposition {
        if method == crate::ask::NOTIFY_ROOTS_LIST_CHANGED {
            roots_changed(plane, principal);
        }
    }
    let roots_epoch = roots_epoch(plane, principal);
    let generation = held.catalogue.generation();
    let named_tool = match &disposition {
        Disposition::Request { row, id } if row.op == crate::tool_ops::OP_TOOL_CALL => {
            Some(id.clone())
        }
        _ => None,
    };
    // The tool a call names, resolved once.
    let called = named_tool
        .as_ref()
        .and_then(|_| params.as_ref()?.get("name")?.as_str())
        .and_then(|name| held.catalogue.tool(name));
    // The grants this answer can ask: a call asks its own tool's two, any other request every
    // grant the catalogue holds.
    let grants = match (&named_tool, called) {
        (Some(_), Some(t)) => vec![
            (door::SCOPE, t.server.as_str()),
            (door::SCOPE_TOOL, t.namespaced.as_str()),
        ],
        (Some(_), None) => Vec::new(),
        (None, _) => held.catalogue.grants(),
    };
    ask_entitlements(services, ticket, unit, &grants);
    // VERIFY-ON-CALL, for a call the caller is entitled to make: the gate below judges what the
    // server serves now.
    if let Some(t) = called.filter(|t| {
        let admit = admit(&unit.entitled);
        admit(door::SCOPE, &t.server) && admit(door::SCOPE_TOOL, &t.namespaced)
    }) {
        if let Looked::Pending =
            verify_on_call(instance, plane, ticket, unit, &held, (&t.server, caller))
        {
            return Some(Step::Pending);
        }
        // A stdio member's child is greeted (once per generation) before the call.
        if let Some(member) = unit.member.clone() {
            if let Looked::Pending = door_program::ready(plane, ticket, unit, &held, &member) {
                return Some(Step::Pending);
            }
        }
    }
    // The kernel's Approve, asked on the route leg after the re-fetch: the called
    // tool's verdict, and on a listing every granted tool's, each its own `trust.serves`.
    let verdict = called.map(|entry| {
        (
            entry.namespaced.clone(),
            trust_of(plane, ticket, &mut unit.issued, entry),
        )
    });
    use busbar_contract::abi::host::service::{DISTRUST_CHANGED, DISTRUST_QUARANTINED};
    let listing = matches!(&disposition, Disposition::Request { row, .. }
        if row.op == crate::tool_ops::OP_TOOLS_LIST);
    let mut hidden = std::collections::BTreeSet::new();
    if listing {
        let listed: Vec<crate::catalogue::ToolEntry> = held
            .catalogue
            .tools_for(&admit(&unit.entitled))
            .into_iter()
            .cloned()
            .collect();
        for entry in &listed {
            // A verdict hides a tool whose server is quarantined, or one offered at another digest
            // than the one approved (the rug-pull) — judged changed only against a sighting: one its
            // server was never seen to offer is listed. A tool waiting on the operator stays listed,
            // so the caller can see what exists (a call is refused on its own verdict).
            let sighted = matches!(
                plane.sightings.get(&entry.server),
                Some(crate::trust::Sighting::Seen(_))
            );
            let hides = match trust_of(plane, ticket, &mut unit.issued, entry) {
                crate::call::Trust::Verdict(DISTRUST_QUARANTINED) => true,
                crate::call::Trust::Verdict(DISTRUST_CHANGED) => sighted,
                _ => false,
            };
            if hides {
                hidden.insert(entry.namespaced.clone());
            }
        }
    }
    let mut seal = services
        .map(|s| door_tasks::door_seal(plane, s, ticket, (&mut unit.issued, &mut unit.claim)));
    let admit = |kind: &str, name: &str| admit(&unit.entitled)(kind, name);
    if let Some(id) = named_tool {
        let fields = &unit.param_fields;
        let header = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        let mut ask = |entry: &crate::catalogue::ToolEntry, arguments: &Value| {
            decide_ask(
                &held,
                Site {
                    principal,
                    roots_epoch,
                    method: crate::codec::METHOD_TOOLS_CALL,
                    server: &entry.server,
                    capability: &entry.namespaced,
                    rounds: &entry.ask_caller,
                },
                params.as_ref(),
                arguments,
                seal.as_mut(),
            )
        };
        let mut trust = |entry: &crate::catalogue::ToolEntry| match &verdict {
            Some((item, trust)) if *item == entry.namespaced => trust.clone(),
            // The catalogue resolved another entry than the one asked about: nothing serves it.
            _ => crate::call::Trust::Verdict(busbar_contract::abi::host::service::DISTRUST_UNKNOWN),
        };
        let admission = crate::call::admit_trusted(
            &held.catalogue,
            &id,
            params.as_ref(),
            &header,
            &admit,
            &mut trust,
            &mut ask,
        );
        if seal.is_some_and(|s| s.pending) {
            return Some(Step::Pending);
        }
        let admission = crate::call::judge_arguments(admission, &mut |entry, dest| {
            let handle = door_tasks::handle(ticket, &mut unit.issued, &mut None);
            dest_verdict(services?, handle, &held, entry, dest)
        });
        let (status, body, line, never_sent) = match admission {
            Admission::Asked(body, line) => (200, body, Some(line), false),
            // NEVER SENT: the door's live tool-list check could not reach the server, so the call
            // did not leave and earns no fee unit ([`never_sent_answer`]).
            Admission::Unreached(body, line) => (200, body, Some(line), true),
            Admission::Refused(refusal, line) => (refusal.status, refusal.body(), line, false),
            // THE TASK PATH: the call is admitted and answered, so the only question left is whether
            // the answer is a result or a task — the operator's declaration crossed with the
            // caller's (SEP-2663).
            Admission::Go(admitted) if door_tasks::creates(&admitted.entry, params.as_ref()) => {
                return Some(door_tasks::create(
                    plane,
                    ticket,
                    principal,
                    unit,
                    &admitted,
                    params.as_ref(),
                ));
            }
            Admission::Go(admitted) => {
                let Some(member) = unit.member.clone() else {
                    // No member to send it to: the walk's terminal is the kernel's to render.
                    unit.relay = Some(Relay::of(admitted));
                    return Some(Step::Taken);
                };
                // A RELAYED ASK'S RETRY goes back to the member that asked, and no other: the walk
                // is declined on any other member (the state pins it).
                if admitted.relay.as_ref().is_some_and(|r| r.member != member) {
                    return Some(Step::Decline);
                }
                match send_to_member(plane, ticket, caller, unit, &held, &member, admitted)? {
                    MemberSend::Step(step) => return Some(step),
                    MemberSend::Decline => return Some(Step::Decline),
                    MemberSend::Judged(admitted, refusal) => {
                        let Settled::Answer { status, body, line } =
                            crate::call::ask_refused(&admitted, &refusal)
                        else {
                            return None;
                        };
                        (status, body, Some(line), false)
                    }
                    MemberSend::Spent(admitted) => {
                        let refusal = crate::ask::AskRefusal::StateRejected(
                            crate::ask::Rejected::AlreadySpent,
                        );
                        let line = crate::call::retry_refused_line(
                            &admitted.entry,
                            refusal.audit_reason(),
                        );
                        let refusal = refusal.refusal(&admitted.id);
                        (refusal.status, refusal.body(), Some(line), false)
                    }
                }
            }
        };
        let ts = clock_s(services, ticket, unit);
        let pending = Pending::answer(status, body, unit.framing.as_ref(), &[]);
        let pending = pending.logged(line.as_ref(), principal, generation, ts);
        unit.pending = Some(if never_sent {
            pending.unbilled()
        } else {
            pending
        });
        return Some(Step::Write);
    }
    // A tool the kernel's verdict hides is gone from the listing.
    let answer = crate::answer::answer(
        &disposition,
        params.as_ref(),
        &held.catalogue,
        &admit,
        |entry: &crate::catalogue::ToolEntry| hidden.contains(&entry.namespaced),
    );
    // Busbar's ask of its caller for a prompt is audited (asked, or its answer refused).
    let mut audit = None;
    let (status, body) = match answer {
        Answer::Here { status, body } => (status, body),
        Answer::Far => match &disposition {
            Disposition::Request { row, id } if row.op == crate::tool_ops::OP_PROMPT_GET => {
                let prompt =
                    crate::reads::prompt_named(&held.catalogue, id, params.as_ref(), &admit)
                        .ok()?;
                let arguments = params
                    .as_ref()
                    .and_then(|p| p.get("arguments"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));
                let site = Site {
                    principal,
                    roots_epoch,
                    method: "prompts/get",
                    server: &prompt.server,
                    capability: &prompt.namespaced,
                    rounds: &prompt.ask_caller,
                };
                let decided = decide_ask(&held, site, params.as_ref(), &arguments, seal.as_mut());
                if seal.is_some_and(|s| s.pending) {
                    return Some(Step::Pending);
                }
                match decided {
                    AskDecision::Proceed | AskDecision::Answered(_) => {
                        (200, crate::reads::prompts_get(prompt, id, params.as_ref()))
                    }
                    AskDecision::Refuse(refusal) => {
                        audit = Some(crate::call::AuditRow::prompt_ask(&prompt.namespaced, false));
                        let r = refusal.refusal(id);
                        (r.status, r.body())
                    }
                    // A prompt never goes upstream, so no state of a relayed ask is its own: the
                    // state is refused as one this request did not ask for.
                    AskDecision::Relayed(_) => {
                        audit = Some(crate::call::AuditRow::prompt_ask(&prompt.namespaced, false));
                        let r = crate::ask::AskRefusal::StateRejected(
                            crate::ask::Rejected::WrongRequest,
                        )
                        .refusal(id);
                        (r.status, r.body())
                    }
                    AskDecision::Ask {
                        asks,
                        request_state,
                        ..
                    } => {
                        audit = Some(crate::call::AuditRow::prompt_ask(&prompt.namespaced, true));
                        (
                            200,
                            crate::ask::input_required_result(id, &asks, &request_state),
                        )
                    }
                }
            }
            _ => return Some(Step::Declined),
        },
    };
    let mut pending = Pending::answer(status, body, unit.framing.as_ref(), &[]);
    pending.audits.extend(audit);
    unit.pending = Some(pending);
    Some(Step::Write)
}

/// What the walk's member is to a call named on a pool's member.
enum Twin {
    /// The member the call names.
    Same,
    /// Another member of its pool, whose own tool is published as this name.
    Call(String),
    /// A member this call may not be sent to.
    Declined,
}

/// The member `member` of the called tool's pool, as the call to send it: the tool it serves under
/// the same upstream name, approved with the digest of the pool's primary.
fn twin_of(held: &Held, params: Option<&Value>, member: &str) -> Twin {
    let Some(selected) = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .and_then(|n| held.catalogue.tool(n))
    else {
        return Twin::Same;
    };
    if selected.server == member {
        return Twin::Same;
    }
    let Some((_, pool)) = held.pool_of(&selected.server) else {
        return Twin::Declined;
    };
    if !pool.members.iter().any(|m| m == member) {
        return Twin::Declined;
    }
    let primary = pool
        .members
        .first()
        .and_then(|p| held.catalogue.tool_on(p, &selected.tool))
        .and_then(|t| t.schema_hash.clone());
    match held.catalogue.tool_on(member, &selected.tool) {
        // Interchangeable only on the PRIMARY's approved digest: an unapproved primary pools nothing.
        Some(twin) if primary.is_some() && twin.schema_hash == primary => {
            Twin::Call(twin.namespaced.clone())
        }
        _ => Twin::Declined,
    }
}

/// Where busbar's own ask is decided: who asks, under which roots epoch, and on what.
#[doc(hidden)]
pub struct Site<'a> {
    pub principal: &'a str,
    pub roots_epoch: u64,
    pub method: &'a str,
    pub server: &'a str,
    pub capability: &'a str,
    pub rounds: &'a [crate::tools_config::AskRoundCfg],
}

/// BUSBAR'S OWN ASK for one request ([`crate::ask::decide`]), bound to the unit's principal, the
/// generation's catalogue and the request's arguments, sealed by `seal` ([`DoorSeal`]); `None` (no
/// host services) or a host that signs nothing is a deployment with no sealer, and a capability that
/// asks its caller is refused as one with no signing key refuses it.
#[doc(hidden)]
pub fn decide_ask<S: SealHost>(
    held: &Held,
    site: Site<'_>,
    params: Option<&Value>,
    arguments: &Value,
    seal: Option<&mut S>,
) -> AskDecision {
    let cap = held
        .section
        .servers
        .get(site.server)
        .and_then(|d| d.max_caller_ask_rounds)
        .unwrap_or(crate::tools_config::DEFAULT_MAX_CALLER_ASK_ROUNDS);
    let null = Value::Null;
    let capabilities = params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(crate::codec::META_CLIENT_CAPABILITIES))
        .unwrap_or(&null);
    let retry = crate::ask::Retry {
        responses: params.and_then(|p| p.get("inputResponses")),
        state: params
            .and_then(|p| p.get("requestState"))
            .and_then(Value::as_str),
    };
    // No signing key, no sealer: an ask busbar cannot seal is one it cannot verify the answer to.
    let mut seal = seal;
    if !site.rounds.is_empty() && seal.as_deref_mut().is_some_and(|s| s.sign(b"").is_none()) {
        seal = None;
    }
    // A state's window is stamped and judged at a time the host's clock gave: a clock that fails
    // refuses (never the epoch), in words that name the clock and not the signing key.
    let now = match seal.as_deref_mut().map(SealHost::now) {
        Some(None) if !site.rounds.is_empty() || retry.state.is_some() => {
            return AskDecision::Refuse(crate::ask::AskRefusal::ClockUnavailable {
                capability: site.capability.to_string(),
            });
        }
        Some(now) => now.unwrap_or_default(),
        None => 0,
    };
    let bind = crate::ask::Bind {
        principal: site.principal,
        method: site.method,
        capability: site.capability,
        generation: held.catalogue.generation(),
        now,
        roots_epoch: site.roots_epoch,
    };
    crate::ask::decide(
        site.rounds,
        cap,
        capabilities,
        retry,
        bind,
        &crate::ask::digest_arguments(arguments),
        seal.map(|s| s as &mut dyn crate::ask::Seal),
    )
}

/// What relaying an upstream's ask came to.
enum Relayed {
    /// The caller's answer: the ask relayed, or refused in the refusal's words.
    Answer(Settled),
    /// A host service pended (the work handle's open): called again on its wake.
    Pending,
    /// A stdio child's requests (their ids) that could not be relayed: refused on its input in the
    /// refusal's words, and the call it serves read on.
    RefuseChild(Vec<Value>, crate::call::AskRefusal),
}

/// The record of the work handle a stdio child's relayed ask is correlated under: the child's
/// generation, the call it owes and the member that asked (its digest).
fn child_record(member: &str, child: &crate::ask::ChildLeg) -> Vec<u8> {
    format!(
        "a1|{}|{}|{}",
        child.generation,
        child.wait,
        busbar_contract::redacted::sha256_hex(member.as_bytes())
    )
    .into_bytes()
}

/// The record a relayed ask's work handle is settled with when nobody came back for it.
const CHILD_LAPSED: &[u8] = b"a1|lapsed";

/// Relay an upstream's ask to the caller (busbar answers nothing on the caller's behalf; the ask
/// is plane traffic to the caller). Its result goes to the
/// caller with `inputRequests` verbatim under busbar's one sealed state, bound to the principal, the
/// call (tool, arguments as sent) and the generation, nesting the member that asked and its own
/// state. A stdio child's own requests are first given a work handle (`work.open`): across separate
/// HTTP arrivals the answer is correlated with `work.*`. On a line carrier the same answer is
/// livened ([`door_line::liven`]): an unsolicited emit, answered by a `FROM_CALLER` line.
fn relay_ask(
    plane: &McpDoor,
    ticket: Ticket,
    (principal, generation, member): (&str, u64, String),
    (issued, claim): (&mut u32, &mut Option<(String, u32, u64)>),
    relay: &mut Relay,
    (result, round, child): (Value, u32, Option<crate::ask::ChildLeg>),
) -> Relayed {
    let server = relay.admitted.entry.server.clone();
    let ids = |c: &crate::ask::ChildLeg| c.asks.iter().map(|(_, id)| id.clone()).collect();
    let refused =
        |child: Option<crate::ask::ChildLeg>, refusal: crate::call::AskRefusal| match child {
            Some(c) => Relayed::RefuseChild(ids(&c), refusal),
            None => Relayed::Answer(crate::call::ask_refused(&relay.admitted, &refusal)),
        };
    let no_sealer = crate::call::AskRefusal::NoSealer {
        server: server.clone(),
    };
    let Some(services) = plane.services else {
        return refused(child, no_sealer);
    };
    // No signing key, no sealer: checked before a work handle is opened for an ask that could not
    // be sealed anyway.
    let mut seal = door_tasks::door_seal(plane, services, ticket, (issued, claim));
    if seal.sign(b"").is_none() {
        relay.asked = None;
        return refused(child, no_sealer);
    }
    let child = match child {
        Some(c) if c.work.is_none() => match open_child_work(
            plane,
            (services, ticket, &mut *seal.issued),
            (&mut relay.asked, &mut relay.work_slot),
            (&server, &member),
            (&result, round, c),
        ) {
            ChildOpened::Pending => return Relayed::Pending,
            ChildOpened::Open(c) => Some(c),
            ChildOpened::Refused(c, refusal) => return refused(Some(c), refusal),
        },
        other => other,
    };
    relay.asked = None;
    let leg = crate::ask::UpstreamLeg {
        member,
        state: result.get("requestState").cloned(),
        round: round.saturating_add(1),
        child: child.clone(),
        answers: crate::call::own_answers(&relay.admitted),
    };
    let bind = |now| crate::ask::Bind {
        principal,
        method: crate::codec::METHOD_TOOLS_CALL,
        capability: &relay.admitted.entry.namespaced,
        generation,
        now,
        roots_epoch: 0,
    };
    let digest = &relay.admitted.sent_digest;
    match seal_relayed(
        &mut seal,
        &server,
        bind,
        digest,
        leg,
        crate::ask::DEFAULT_TTL_SECS,
    ) {
        Ok(state) => Relayed::Answer(Settled::Answer {
            status: 200,
            body: crate::ask::relayed_result(&relay.admitted.id, &result, &state),
            line: crate::call::relayed_line(&relay.admitted.entry),
        }),
        Err(refusal) => refused(child, refusal),
    }
}

/// What giving a stdio child's relayed ask its work handle came to ([`open_child_work`]).
enum ChildOpened {
    /// The open pended: called again on its wake, the ask held in the relay.
    Pending,
    /// The handle is open: the child's leg names it.
    Open(crate::ask::ChildLeg),
    /// The host opened none: the child's ask is refused in these words.
    Refused(crate::ask::ChildLeg, crate::call::AskRefusal),
}

/// A STDIO CHILD'S RELAYED ASK GIVEN ITS WORK HANDLE (`work.open`): across separate arrivals the
/// caller's answer is correlated with `work.*`, the synchronous call's and a task's alike. The ask
/// (`result`, `round`, the child's leg `c`) is held in `asked` while the open pends, the open
/// re-issued under `work_slot`; an opened handle is swept with the relays once its state lapses.
fn open_child_work(
    plane: &McpDoor,
    (services, ticket, issued): (StaticServices, Ticket, &mut u32),
    (asked, work_slot): (
        &mut Option<(Value, u32, crate::ask::ChildLeg)>,
        &mut Option<u32>,
    ),
    (server, member): (&str, &str),
    (result, round, mut c): (&Value, u32, crate::ask::ChildLeg),
) -> ChildOpened {
    *asked = Some((result.clone(), round, c.clone()));
    let h = door_tasks::handle(ticket, issued, work_slot);
    let record = child_record(member, &c);
    let (mut buf, mut spans) = ([0u8; 64], [door_tasks::blank(); 2]);
    match services.work_open(
        h,
        crate::tool_records::KIND_APPROVAL,
        &record,
        &mut buf,
        &mut spans,
    ) {
        std::task::Poll::Pending => ChildOpened::Pending,
        std::task::Poll::Ready(Ok(opened)) => {
            c.work = Some(opened.reference.to_string());
            let now_ms = wall_ms(Some(services), ticket, issued);
            // A failed clock read gives the handle no lapse (never one at the epoch): it is
            // settled at once and the ask refused.
            let Some(now_ms) = now_ms else {
                let h = door_tasks::handle(ticket, issued, &mut None);
                let _unheard = services.work_settle(h, opened.handle, CHILD_LAPSED);
                *asked = None;
                return ChildOpened::Refused(
                    c,
                    crate::call::AskRefusal::Unavailable {
                        server: server.to_string(),
                        reason: CLOCK_UNREAD.to_string(),
                    },
                );
            };
            sweep_relays(plane, services, ticket, issued, now_ms);
            plane.relays.insert(
                opened.handle,
                now_ms.saturating_add(crate::ask::DEFAULT_TTL_SECS.saturating_mul(1000)),
            );
            ChildOpened::Open(c)
        }
        std::task::Poll::Ready(Err(_)) => {
            *asked = None;
            ChildOpened::Refused(
                c,
                crate::call::AskRefusal::Unavailable {
                    server: server.to_string(),
                    reason: "the host opened no work handle to correlate the caller's answer \
                             under (it keeps no store for them, or holds as many live ones as \
                             it keeps)"
                        .to_string(),
                },
            )
        }
    }
}

/// Why a relayed state is refused when the host's clock cannot be read.
pub const CLOCK_UNAVAILABLE: &str = "the host's clock could not be read, so the window of the \
     state the caller answers under can be neither stamped nor checked";

/// A RELAYED ASK'S STATE, sealed at the host's clock (one home for a relayed ask and a task parked
/// on its caller's answer): `bind` is made from the time read, and the state stands `ttl_secs`.
///
/// # Errors
///
/// `Unavailable` naming the clock when it cannot be read, `NoSealer` when the state cannot be signed.
#[doc(hidden)]
pub fn seal_relayed<'b, S: SealHost>(
    seal: &mut S,
    server: &str,
    bind: impl FnOnce(u64) -> crate::ask::Bind<'b>,
    digest: &str,
    leg: crate::ask::UpstreamLeg,
    ttl_secs: u64,
) -> Result<String, crate::call::AskRefusal> {
    let no_sealer = || crate::call::AskRefusal::NoSealer {
        server: server.to_string(),
    };
    let now = seal
        .now()
        .ok_or_else(|| crate::call::AskRefusal::Unavailable {
            server: server.to_string(),
            reason: CLOCK_UNAVAILABLE.to_string(),
        })?;
    crate::ask::relay_state_for(bind(now), digest, leg, ttl_secs, seal).ok_or_else(no_sealer)
}

/// THE SWEEP of relayed asks' work handles, run as another is opened: each one whose state lapsed
/// with nobody come back for it is settled (its answer is not waited on), so the live bound holds
/// only asks a caller can still answer.
fn sweep_relays(
    plane: &McpDoor,
    services: StaticServices,
    ticket: Ticket,
    issued: &mut u32,
    now: u64,
) {
    let lapsed: Vec<u64> = plane.relays.with_all(|m| {
        let gone: Vec<u64> = m
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(h, _)| *h)
            .collect();
        for h in &gone {
            m.remove(h);
        }
        gone
    });
    for work in lapsed {
        let h = door_tasks::handle(ticket, issued, &mut None);
        let _unheard = services.work_settle(h, work, CHILD_LAPSED);
    }
}

/// A STDIO CHILD'S ASKS (their `ids`) REFUSED on its input in `refusal`'s words (the operator's
/// round cap, or a relay the deployment cannot carry): the child is never left waiting on an answer
/// nobody will give, and the call it serves is read on.
/// `None` when the member is unregistered or its call is not relayed to a child.
fn refuse_child(
    plane: &McpDoor,
    ticket: Ticket,
    member: &str,
    def: Option<&crate::tools_config::McpServerDefCfg>,
    program: Option<&mut door_program::ProgramRelay>,
    ids: &[Value],
    refusal: &crate::call::AskRefusal,
) -> Option<Step> {
    let (def, program) = (def?, program?);
    let replies = ids
        .iter()
        .map(|id| {
            serde_json::to_vec(&crate::client::peer::refused(
                id,
                refusal.audit_reason(),
                refusal.to_string(),
            ))
            .unwrap_or_default()
        })
        .collect();
    Some(
        match door_program::refuse_asks(plane, ticket, member, def, program, replies) {
            door_program::Far::Pending => Step::Pending,
            _ => Step::Taken,
        },
    )
}

/// THE RETRY OF A STDIO CHILD'S RELAYED ASK binds the work handle the ask is correlated under: found
/// (`work.find`, scoped to the instance and the caller's principal; its record the child's), bound to
/// this unit (`work.resume`) and settled, once. `false` for a handle that is gone, another's, spent
/// or not the child's.
fn bind_child_work(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    member: &str,
    child: &crate::ask::ChildLeg,
) -> std::task::Poll<bool> {
    use std::task::Poll;
    let (Some(services), Some(reference)) = (plane.services, child.work.as_deref()) else {
        return Poll::Ready(false);
    };
    let st = &mut unit.child_work;
    if st.done {
        return Poll::Ready(true);
    }
    let (mut buf, mut spans) = ([0u8; 512], [door_tasks::blank(); 1]);
    if st.handle == 0 {
        let h = door_tasks::handle(ticket, &mut unit.issued, &mut st.find);
        match services.work_find(h, reference, &mut buf, &mut spans) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(Some(found)))
                if found.state == busbar_contract::abi::host::service::WORK_LIVE
                    && found.record == child_record(member, child).as_slice() =>
            {
                st.handle = found.handle;
            }
            Poll::Ready(_) => return Poll::Ready(false),
        }
    }
    if !st.resumed {
        let h = door_tasks::handle(ticket, &mut unit.issued, &mut st.resume);
        match services.work_resume(h, st.handle, &mut buf, &mut spans) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(_)) => st.resumed = true,
            Poll::Ready(Err(_)) => return Poll::Ready(false),
        }
    }
    let h = door_tasks::handle(ticket, &mut unit.issued, &mut st.settle);
    match services.work_settle(h, st.handle, b"a1|answered") {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Ok(())) => {}
        Poll::Ready(Err(_)) => return Poll::Ready(false),
    }
    plane.relays.remove(&st.handle);
    st.done = true;
    Poll::Ready(true)
}

impl Relay {
    fn of(admitted: AdmittedCall) -> Self {
        Relay {
            admitted,
            round: 0,
            status: 0,
            sse: false,
            far: Vec::new(),
            frames: Vec::new(),
            program: None,
            asked: None,
            work_slot: None,
            dispatched_ms: None,
            queued: None,
        }
    }
}

/// What sending an admitted call to its member came to ([`send_to_member`]).
enum MemberSend {
    /// The step the unit takes: its request written, held in its member's line, or pending.
    Step(Step),
    /// The member is not one this call may be sent to: the walk moves on.
    Decline,
    /// The caller's reply to the member's ask is over the member's `sampling_bounds`:
    /// refused by name, never forwarded.
    Judged(Box<AdmittedCall>, crate::call::AskRefusal),
    /// The work handle a stdio child's relayed ask is correlated under is gone, another's or spent.
    Spent(Box<AdmittedCall>),
}

/// The one member-send: an admitted call sent to `member`,
/// the synchronous call's and a task's continuation's alike. The caller's reply to a relayed ask is
/// judged against the member's bound before anything is sent; a `transport: stdio` member's call
/// goes to its child (a relayed ask's retry binding the work handle the ask is correlated under);
/// a network member's carries the caller's `token_exchange:` down-scope and rides the client ladder
/// for this caller (`caller`, the binding its upstream sessions are kept under); and a call behind
/// another on a child whose asks are relayed waits its turn. `None` for a member the section does
/// not register or a call the client dialect cannot build.
fn send_to_member(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
    held: &Held,
    member: &str,
    admitted: AdmittedCall,
) -> Option<MemberSend> {
    let services = plane.services;
    let def = held.section.servers.get(member)?;
    let mut relay = Relay::of(admitted);
    let (round, continuation) = match &relay.admitted.relay {
        Some(r) => (r.round, Some(r.continuation.clone())),
        None => (0, None),
    };
    relay.round = round;
    let child = relay.admitted.relay.as_ref().and_then(|r| r.child.clone());
    // THE CALLER'S REPLY IS BOUNDED TOO (`sampling_bounds.max_input_response_bytes`):
    // what would be forwarded, as it would be serialised, is measured before anything
    // is sent, and a reply over the cap is refused by name and never forwarded.
    let judged = match (&child, &continuation) {
        (Some(child), _) => crate::call::judge_input_response(
            member,
            &def.sampling_bounds,
            crate::tool_program::child_replies(
                child,
                continuation.as_ref().and_then(|c| c.get("inputResponses")),
            )
            .iter()
            .map(Vec::len)
            .sum(),
        ),
        (None, Some(continuation)) => crate::call::judge_input_response(
            member,
            &def.sampling_bounds,
            continuation.to_string().len(),
        ),
        (None, None) => Ok(()),
    };
    if let Err(refusal) = judged {
        return Some(MemberSend::Judged(Box::new(relay.admitted), refusal));
    }
    let mut outbound = if let Some(child) = child {
        // A STDIO CHILD'S RELAYED ASK, ANSWERED: its work handle bound, the caller's
        // answers written to the child under its own ids, and the call it still owes
        // read on.
        if !door_program::is_program(def) {
            return Some(MemberSend::Decline);
        }
        match bind_child_work(plane, ticket, unit, member, &child) {
            std::task::Poll::Pending => return Some(MemberSend::Step(Step::Pending)),
            std::task::Poll::Ready(true) => {}
            std::task::Poll::Ready(false) => {
                return Some(MemberSend::Spent(Box::new(relay.admitted)));
            }
        }
        let mut replies = crate::tool_program::child_replies(
            &child,
            continuation.as_ref().and_then(|c| c.get("inputResponses")),
        );
        let first = if replies.is_empty() {
            Vec::new()
        } else {
            replies.remove(0)
        };
        relay.program = Some(door_program::ProgramRelay::retrying(
            plane,
            member,
            child.wait,
            child.generation,
            replies,
        ));
        crate::call::OutboundCall {
            verb: "POST",
            target: "/".to_string(),
            fields: Vec::new(),
            body: first,
        }
    } else if door_program::is_program(def) {
        // A stdio member: the call carries the unit's own id on the child.
        let id = crate::tool_program::call_id(unit.key, round);
        relay.program = Some(door_program::ProgramRelay::waiting(plane, member, id));
        crate::call::outbound_program(&relay.admitted, member, def, continuation.as_ref(), id)?
    } else {
        crate::call::outbound(&relay.admitted, member, def, round, continuation.as_ref())?
    };
    // A member's token_exchange down-scope / passthrough lend rides its outbound
    // (Q-L3B-DOOR-EXCHANGE); a stdio child carries none.
    if relay.program.is_none() {
        let scope = exchange_scope(services, ticket, unit, held, member, &relay.admitted);
        scoped(&mut outbound.fields, scope.as_deref());
        // THE CLIENT LADDER'S FIRST HOP is the walk's: the stateless request as it
        // always was, or, to an upstream busbar holds a session with, that request
        // lowered into the session ([`door_sessions::Negotiating`]).
        let original = door_sessions::original(&def.url, &outbound);
        // The conversation is this caller's: a session busbar
        // holds with the member for another caller is never this call's.
        let negotiating = door_sessions::Negotiating::begin(plane, member, caller, original);
        if let Some(first) = negotiating.first_request() {
            outbound.fields.clone_from(&first.headers);
            outbound.body.clone_from(&first.body);
        }
        unit.negotiating = Some(Box::new(negotiating));
    }
    // One call at a time on a child whose asks are relayed: a call behind
    // another in its member's line waits its turn, within its own deadline.
    let now = mono_ms(services, ticket, unit);
    if door_program::serialised(def)
        && relay
            .program
            .as_ref()
            .is_some_and(|p| !door_program::in_line(plane, p, now, ticket))
    {
        let deadline = now.map_or(0, |now| now.saturating_add(def.timeout_ms()));
        relay.queued = Some((outbound, deadline));
        unit.relay = Some(relay);
        return Some(MemberSend::Step(Step::Wait(
            deadline.saturating_mul(1_000_000),
        )));
    }
    relay.dispatched_ms = now;
    unit.pending = Some(Pending::far(outbound).laned(&relay.admitted.entry.server));
    unit.relay = Some(relay);
    Some(MemberSend::Step(Step::Write))
}

/// The down-scope a `token_exchange:` member's token is asked for on this unit's call
/// ([`crate::tool_scope::caller_downscope`]): the kernel's entitlement
/// answers for every tool the member serves, and whether the caller's tool grant is a wildcard (a
/// grant no tool name can be: only a wildcard holds it). `None` for a member that does not
/// exchange.
fn exchange_scope(
    services: Option<StaticServices>,
    ticket: Ticket,
    unit: &mut CallUnit,
    held: &Held,
    member: &str,
    admitted: &AdmittedCall,
) -> Option<String> {
    let def = held.section.servers.get(member)?;
    if !crate::tool_scope::exchanges(def, held.section.effective_upstream_credentials(member)) {
        return None;
    }
    let called = held
        .catalogue
        .tool_on(member, &admitted.entry.tool)
        .map_or_else(
            || format!("{member}_{}", admitted.entry.tool),
            |t| t.namespaced.clone(),
        );
    let mut names = vec![String::new()];
    names.extend(
        held.catalogue
            .tools_for(&|kind: &str, name: &str| kind != door::SCOPE || name == member)
            .into_iter()
            .map(|t| t.namespaced.clone()),
    );
    let grants: Vec<(&'static str, &str)> = names
        .iter()
        .map(|n| (door::SCOPE_TOOL, n.as_str()))
        .collect();
    ask_entitlements(services, ticket, unit, &grants);
    let admit = admit(&unit.entitled);
    let entitled = |name: &str| admit(door::SCOPE_TOOL, name);
    Some(crate::tool_scope::caller_downscope(
        &held.catalogue,
        member,
        &called,
        entitled(""),
        &entitled,
    ))
}

/// State `scope` on a request bound for a `token_exchange:` member: the host's own field
/// (`abi::auth::SCOPE_REQUEST_FIELD`), which the host takes into the member's auth call and no wire
/// carries.
fn scoped(fields: &mut Vec<(String, String)>, scope: Option<&str>) {
    if let Some(scope) = scope {
        fields.push((
            busbar_contract::abi::auth::SCOPE_REQUEST_FIELD.to_string(),
            scope.to_string(),
        ));
    }
}

slot!(
    /// `on_piece`: the ATTEMPT names the member; the caller's body is answered from what the plane
    /// holds or sent on as the relayed call; the far end's answer is settled into the caller's. An
    /// answer is written over as many calls as the reply buffer takes, and the unit ends with it.
    OnPiece, OnPieceIn, OnPieceOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let piece = input;
        // A piece of a session (a subscription on the HTTP carrier, or a session revision's held
        // stream) is the session's.
        if piece.stream() != 0 {
            if door_sessions::holds(plane, piece.unit()) {
                return door_sessions::piece(plane, input, &mut out);
            }
            return door_listen::piece(plane, input, &mut out);
        }
        let key = piece.unit();
        let ticket = piece.head().ticket();
        let member = input.member().as_str().unwrap_or_default().to_string();
        let caller = input.caller_ref().as_str().unwrap_or_default().to_string();
        let bytes = input.bytes().bytes();
        let far_type = head(input.head_fields(), CONTENT_TYPE);
        // A session revision's far end names its session in its head.
        let far_session = head(input.head_fields(), crate::adapt::H_SESSION_ID).map(str::to_string);
        // A stdio member's lease names the generation of the child it reached in its head.
        let far_generation = head(input.head_fields(), busbar_contract::conn::PROGRAM_GENERATION_FIELD)
            .and_then(|v| v.trim().parse::<u64>().ok());
        let step = plane.units.with(&key, |unit| {
            let unit = unit?;
            unit.ticket = Some(ticket);
            // A re-call after `more = 1` carries nothing new: write what is still pending.
            if unit.pending.is_some() {
                return Some(Step::Write);
            }
            // A task's continuation, called again part way through a phase that waits.
            let principal = principal_of(&caller);
            if let Some(step) = door_tasks::resume(plane, ticket, principal, unit) {
                return Some(step);
            }
            match piece.from() {
                FROM_KERNEL if piece.attempt_no() > 0 => {
                    unit.member = Some(member);
                    unit.attempt = piece.attempt_no();
                    unit.verified = None;
                    // A new attempt negotiates afresh with its own member.
                    unit.negotiating = None;
                    Some(Step::Taken)
                }
                FROM_KERNEL => Some(Step::Taken),
                FROM_CALLER if piece.flags() & PIECE_LAST == 0 => Some(Step::Taken),
                FROM_CALLER => answer_body(&instance, plane, ticket, &caller, unit),
                FROM_FAR_END => {
                    let held = unit.held.clone();
                    let generation = held.as_ref().map_or(0, |h| h.catalogue.generation());
                    let framing = unit.framing.clone();
                    let task_run = door_tasks::is_run(unit);
                    let relay = unit.relay.as_mut()?;
                    let def = held
                        .as_ref()
                        .and_then(|h| h.section.servers.get(unit.member.as_deref()?));
                    // Replies no call waited for on this caller's held stream: audited on this
                    // answer, rejected (never delivered).
                    let mut dropped_replies = 0_u32;
                    let settled = match () {
                        // A child's ask held while its work handle opened: taken up where it was.
                        () if relay.asked.is_some() => {
                            let (result, round, child) = relay.asked.clone()?;
                            Settled::Relay {
                                result,
                                round,
                                child: Some(child),
                            }
                        }
                        // A stdio member: its answer is the message carrying the call's id.
                        () if relay.program.is_some() => {
                            let member = unit.member.as_deref().unwrap_or_default();
                            let (Some(def), Some(program)) = (def, relay.program.as_mut()) else {
                                return None;
                            };
                            let last = piece.flags() & PIECE_LAST != 0;
                            let head = far_generation.filter(|_| piece.flags() & PIECE_HAS_STATUS != 0);
                            let far = door_program::far(
                                plane, ticket, member, def, program, head, bytes, last,
                            );
                            let wait = program.wait;
                            relay.frames.extend(std::mem::take(&mut program.corr.progress));
                            match far {
                                door_program::Far::Taken => return Some(Step::Taken),
                                door_program::Far::Pending => return Some(Step::Pending),
                                // The child asked busbar's caller: its requests, verbatim,
                                // are relayed under the call's next round; past the operator's round
                                // cap they are refused on the child's input and the call read on.
                                door_program::Far::Asked(asks) => {
                                    let cap = def.max_input_required_rounds.unwrap_or(
                                        crate::tools_config::DEFAULT_MAX_INPUT_REQUIRED_ROUNDS,
                                    );
                                    // An ask past the operator's `sampling_bounds` is refused by
                                    // name on the child's input, as the round cap is.
                                    let server = &relay.admitted.entry.server;
                                    let judged = if relay.round >= cap {
                                        Err(crate::call::AskRefusal::RoundCapExceeded {
                                            server: server.clone(),
                                            cap,
                                        })
                                    } else {
                                        crate::call::judge_sampling_bounds(
                                            server,
                                            &def.sampling_bounds,
                                            asks.iter().map(|a| &a.request),
                                        )
                                    };
                                    if let Err(refusal) = judged {
                                        let ids: Vec<Value> =
                                            asks.into_iter().map(|a| a.id).collect();
                                        let (def, program) = (Some(def), Some(program));
                                        return refuse_child(plane, ticket, member, def, program, &ids, &refusal);
                                    }
                                    // The child still serves the call: its place in the line
                                    // is held for the retry, until the ask's state lapses.
                                    if let Some(now) = clock(plane.services, ticket, &mut unit.issued)
                                        .map(|r| r.mono_ns / 1_000_000)
                                    {
                                        program.hold(now.saturating_add(
                                            crate::ask::DEFAULT_TTL_SECS.saturating_mul(1000),
                                        ));
                                    }
                                    let (result, keys) = crate::tool_program::relayed_asks(&asks);
                                    Settled::Relay {
                                        result,
                                        round: relay.round,
                                        child: Some(crate::ask::ChildLeg {
                                            generation: program.generation,
                                            wait,
                                            asks: keys,
                                            work: None,
                                        }),
                                    }
                                }
                                door_program::Far::Settled(Ok(answer)) => {
                                    relay.status = 200;
                                    relay.far = answer;
                                    crate::call::settle_call_as(
                                        &relay.admitted,
                                        Some(def),
                                        relay.status,
                                        &relay.far,
                                        false,
                                        relay.round,
                                        wait,
                                    )
                                }
                                door_program::Far::Settled(Err(reason)) => {
                                    relay.status = 0;
                                    crate::call::upstream_failed(&relay.admitted, &reason)
                                }
                            }
                        }
                        () => {
                            // A negotiation under way is entered again with the piece it began
                            // on: the far end's answer is already whole.
                            let resumed = unit.negotiating.as_ref().is_some_and(|n| n.fed);
                            let mut over = None;
                            if !resumed {
                                if piece.flags() & PIECE_HAS_STATUS != 0 {
                                    relay.status = piece.status_code();
                                    relay.sse = far_type
                                        .is_some_and(|t| t.starts_with(EVENT_STREAM));
                                    if let Some(n) = unit.negotiating.as_mut() {
                                        n.walk_session = far_session.clone();
                                    }
                                }
                                // AN UPSTREAM'S ANSWER IS BOUNDED as the SDK bounds a reply: one
                                // past the ceiling fails the call as any bad upstream answer does,
                                // and nothing more of it is kept.
                                if relay.far.len().saturating_add(bytes.len()) > REPLY_MAX {
                                    relay.far = Vec::new();
                                    (relay.status, relay.sse) = (0, false);
                                    over = Some(crate::call::upstream_failed(
                                        &relay.admitted,
                                        REPLY_OVER_BOUND,
                                    ));
                                } else {
                                    relay.far.extend_from_slice(bytes);
                                    if piece.flags() & PIECE_LAST == 0 {
                                        return Some(Step::Taken);
                                    }
                                }
                            }
                            if let Some(settled) = over {
                                unit.negotiating = None;
                                settled
                            } else {
                                // The client ladder: an
                                // upstream that refuses the stateless request is negotiated with
                                // over the door's connector; one that answered is handed on as it
                                // answered.
                                let mut failed = None;
                                // The id the call carried in its session, when it is not the
                                // round's: the answer is correlated by it.
                                let mut sent = None;
                                if let (Some(n), Some(def)) = (unit.negotiating.as_mut(), def) {
                                    let base = NEGOTIATE_SEQ
                                        .saturating_add(unit.attempt.saturating_mul(ROUND_SEQ_SPAN));
                                    let member = unit.member.as_deref().unwrap_or_default();
                                    let polled = door_sessions::far_answer(
                                        &instance,
                                        plane,
                                        n,
                                        (base, member, def.timeout_ms()),
                                        (relay.status, relay.sse, &relay.far),
                                    );
                                    let std::task::Poll::Ready(done) = polled else {
                                        return Some(Step::Pending);
                                    };
                                    // The walk's own answer too: a call lowered into its session
                                    // carried that session's id.
                                    sent = n.sent_id();
                                    dropped_replies = n.dropped();
                                    match done {
                                        None => {}
                                        Some(door_sessions::Negotiated::Answer(
                                            status,
                                            raw,
                                            sse,
                                            _,
                                        )) => {
                                            relay.status = u32::from(status);
                                            relay.far = raw;
                                            relay.sse = sse;
                                        }
                                        Some(door_sessions::Negotiated::Failed(reason)) => {
                                            relay.status = 0;
                                            failed = Some(reason);
                                        }
                                    }
                                }
                                unit.negotiating = None;
                                match failed {
                                    Some(reason) => {
                                        crate::call::upstream_failed(&relay.admitted, &reason)
                                    }
                                    None => crate::call::settle_call_as(
                                        &relay.admitted,
                                        def,
                                        relay.status,
                                        &relay.far,
                                        relay.sse,
                                        relay.round,
                                        sent.unwrap_or(crate::client::jsonrpc::dispatch_request_id(
                                            relay.round,
                                        )),
                                    ),
                                }
                            }
                        }
                    };
                    let mut frames = std::mem::take(&mut relay.frames);
                    // An upstream's ask, relayed: its result goes to the caller with
                    // `inputRequests` verbatim, under busbar's one sealed state, which pins the
                    // member that asked and nests the upstream's own; busbar answers none of it.
                    let settled = match settled {
                        // A task's continuation parks its task on the ask, and the caller answers it
                        // through `tasks/update`.
                        Settled::Relay {
                            result,
                            round,
                            child,
                        } if task_run => {
                            let server = relay.admitted.entry.server.clone();
                            // A STDIO CHILD'S ASK on a task is given its work handle as the
                            // synchronous call's is: the task's retry binds it (C-H3).
                            let child = match (child, plane.services) {
                                (Some(c), Some(services)) if c.work.is_none() => {
                                    let member = unit.member.clone().unwrap_or_default();
                                    match open_child_work(
                                        plane,
                                        (services, ticket, &mut unit.issued),
                                        (&mut relay.asked, &mut relay.work_slot),
                                        (&server, &member),
                                        (&result, round, c),
                                    ) {
                                        ChildOpened::Pending => return Some(Step::Pending),
                                        ChildOpened::Open(c) => Some(c),
                                        ChildOpened::Refused(c, refusal) => {
                                            let ids: Vec<Value> =
                                                c.asks.iter().map(|(_, id)| id.clone()).collect();
                                            let program = relay.program.as_mut();
                                            return refuse_child(plane, ticket, &member, def, program, &ids, &refusal);
                                        }
                                    }
                                }
                                (child, _) => child,
                            };
                            relay.asked = None;
                            let digest = relay.admitted.sent_digest.clone();
                            let answered = (relay.status != 0).then_some(relay.far.len());
                            return Some(door_tasks::continuation_asked(
                                plane,
                                ticket,
                                principal,
                                unit,
                                &result,
                                round,
                                child,
                                (&server, &digest, answered),
                            ));
                        }
                        Settled::Relay {
                            result,
                            round,
                            child,
                        } => {
                            let member = unit.member.clone().unwrap_or_default();
                            let asked = relay_ask(
                                plane,
                                ticket,
                                (principal, generation, member),
                                (&mut unit.issued, &mut unit.claim),
                                relay,
                                (result, round, child),
                            );
                            match asked {
                                Relayed::Answer(settled) => settled,
                                Relayed::Pending => return Some(Step::Pending),
                                // The child is told, and the call it serves read on.
                                Relayed::RefuseChild(ids, refusal) => {
                                    let member = unit.member.as_deref().unwrap_or_default();
                                    let program = relay.program.as_mut();
                                    return refuse_child(plane, ticket, member, def, program, &ids, &refusal);
                                }
                            }
                        }
                        answered => answered,
                    };
                    if relay.sse {
                        frames.extend(crate::call::progress_frames(&relay.far));
                        // A progress stream is untrusted upstream input: at most 256 frames across
                        // every round of one call.
                        frames.truncate(256);
                        // What the upstream said beside its answer: its resource updates reach the
                        // sessions watching them, its log records the caller's own session.
                        let server = unit.member.clone().unwrap_or_default();
                        let in_session = door_sessions::session_of(&unit.session);
                        let owner = door_sessions::owner_of(&caller);
                        // The caller's session is touched only at a time the clock gave.
                        let now = in_session.as_ref().and_then(|_| {
                            wall_ms(plane.services, ticket, &mut unit.issued)
                        });
                        // The rate limit on its `list_changed` reads the monotonic clock.
                        let mono = clock(plane.services, ticket, &mut unit.issued)
                            .map(|r| r.mono_ns / 1_000_000);
                        door_sessions::heard(
                            plane,
                            &server,
                            &relay.far,
                            in_session.as_deref().zip(now).map(|(s, now)| (s, &owner, now)),
                            mono,
                        );
                    }
                    let Settled::Answer { status, body, line } = settled else {
                        return None;
                    };
                    // A TASK'S CONTINUATION ends in its task, never in a caller's answer.
                    if task_run {
                        let leg =
                            crate::call::leg_of(relay.status, &relay.far, relay.sse, relay.round);
                        let answered = (relay.status != 0).then_some(relay.far.len());
                        return Some(door_tasks::continuation_answered(
                            plane, ticket, principal, unit, leg, answered, &body,
                        ));
                    }
                    let progress = relay_progress(&relay.admitted, frames);
                    let answered = relay.status != 0;
                    let far_len = relay.far.len();
                    let ts = clock_s(plane.services, ticket, unit);
                    let mut pending = Pending::answer(status, body, framing.as_ref(), &progress)
                        .logged(Some(&line), principal, generation, ts);
                    for _ in 0..dropped_replies {
                        pending = pending.audited(crate::call::AuditRow {
                            action: door_legacy::ACTION_REPLY_DROPPED,
                            resource: server_lane(unit.member.as_deref().unwrap_or_default()),
                            applied: false,
                        });
                    }
                    unit.pending = Some(if answered {
                        pending.counted(far_len)
                    } else {
                        pending
                    });
                    Some(Step::Write)
                }
                _ => Some(Step::Declined),
            }
        });
        match step {
            // A piece the plane refuses ends the unit: its state is dropped with it.
            None | Some(Step::Declined) => {
                plane.units.remove(&key);
                Outcome::Refused
            }
            Some(Step::Taken) => Outcome::Ready,
            Some(Step::Pending) => Outcome::Pending,
            Some(Step::Decline) => {
                out.set(|o| &o.verdict, VERDICT_RETRY);
                Outcome::Ready
            }
            Some(Step::Wait(at)) => {
                if at != 0 {
                    out.wake_at(at);
                }
                Outcome::Pending
            }
            Some(Step::Write) => {
                let finished = plane.units.with(&key, |unit| {
                    let unit = unit?;
                    // A session revision's answer is lowered into it before its first byte goes
                    // ([`door_sessions::lower`]).
                    door_sessions::lower(plane, ticket, &caller, unit);
                    // A line's `input_required` answer is put to its caller as live requests on
                    // the carrier session ([`door_line::liven`]), before its first byte goes.
                    if unit.line.is_some() && unit.pending.as_ref().is_some_and(|p| !p.headed) {
                        door_line::liven(plane, ticket, unit);
                    }

                    let pending = unit.pending.as_mut()?;
                    Some(write(&input, &mut out, pending))
                });
                match finished {
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
                        Outcome::Ready
                    }
                }
            }
        }
    }
);

/// The far end's progress frames, mapped to the caller's own `progressToken` (none when the caller
/// asked for no progress).
fn relay_progress(admitted: &AdmittedCall, mut frames: Vec<Value>) -> Vec<Value> {
    let Some(token) = admitted.progress_token.clone() else {
        return Vec::new();
    };
    for f in &mut frames {
        if let Some(p) = f.get_mut("params").and_then(Value::as_object_mut) {
            p.insert("progressToken".to_string(), token.clone());
        }
    }
    frames
}

/// An admin audit row as the `RECORD_AUDIT` write it rides as (the kernel folds it into its own
/// audit chain under the principal it verified).
fn audit_write(arena: &mut HostBuf<'_, u8>, row: &crate::call::AuditRow) -> RecordWrite {
    RecordWrite {
        kind: if row.applied {
            AUDIT_APPLIED
        } else {
            AUDIT_REJECTED
        },
        op: RECORD_AUDIT,
        key: arena.span(row.action.as_bytes()),
        value: arena.span(row.resource.as_bytes()),
    }
}

/// What one write came to.
enum Written {
    /// More is waiting.
    More,
    /// All of it went, and the unit goes on (a request sent to the far end).
    Sent,
    /// All of it went, and the unit's reply is complete.
    Done,
}

/// Write as much of `pending` as the host's buffers hold: its head with the first call, then its
/// bytes. `Err` = the head's buffers are short (re-called once with what they need).
fn write(
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    pending: &mut Pending,
) -> Result<Written, ()> {
    if !pending.headed {
        let (mut fields, mut arena) = (input.fields_buf(), input.arena_buf());
        for (name, value) in &pending.fields {
            fields.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value.as_bytes()),
            });
        }
        let request = pending
            .request
            .as_ref()
            .map(|(verb, target)| (arena.span(verb.as_bytes()), arena.span(target.as_bytes())));
        let mut records = input.records_buf();
        for (kind, key, value) in &pending.records {
            records.push(RecordWrite {
                kind: *kind,
                op: RECORD_PUT,
                key: arena.span(key),
                value: arena.span(value),
            });
        }
        for row in &pending.audits {
            records.push(audit_write(&mut arena, row));
        }
        let lane = pending
            .lane
            .as_ref()
            .map(|lane| arena.span(lane.as_bytes()));
        let mut units = input.units_buf();
        for count in &pending.units {
            units.push(*count);
        }
        let short = !(fields.fits() && arena.fits() && records.fits() && units.fits());
        let (fw, fnd) = fields.settle(short);
        let (rw, rnd) = records.settle(short);
        let (uw, und) = units.settle(short);
        let (aw, and) = arena.settle(short);
        out.set(|o| &o.records_written, rw as u32);
        out.set(|o| &o.records_needed, rnd as u32);
        out.set(|o| &o.units_written, uw as u32);
        out.set(|o| &o.units_needed, und as u32);
        out.set(|o| &o.fields_written, fw as u32);
        out.set(|o| &o.fields_needed, fnd as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        if short {
            return Err(());
        }
        if let Some((verb, target)) = request {
            out.set(|o| &o.verb, verb);
            out.set(|o| &o.target, target);
        }
        if let Some(lane) = lane {
            out.set(|o| &o.lane, lane);
        }
        out.set(|o| &o.reply_status, pending.status);
        pending.headed = true;
    }
    let mut reply = input.reply_buf();
    let n = reply.stream(pending.bytes.get(pending.sent..).unwrap_or_default());
    pending.sent += n;
    out.set(|o| &o.emitted, n as u64);
    let mut flags = 0;
    if pending.request.is_some() {
        flags |= EMIT_TO_FAR_END;
    }
    if pending.sent < pending.bytes.len() {
        out.set(|o| &o.more, 1);
        out.set(|o| &o.flags, flags);
        return Ok(Written::More);
    }
    if pending.done {
        flags |= EMIT_DONE;
    }
    out.set(|o| &o.flags, flags);
    Ok(if pending.done {
        Written::Done
    } else {
        Written::Sent
    })
}

slot!(
    /// `refusal`: a refused arrival's own words rendered with its own status; any other refusal
    /// rendered as the one error envelope with no id.
    RefusalSlot, RefusalIn, RefusalOut, |instance, input, mut out| {
        let given = input;
        // What the refused unit's arrival read: the request id its caller sent (an answer the
        // caller cannot correlate is not an answer), the tool a refused `tools/call` named, and
        // what it is to the tasks extension: a call that would have created a task (its budget
        // refusal is the task-path words), or a task's continuation (its task
        // fails).
        let (unit_id, called, creates_task, run_reference) = instance
            .get()
            .and_then(|plane| {
                plane.units.with(&given.unit(), |unit| {
                    let unit = unit?;
                    let (id, called) = match &unit.disposition {
                        Disposition::Request { row, id } => (
                            Some(id.clone()),
                            (row.op == crate::tool_ops::OP_TOOL_CALL)
                                .then(|| unit.params.as_ref()?.get("name")?.as_str().map(str::to_string))
                                .flatten(),
                        ),
                        _ => (None, None),
                    };
                    Some((id, called, door_tasks::creates_task(unit), door_tasks::run_reference(unit)))
                })
            })
            .unwrap_or_default();
        // The words the refusal is said in: the kernel's text, but for the walk's exhaustion (an
        // open breaker, a walk out of members or out of time) the reason's own word, wherever this
        // door repeats the words (its generic error, a task's failure): the kernel's text there is
        // the walk's own sentence.
        let text: &[u8] = if given.cause() != REFUSAL_ARRIVE
            && given.reason() == busbar_contract::abi::plane::RefusalCode::BreakerOpen.code()
        {
            // `RefusalCode::BreakerOpen`'s word (`caps` is kernel-side, never named here).
            b"breaker_open"
        } else {
            input.text().bytes()
        };
        // The registration the refused call resolved to (its server), where the catalogue holds it.
        let called_server = instance.get().and_then(|plane| {
            let held = plane.current()?;
            Some(held.catalogue.tool(called.as_deref()?)?.server.clone())
        });
        // Its failure is written to the host's records here, at the refusal.
        let mut task_records = Vec::new();
        if let (Some(plane), Some(reference)) = (instance.get(), run_reference.as_deref()) {
            let message = std::str::from_utf8(text).unwrap_or_default();
            task_records = door_tasks::continuation_refused(plane, given.unit(), reference, message);
        }
        let mut audit: Option<crate::call::AuditRow> = None;
        let mut retry_after: Option<u32> = None;
        // A KERNEL REFUSAL BEFORE ANY UNIT (a mounted path's authentication, the body limit): the
        // JSON-RPC envelope with no id, in the 1.6.0 baseline's bytes (audit K4#2(b): the plane owns
        // the text, the kernel no longer renders it).
        let unitless = (given.unit() == 0 && given.cause() == REFUSAL_KERNEL)
            .then(|| busbar_contract::jsonrpc::unitless_kernel_body(given.reason()))

            .flatten();
        let (status, body, allow) = if let Some(body) = unitless {
            // `0`: the kernel's status stands.
            (0, body.to_vec(), false)
        } else if given.cause() == REFUSAL_ARRIVE {
            // A refused arrival's words read back.
            if text == NOT_ALLOWED_TEXT.as_bytes() {
                (door::STATUS_METHOD_NOT_ALLOWED, door::method_not_allowed_body(), true)
            } else if text == FORBIDDEN_ORIGIN_TEXT.as_bytes() {
                (door::STATUS_FORBIDDEN_ORIGIN, door::forbidden_origin_body(), false)
            } else {
                let Ok(refusal) = serde_json::from_slice::<crate::tool_arrival::Refusal>(text) else {
                    return Outcome::Failed;
                };
                (refusal.status, refusal.body(), false)
            }
        } else {
            let message = std::str::from_utf8(text).unwrap_or_default();
            // The caller's budget said no (a spent budget, a rate, a frozen group): its reason is
            // the one the caller acts on.
            let budget = [
                busbar_contract::abi::plane::RefusalCode::OverBudget,
                busbar_contract::abi::plane::RefusalCode::RateLimited,
                busbar_contract::abi::plane::RefusalCode::GroupFrozen,
            ]
            .into_iter()
            .any(|r| r.code() == given.reason());
            // A call the caller is not granted (the kernel's grant check said no before the plane
            // decided it): answered `404 not_granted` in the words an unknown tool gets.
            let scope_denied =
                given.reason() == busbar_contract::abi::plane::RefusalCode::ScopeDenied.code();
            let ungranted = scope_denied && !creates_task;
            // The audit row of a call the kernel refused before the plane decided it: a scope
            // denial or a hook's veto is a rejected `mcp_tool.call` on the tool the caller named.
            if scope_denied || given.cause() == REFUSAL_GATE {
                audit = called
                    .as_deref()
                    .map(|name| crate::call::AuditRow::tool(name, false));
            }
            let breaker_open =
                given.reason() == busbar_contract::abi::plane::RefusalCode::BreakerOpen.code();
            if let (true, Some(server)) = (breaker_open, called_server.as_deref()) {
                // A TRIPPED SERVER (the walk found no member its breaker admits): the served
                // engine's `503`, `-32030`, its sentence and data, and the wait the kernel's cell
                // knows as `Retry-After`.
                retry_after = Some(given.retry_after_s());
                // The same `-32030` either way; only the account of what happened differs: a call
                // that WAS dispatched and spent the server's `timeout:` says so, and "did not
                // dispatch" stays the words of the paths that dispatched nothing.
                let expired = instance.get().is_some_and(|plane| {
                    plane.units.with(&given.unit(), |unit| {
                        unit.is_some_and(|unit| timed_out(plane.services, given.head().ticket(), unit))
                    })
                });
                let message = if expired {
                    format!(
                        "MCP server `{server}` is unavailable: it did not answer this call within \
                         the server's timeout; busbar dispatched it and stopped waiting. Retry after \
                         {}s.",
                        given.retry_after_s()
                    )
                } else {
                    format!(
                        "MCP server `{server}` is unavailable: its circuit breaker is open after \
                         repeated failures; busbar did not dispatch this call. Retry after {}s.",
                        given.retry_after_s()
                    )
                };
                let refusal = crate::tool_arrival::Refusal {
                    status: 503,
                    id: unit_id.clone(),
                    code: crate::codec::CODE_UPSTREAM_UNAVAILABLE,
                    message,
                    data: Some(serde_json::json!({
                        "reason": "upstream_unavailable",
                        "server": server,
                        "retry_after_ms": u64::from(given.retry_after_s()).saturating_mul(1000),
                    })),
                };
                (refusal.status, refusal.body(), false)
            } else if let (true, Some(name)) = (ungranted, called.as_deref()) {
                let refusal = crate::call::not_granted(
                    unit_id.as_ref().unwrap_or(&Value::Null),
                    name,
                );
                (refusal.status, refusal.body(), false)
            } else {
            // A budget refusal carries the wait the kernel's window reset names (every plane's
            // budget refusal renders it as `Retry-After`, never 0).
            if budget && given.retry_after_s() > 0 {
                retry_after = Some(given.retry_after_s());
            }
            let refusal = if budget && creates_task {
                door_tasks::budget_refused(unit_id.clone(), message)
            } else if budget {
                crate::tool_arrival::Refusal {
                    status: given.status(),
                    id: unit_id.clone(),
                    code: crate::codec::CODE_REFUSED,
                    message: format!("this request was refused by your budget: {message}"),
                    data: Some(serde_json::json!({ "reason": "budget_exhausted" })),
                }
            } else {
                crate::tool_arrival::Refusal {
                    status: given.status(),
                    id: unit_id.clone(),
                    code: crate::codec::CODE_REFUSED,
                    message: message.to_string(),
                    // A hook's veto carries the reason (`hook_rejected`) and the name of the hook
                    // that vetoed it, where the kernel names one.
                    data: (given.cause() == REFUSAL_GATE).then(|| {
                        let reason = busbar_contract::vocab::REASON_HOOK_REJECTED;
                        match std::str::from_utf8(input.hook().bytes()) {
                            Ok(hook) if !hook.is_empty() => {
                                serde_json::json!({ "reason": reason, "hook": hook })
                            }
                            _ => serde_json::json!({ "reason": reason }),
                        }
                    }),
                }
            };
            (0, refusal.body(), false)
            }
        };
        let (mut reply, mut field_buf, mut arena) =
            (input.reply_buf(), input.fields_buf(), input.arena_buf());
        reply.extend(&body);
        if allow {
            field_buf.push(OutField {
                name: arena.span(b"allow"),
                value: arena.span(b"POST"),
            });
        }
        field_buf.push(OutField {
            name: arena.span(CONTENT_TYPE.as_bytes()),
            value: arena.span(JSON.as_bytes()),
        });
        if let Some(secs) = retry_after {
            field_buf.push(OutField {
                name: arena.span(b"retry-after"),
                value: arena.span(secs.to_string().as_bytes()),
            });
        }
        let mut records = input.records_buf();
        for (key, value) in &task_records {
            records.push(RecordWrite {
                kind: door::RECORD_TASK,
                op: RECORD_PUT,
                key: arena.span(key),
                value: arena.span(value),
            });
        }
        if let Some(row) = &audit {
            records.push(audit_write(&mut arena, row));
        }
        let short = !(reply.fits() && field_buf.fits() && arena.fits() && records.fits());
        let (rw, rnd) = reply.settle(short);
        let (fw, fnd) = field_buf.settle(short);
        let (cw, cnd) = records.settle(short);
        let (aw, and) = arena.settle(short);
        out.set(|o| &o.reply_written, rw as u64);
        out.set(|o| &o.reply_needed, rnd as u64);
        out.set(|o| &o.fields_written, fw as u32);
        out.set(|o| &o.fields_needed, fnd as u32);
        out.set(|o| &o.records_written, cw as u32);
        out.set(|o| &o.records_needed, cnd as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        if short {
            return Outcome::Failed;
        }
        out.set(|o| &o.status, status);
        // THE REFUSED UNIT IS OVER: the kernel ends a unit it refuses, and nothing else would ever
        // name it again, so its state (its request's params among it) goes with the refusal.
        if let Some(plane) = instance.get() {
            plane.units.remove(&given.unit());
        }
        Outcome::Ready
    }
);

/// The server name a trust verb's target names (`/tools/{name}/<verb>`), its query cut.
fn verb_subject(target: &[u8]) -> Option<String> {
    let path = std::str::from_utf8(target).ok()?;
    let path = path.split('?').next().unwrap_or(path);
    let mut segments = path.trim_start_matches('/').split('/');
    let (_section, name) = (segments.next()?, segments.next()?);
    (!name.is_empty()).then(|| name.to_string())
}

/// A `connect` paused on the kernel's trust book: the sighting its fetch landed.
struct Sighted(crate::trust::Sighting);

/// The completion handle `trust.sight` is issued on: past every handle the connect's exchange
/// issues on the request's ticket. Past it: a `connect`'s clock reading at `+1`, an admin view's
/// `trust.state` at `+2`, and `connect`'s per-tool `trust.sight_item`s from `+3`.
const SIGHT_SEQ: u32 = 1 << 30;

/// The first handle verify-on-call's fetch numbers its connector services from on a unit's ticket:
/// clear of the unit's own handles (counted from `0`) and of the further rounds'.
const VERIFY_SEQ: u32 = 1 << 29;

/// How many handles one attempt's verify-on-call exchange may number.
const ROUND_SEQ_SPAN: u32 = 1 << 12;

/// The first handle seq a relayed call's negotiation (its hops after the walk's) numbers its
/// connector services from on a unit's ticket: clear of the unit's own handles and of
/// verify-on-call's ([`VERIFY_SEQ`]), each attempt [`ROUND_SEQ_SPAN`] apart.
const NEGOTIATE_SEQ: u32 = 1 << 28;

/// ONE EXCHANGE ON A UNIT'S TICKET, its connector services numbered from `base` (a unit's ticket
/// carries several exchanges, one after another: each counts its own handles, so none reads
/// another's stored answer), parked on the instance while it pends.
fn exchange_at(
    instance: &Instance<'_, McpDoor>,
    host: Option<&busbar_contract::abi::sdk::conn::Host>,
    base: u32,
    url: &str,
    member: &str,
    request: impl FnOnce() -> busbar_contract::abi::sdk::exchange::Request,
) -> std::task::Poll<
    Result<
        busbar_contract::abi::sdk::exchange::ExchangeResponse,
        busbar_contract::abi::sdk::conn::ConnFailure,
    >,
> {
    use busbar_contract::abi::sdk::exchange::{exchange, Exchange};
    let Some(host) = host else {
        return std::task::Poll::Ready(Err(busbar_contract::abi::sdk::conn::ConnFailure::Unarmed));
    };
    let mut state = match instance.resume::<Exchange>() {
        Some(parked) => *parked,
        // The exchange reaches the registration `member`: its own private reach applies.
        None => match Exchange::request(request()) {
            Ok(s) => s.as_member(member),
            Err(e) => return std::task::Poll::Ready(Err(e)),
        },
    };
    let answer = exchange(
        &mut host.connector_from(instance.ticket(), base),
        &mut state,
        0,
        Some(url),
    );
    if answer.is_pending() {
        instance.park(state);
    }
    answer
}

/// The JSON-RPC id a `connect`'s `tools/list` carries: one request, correlated by this id.
const CONNECT_REQUEST_ID: u64 = 1;

/// The door's own `tools/list` of registration `server` (verify-on-call's and `connect`'s): a
/// `token_exchange:` registration's binding exchanges for its approved set.
fn list_request(
    held: &Held,
    server: &str,
    def: &crate::tools_config::McpServerDefCfg,
) -> crate::client::jsonrpc::OutboundRequest {
    let mut request = crate::client::jsonrpc::tools_list(&def.url, CONNECT_REQUEST_ID, None);
    let upstream = held.section.effective_upstream_credentials(server);
    let scope = crate::tool_scope::exchanges(def, upstream)
        .then(|| crate::tool_scope::registration_scope(server, def));
    scoped(&mut request.headers, scope.as_deref());
    request
}

/// The sighting a `connect`'s exchange landed: the server's tool list re-hashed, or why the
/// contact failed.
fn sighting_of(
    answer: Result<busbar_contract::abi::sdk::exchange::ExchangeResponse, String>,
    sent_id: u64,
) -> crate::trust::Sighting {
    use crate::client::jsonrpc::{parse_response, RpcOutcome};
    use crate::trust::Sighting;
    let response = match answer {
        Ok(r) => r,
        Err(reason) => return Sighting::Failed(reason),
    };
    let failed = Sighting::Failed;
    match parse_response(&response.body, sent_id) {
        RpcOutcome::Result(value) => match crate::trust::observe(&value) {
            Ok(obs) => Sighting::Seen(obs),
            Err(reason) => failed(reason),
        },
        RpcOutcome::Error { code, message } => failed(format!(
            "the upstream answered JSON-RPC error {code}: {message}"
        )),
        RpcOutcome::InputRequired { kind } => failed(format!(
            "the upstream answered `tools/list` with an input-required result asking for `{}`; a \
             tool list is not a dispatch and busbar has no round to meter that ask against, so it \
             is refused here",
            kind.key()
        )),
        RpcOutcome::Malformed(reason) => failed(format!(
            "the upstream returned HTTP {} and a body that is not a JSON-RPC response: {reason}",
            response.status
        )),
        RpcOutcome::Uncorrelated(reason) => failed(format!(
            "the upstream returned HTTP {} and a JSON-RPC response busbar cannot correlate to this \
             refresh: {reason}",
            response.status
        )),
    }
}

slot!(
    /// `serve`: the trust verbs over the section's registrations:
    /// `connect` fetches the server's live tool list over the door's own need, re-hashes it, records
    /// the sighting's catalogue hash on the kernel's trust book (`trust.sight`) and answers the trust
    /// view; `changes` answers the same view off the last sighting, contacting nothing; `health`
    /// answers whether it serves. An unregistered name is `404` before anything else; a
    /// `passthrough` registration refuses `connect` with `400` before any network I/O (its credential
    /// belongs to a caller, and an operator's refresh has none). An error answer's body is the
    /// operator-facing message alone: the kernel frames it in the admin taxonomy.
    Serve, ServeIn, ServeOut, |instance, input, mut out| {
        use crate::trust::Sighting;
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let route = input.route() as usize;
        let held = plane.current();
        let name = verb_subject(input.target().bytes());
        let verb = door::ADMIN_VERBS.get(route).map_or("", |(_, t)| t.rsplit('/').next().unwrap_or(""));
        let found = held
            .as_ref()
            .zip(name.as_ref())
            .and_then(|(h, n)| h.section.servers.get(n).cloned().map(|d| (h, n, d)))
            .filter(|_| matches!(verb, "changes" | "health" | "connect"));
        let Some((held, name, def)) = found else {
            let not_found = crate::tool_arrival::STATUS_NOT_FOUND;
            return out.answer(&input, not_found, &[(CONTENT_TYPE, "text/plain")], b"", 0);
        };
        if verb != "connect" {
            let last = plane.sightings.get(name).unwrap_or_default();
            let items = kernel_items(plane, instance.ticket(), name);
            let view = if verb == "changes" {
                crate::trust::trust_view(name, &def, &last, &items)
            } else {
                crate::trust::health_view(name, &last, &items)
            };
            return out.answer(&input, 200, &[(CONTENT_TYPE, JSON)], view.as_bytes(), 0);
        }
        if held.section.effective_upstream_credentials(name)
            == Some(busbar_contract::config::UpstreamCreds::Passthrough)
        {
            let message = format!(
                "server `{name}` is configured `upstream_credentials: passthrough`, so its \
                 credential belongs to a caller; an operator-driven refresh has no caller and \
                 busbar will not substitute its own"
            );
            let plain = [(CONTENT_TYPE, "text/plain")];
            return out.answer(&input, 400, &plain, message.as_bytes(), AUDIT_REJECTED);
        }
        // THE FETCH, unless a pause on the trust book already holds what it landed.
        let sighting = match instance.resume::<Sighted>() {
            Some(sighted) => sighted.0,
            // A `transport: stdio` server is fetched from its own child.
            None if door_program::is_program(&def) => {
                let std::task::Poll::Ready((answer, id)) =
                    door_program::connect_child(&instance, plane, &def, name)
                else {
                    return Outcome::Pending;
                };
                sighting_of(
                    answer.map(|body| busbar_contract::abi::sdk::exchange::ExchangeResponse {
                        status: 200,
                        reason: None,
                        fields: Vec::new(),
                        body,
                    }),
                    id,
                )
            }
            None if def.url.is_empty() => Sighting::Failed(format!(
                "server `{name}` registers no `url:` this door can reach it at"
            )),
            None => {
                // The fetch is verify-on-call's: the stateless `tools/list`
                // first, NEGOTIATED with a server that requires a session or speaks only the
                // `2024-11-05` event stream ([`door_sessions::fetch_in`]), every hop on the
                // connector to the registration `name` (its own private reach applies),
                // bounded by the server's own `timeout:` (an operator verb that hangs is one that
                // gets killed and retried). The conversation is the operator's own binding, never a
                // caller's.
                let request = list_request(held, name, &def);
                let mut slot = plane
                    .connecting
                    .remove(name)
                    .filter(|(ticket, _)| *ticket == instance.ticket())
                    .map(|(_, negotiating)| negotiating);
                let answer = door_sessions::fetch_in(
                    &instance,
                    plane,
                    &mut slot,
                    // The operator's own binding, never a caller reference (those are the kernel's
                    // opaque hex, or empty), so its upstream session is never a caller's.
                    (0, name.as_str(), "operator:connect", def.timeout_ms()),
                    request,
                );
                let std::task::Poll::Ready(answer) = answer else {
                    if let Some(negotiating) = slot {
                        plane.connecting.insert(name.clone(), (instance.ticket(), negotiating));
                    }
                    return Outcome::Pending;
                };
                sighting_of(answer, CONNECT_REQUEST_ID)
            }
        };
        // THE KERNEL'S TRUST BOOK records the observed catalogue (it stamps the re-verification
        // clock); the answer is the plane's comparison, which is what the operator is looking at.
        if let Some(services) = plane.services {
            let mut seq = SIGHT_SEQ + 3;
            if record_sighting(&services, instance.ticket(), &mut seq, &held.catalogue, name, &sighting) {
                instance.park(Sighted(sighting));
                return Outcome::Pending;
            }
        }
        plane.sightings.insert(name.clone(), sighting.clone());
        // THE FRESHNESS CLOCK records that the operator's connect SAW the list: a call within
        // `verify_ttl` of it reuses this sighting rather than fetching the list again. A contact
        // that failed stamps nothing: the next call fetches again, never
        // answered "never sent" off the operator's failed refresh for `verify_ttl`.
        plane.checked.remove(name);
        if let (Some(services), Sighting::Seen(_)) = (plane.services, &sighting) {
            if let Ok(now) = services.clock_now(handle_at(instance.ticket(), SIGHT_SEQ + 1)) {
                plane.checked.insert(name.clone(), now.wall_ns / 1_000_000);
            }
        }
        let items = kernel_items(plane, instance.ticket(), name);
        let view = crate::trust::trust_view(name, &def, &sighting, &items);
        out.answer(&input, 200, &[(CONTENT_TYPE, JSON)], view.as_bytes(), AUDIT_APPLIED)
    }
);

slot!(
    /// `hydrate` and `start`: nothing to restore (the plane's durable records are the host's, and
    /// the trust state they feed is the kernel's) and no background work (re-verification is the
    /// kernel's trust tick, and a stale server is re-verified on the call that names it).
    Inert, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `project`: a `tools/call` as the hook kind's request view: one turn of tool arguments
    /// ([`crate::call::invocation`]), named by the plane's key, the `{tool, arguments}` body, and the
    /// prompt view a content-granted hook reads (the one `user` turn, the arguments as JSON text).
    /// A request-stage hook's rewrite
    /// ([`crate::call::rewritten`]) is applied first: the rewritten request is answered in
    /// `rewritten` (the body the kernel keeps and re-pushes from then on) and is the body projected.
    /// Any other request carries no invocation for a hook to read: REFUSED.
    Project, ProjectIn, ProjectOut, |instance, input, mut out| {
        // THE BODY IS PARSED ONCE: rewritten in place, its params kept, its arguments projected.
        let mut request = serde_json::from_slice::<Value>(input.body().bytes()).ok();
        let rewrite = input.rewrite().bytes();
        let rewritten = request
            .as_mut()
            .filter(|_| !rewrite.is_empty())
            .and_then(|r| {
                crate::call::rewritten(r, rewrite).and_then(|()| serde_json::to_vec(&*r).ok())
            });
        // The rewritten params, kept before the arguments are moved into the invocation.
        let params = rewritten
            .is_some()
            .then(|| request.as_ref().and_then(|v| v.get("params").cloned()));
        let Some(invocation) = request.and_then(crate::call::invocation) else {
            // Any other request carries no invocation for a hook to read, and names no entry its
            // hooks are attached to: an empty view, never a
            // refusal (a bound hook stage asks every routed unit).
            out.set(
                |o| &o.body,
                busbar_contract::abi::mechanism::call::Span {
                    offset: busbar_contract::abi::plane::SPAN_ABSENT,
                    len: 0,
                },
            );
            return Outcome::Ready;
        };
        // AN APPLIED REWRITE IS THE UNIT'S REQUEST FROM NOW ON (`ProjectIn::unit`): the call the
        // door admits and relays is decided from the rewritten params, never the caller's.
        if let (Some(params), Some(plane)) = (params, instance.get()) {
            plane.units.with(&input.unit(), |unit| {
                if let Some(unit) = unit {
                    unit.params = params;
                }
            });
        }
        let shape = busbar_contract::ir::facts::IrFacts::shape(&invocation);
        // The entry the call's hooks are attached to: the registered server its published tool is
        // served by (`tools.hooks` and `tools.<server>.hooks` fire by server).
        let entry = instance
            .get()
            .and_then(McpDoor::current)
            .and_then(|held| held.catalogue.tool(&invocation.tool).map(|t| t.server.clone()))
            .unwrap_or_default();
        // The session an incremental gate scan is keyed on: the caller's `x-session-id`; none
        // when the caller sent none.
        let session = head(input.fields(), "x-session-id")
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        let turns: Vec<(&str, String)> = busbar_contract::ir::facts::IrFacts::content(&invocation)
            .iter()
            .map(|item| (item.author(), item.screenable_text().into_owned()))
            .collect();
        // The `{tool, arguments}` body, the invocation moved into it (never copied).
        let mut projected = serde_json::Map::new();
        projected.insert("tool".to_string(), Value::String(invocation.tool));
        projected.insert("arguments".to_string(), invocation.arguments);
        let projected = serde_json::to_vec(&projected).unwrap_or_default();
        let (mut arena, signals, mut messages) =
            (input.arena_buf(), input.signals_buf(), input.messages_buf());
        let pool = arena.span(entry.as_bytes());
        let session = session.as_deref().map(|s| arena.span(s.as_bytes()));
        let dialect = arena.span(crate::PLANE_KEY.as_bytes());
        let body = arena.span(&projected);
        let rewritten = rewritten.as_deref().map(|r| arena.span(r));
        let turns: Vec<_> = turns
            .iter()
            .map(|(role, text)| (arena.span(role.as_bytes()), arena.span(text.as_bytes())))
            .collect();
        for (role, text) in turns {
            messages.push_turn(&arena, role, text);
        }
        let short = !arena.fits() || !messages.fits();
        let (written, needed) = arena.settle(short);
        let (turns_written, turns_needed) = messages.settle(short);
        out.set(|o| &o.arena_written, written as u64);
        out.set(|o| &o.arena_needed, needed as u64);
        out.set(|o| &o.messages_needed, turns_needed as u32);
        if short {
            return Outcome::Failed;
        }
        out.host_str(|o| &o.view.pool, &arena, pool);
        if let Some(session) = session {
            out.host_octets(|o| &o.view.session, &arena, session);
        }
        out.host_str(|o| &o.view.ingress_dialect, &arena, dialect);
        out.host_list(|o| &o.view.signals, |o| &o.view.signals_len, &signals);
        out.set(|o| &o.view.message_count, shape.turn_count as u64);
        out.set(|o| &o.view.total_chars, shape.text_chars as u64);
        let mut flags = 0;
        if shape.has_tools {
            flags |= busbar_contract::abi::hook::REQUEST_HAS_TOOLS;
        }
        out.set(|o| &o.view.flags, flags);
        out.set(|o| &o.body, body);
        out.host_rows(|o| &o.prompt.messages, &messages);
        out.set(|o| &o.prompt.messages_len, turns_written);
        out.set(|o| &o.prompt.message_count, turns_written as u64);
        if let Some(rewritten) = rewritten {
            out.set(|o| &o.rewritten, rewritten);
        }
        Outcome::Ready
    }
);

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<Validate>, open: Safe<Open>, refresh: Safe<Refresh>, retire: Safe<Retire>,
        tick: Safe<Tick>, drive: Safe<Drive>, cancel: Safe<Cancel>, release: Safe<Release>,
        close: Safe<Close>,
    },
    kind_ops: {
        arrive: Safe<Arrive>, on_piece: Safe<OnPiece>, refusal: Safe<RefusalSlot>,
        serve: Safe<Serve>, hydrate: Safe<Inert>, start: Safe<Inert>, project: Safe<Project>,
    },
}

/// THE SUBSCRIPTIONS HELD AS SESSIONS ON THE HTTP CARRIER (Q-L3B-K6-HTTP (a)): a child of the door,
/// so it reads the door's own unit and answer state.
#[path = "door_listen.rs"]
mod door_listen;

#[path = "door_legacy.rs"]
mod door_legacy;

/// The line carrier's units: a process's own stdin/stdout, one carrier session, one unit per line.
#[path = "door_line.rs"]
mod door_line;
/// THE STDIO SERVERS' LEG (Q-L3B-STDIO-UPSTREAM (A)): a child of the door, so it reads the door's own
/// unit and relay state.
#[path = "door_program.rs"]
mod door_program;
/// The session revisions and the legacy event stream, both directions: a child of the door, so it reads the door's own unit, answer and stream state.
#[path = "door_sessions.rs"]
mod door_sessions;
/// The tasks extension's units: a child of the door, so it
/// reads the door's own unit and answer state.
#[path = "door_tasks.rs"]
mod door_tasks;

/// The door's money answers, pure: what a unit reports beside the answer its caller is written.
#[cfg(test)]
#[path = "tests/door_money.rs"]
mod door_money;
