use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{GenIn, RefreshIn, TickIn, TickOut};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneCancelIn, PlaneCancelOut,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneSnapshot, ProjectIn, ProjectOut, RecordWrite,
    RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount, AUDIT_APPLIED, AUDIT_REJECTED, EMIT_DONE,
    EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST,
    PRINCIPAL_REQUIRED, RECORD_AUDIT, RECORD_PUT, REFUSAL_ARRIVE, REFUSAL_GATE, REFUSAL_KERNEL,
    ROUTE_DIRECT, ROUTE_POOL, UNITS_REPORTED, VERDICT_RETRY,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::exchange::{REPLY_MAX, REPLY_OVER_BOUND};
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::plane::{cancel_disposition, Ending, UnitCancel};
use busbar_contract::abi::sdk::plane_life::{Opened, PlaneLife, Published};
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
use crate::framing::{
    Framing, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, EVENT_STREAM, JSON, NO_STORE,
};
use crate::statement::{self};
use crate::tool_arrival::Disposition;
use crate::tools_config::ToolsCfg;

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// The names of the diagnostics the door raises, as its Statement's diagnostic ids spell them
#[cfg(test)]
pub(crate) const DIAG_NAMES: &[&str] = door_sessions::DIAG_NAMES;

/// How many diagnostic ids the Statement states.
#[cfg(test)]
pub(crate) const DIAG_IDS_LEN: usize = door_sessions::DIAG_IDS.len();

/// At most 64 calls in flight on one instance, as the transport doors state it.
pub const MAX_INFLIGHT: u32 = 64;

/// THE STATEMENT: the plane's name and version, the settings sections it declares
pub const STATEMENT: Statement = {
    let mut s = statement(crate::PLANE_KEY, VERSION, MAX_INFLIGHT)
        .with_sections(statement::SECTIONS)
        .with_needs(statement::NEEDS)
        .with_secret_refs(statement::SECRET_REFS)
        .with_diag_ids(door_sessions::DIAG_IDS)
        .with_kind_tail(statement::TAIL);
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
    /// The pools its servers are members of ([`statement::read_open`]).
    pub pools: BTreeMap<String, statement::ToolPool>,
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
    pub fn pool_of(&self, server: &str) -> Option<(&str, &statement::ToolPool)> {
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
    /// ([`statement::admitted`]).
    admitted: Option<(String, String)>,
    /// Its protected-resource facts ([`statement::resource_facts`]).
    facts: Option<Vec<u8>>,
    /// The browser origins it admits beyond loopback ([`statement::allowed_origins`]).
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
    /// Each registered server's PUBLISHED TOOL LIST ([`PublishedList`]): its last sighting
    /// (verify-on-call's re-fetch, or `connect`), under its generation. What the trust views and the
    /// dispatch gate judge against the section's approval; replaced whole, in one swap
    /// ([`publish`]).
    sightings: Keyed<ListKey, PublishedList>,
    /// THE LOCAL HALF OF THE SPENT-APPROVAL LEDGER: each nonce this instance redeemed, until the
    /// state it records lapses. Consulted before the host's one-time claim, so a node refuses its
    /// own replay without a round trip, and the whole gate where the host binds no store.
    spent: Keyed<String, u64>,
    /// When each registered server's tool list was last fetched (Unix ms, the kernel's clock): what
    /// verify-on-call reads its `verify_ttl` against.
    checked: Keyed<ListKey, u64>,
    /// When each server's last ACCEPTED `list_changed` marked its list stale (the kernel's
    /// monotonic clock, ms): what the notifications' rate limit is read against
    /// ([`door_sessions::list_changed`]).
    list_noticed: Keyed<String, u64>,
    /// THE TOOL-LIST FETCH IN FLIGHT per server (single-flight): the one call fetching it, until
    /// when its lease holds, and the calls waiting on it.
    list_fetch: Keyed<ListKey, ListFetch>,
    /// How many of each server's verify-on-call fetches have landed: a call that joined a fetch
    /// goes on once this moves past the count it joined at.
    list_landed: Keyed<ListKey, u64>,
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
    /// Checked names of complete host Member incarnation/generation pairs.
    program_versions: Keyed<(), crate::program_trust::Versions>,
    /// The requests of a stdio child's own the door decided, by member, generation and id: the call
    /// a granted ask was put to, or `None` = busbar answered it, decided once by whichever exchange
    /// read it first.
    answered: Keyed<(), door_program::Answered>,
    /// The line of calls relayed to stdio children: which call a child serves, so whose its ask
    /// is ([`door_program::Relaying`]).
    relaying: door_program::Relaying,
    /// THE TASKS this instance holds, by `taskId` (SEP-2663, [`door_tasks`]).
    tasks: Keyed<String, crate::tool_tasks::Task>,
    /// Cache-evicted results awaiting authorized host absence: their owner and remaining chunks.
    strikes: Keyed<String, door_tasks::Strikes>,
    inspection_leases: busbar_contract::abi::sdk::life::Leases,
    inspection_serial: Keyed<(), u64>,
    inspection_units: Keyed<u64, door_inspection::Unit>,
    inspection_driver: Keyed<(), door_inspection::Maintenance>,
    /// THE LIVE ASK ROUNDS on carrier sessions, by `(session, ask number)` ([`door_line`]).
    live_asks: Keyed<(u64, u64), crate::line::LiveAsk>,
    /// The subscriptions kept on carrier sessions, by `(session, request id)` ([`door_line`]).
    line_listens: Keyed<(u64, String), door_line::LineListen>,
    /// The last number busbar spelled one of its own requests on a carrier session in.
    ask_seq: Keyed<(), u64>,
    /// Child work owned independently of request units until durable cleanup is confirmed.
    relays: Keyed<u64, door_relay_cleanup::Work>,
    /// THE SESSIONS of the session revisions and the `2024-11-05` stream: this process's, bounded
    /// per owner in count and bytes ([`crate::tool_sessions::SessionTable`], [`door_sessions`]).
    sessions: Keyed<(), door_sessions::Sessions>,
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
    /// Maintenance host/connector handles and their confirmed completion-retirement state.
    legacy_seq: Keyed<(), door_legacy::Driver>,
    /// Whether this instance said its ungoverned chain's sessions are unisolated (once).
    said_ungoverned: Keyed<(), ()>,
    /// The session revision each line-carrier session negotiated with `initialize`.
    line_revisions: Keyed<u64, crate::revision::Revision>,
    /// THE OPERATOR `connect`S UNDER WAY, by server: the ticket each runs on and its negotiated
    /// fetch, kept while it pends (an operator verb has no unit to keep it on). One per server: a
    /// concurrent tickets keep independent negotiation state.
    connecting: Keyed<(String, u32, u32), ConnectFetch>,
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

/// THE LIFECYCLE over the SDK's [`PlaneLife`] (`lifecycle: plane_life(McpDoor)`): `validate`,
impl PlaneLife for McpDoor {
    type Held = Held;

    fn generations(&self) -> &Generations<PlaneSnapshot, Held> {
        &self.generations
    }

    fn leases(&self) -> Option<&busbar_contract::abi::sdk::life::Leases> {
        Some(&self.inspection_leases)
    }

    /// `validate`: the settings read as the section, or refused in the grammar's words.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        statement::read_dealt_tools(settings)
            .map(|_| ())
            .map_err(Refusal::refused)
    }

    /// `open`: the instance over the section, the public base URL and the host services, and the
    fn open(input: &Lent<'_, PlaneOpenIn>) -> Result<Opened<Self>, Refusal> {
        let (cfg, pools) =
            statement::read_open(input.open().settings().bytes()).map_err(Refusal::refused)?;
        let generation = input.open().generation();
        let owned = input.owned().bytes();
        let admitted = statement::admitted_endpoint(input.public_url().stated().as_deref(), owned)
            .map_err(Refusal::refused)?;
        let facts = statement::resource_facts(owned).map_err(Refusal::refused)?;
        let origins = statement::allowed_origins(owned).map_err(Refusal::refused)?;
        let open = input.field(|i| &i.open);
        let host = open.host();
        let plane = McpDoor {
            admitted,
            facts,
            origins,
            services: host.and_then(Services::of),
            host: host.map(busbar_contract::abi::sdk::conn::Host::of),
            wake: host.and_then(busbar_contract::abi::sdk::services::Wake::of),
            ..McpDoor::default()
        };
        plane.sessions.insert(
            (),
            door_sessions::Sessions::new(crate::tool_sessions::Bounds::default()),
        );
        plane
            .upstreams
            .insert((), crate::tool_sessions::UpstreamTable::new(1024, 1 << 20));
        let spec = statement::snapshot_spec_with(plane.admitted.clone(), plane.facts.clone());
        let held = Held {
            pools,
            ..Held::of(generation, cfg)
        };
        Ok(Opened {
            plane,
            first: Published { spec, held },
        })
    }

    /// `refresh` from the whole lent `in`: the new section judged ([`PlaneLife::refresh`]), then the
    fn refresh_in(&self, input: &Lent<'_, RefreshIn>) -> Result<Published<Held>, Refusal> {
        let published = self.refresh(input.settings().bytes(), input.generation())?;
        let owned = busbar_contract::abi::mechanism::extensions::get(
            input.head().extensions().bytes(),
            busbar_contract::abi::plane::EXT_OWNED,
        )
        .unwrap_or_default();
        statement::judge_endpoint_block(owned).map_err(Refusal::refused)?;
        Ok(published)
    }

    /// `refresh`: the new section judged, and the next generation's snapshot over the same public base
    fn refresh(&self, settings: &[u8], generation: u64) -> Result<Published<Held>, Refusal> {
        let (cfg, pools) = statement::read_open(settings).map_err(Refusal::refused)?;
        let spec = statement::snapshot_spec_with(self.admitted.clone(), self.facts.clone());
        let held = Held {
            pools,
            ..Held::of(generation, cfg)
        };
        Ok(Published { spec, held })
    }

    /// A generation was published: a subscription held as a session compares what its caller can
    fn published(&self, _generation: u64) {
        door_listen::wake_all(self);
    }

    fn retire(&self, generation: u64) {
        let waiters = self.list_fetch.with_all(|fetches| {
            let keys: Vec<_> = fetches
                .keys()
                .filter(|(g, _)| *g == generation)
                .cloned()
                .collect();
            keys.into_iter()
                .filter_map(|key| fetches.remove(&key))
                .flat_map(|lease| lease.waiters)
                .collect::<Vec<_>>()
        });
        wake_fetches(self, waiters);
        self.checked
            .with_all(|m| m.retain(|(g, _), _| *g != generation));
        self.sightings
            .with_all(|m| m.retain(|(g, _), _| *g != generation));
        self.list_landed
            .with_all(|m| m.retain(|(g, _), _| *g != generation));
    }

    /// `tick`: the clock of the subscriptions held as sessions ([`door_listen::tick`]), every
    fn tick(
        instance: Instance<'_, Self>,
        input: Lent<'_, TickIn>,
        mut out: Out<'_, TickOut>,
    ) -> Outcome {
        let given = input;
        if let Some(plane) = instance.get() {
            let existing = door_inspection::retained_bytes(given.head().extensions().bytes());
            out.set(
                |o| &o.next_tick_ns,
                given.now_ns().saturating_add(door_listen::POLL_NS),
            );
            if let Err(error) = door_inspection::begin_maintenance(
                plane,
                given.head().ticket(),
                given.now_ns(),
                existing,
            ) {
                return out.fail(Refusal::refused(format!(
                    "carrier-session inspection failed: {error:?}"
                )));
            }
            match door_inspection::maintain(&instance, plane, input, &mut out, existing) {
                std::task::Poll::Pending => return Outcome::Pending,
                std::task::Poll::Ready(Err(error)) => {
                    return out.fail(Refusal::refused(format!(
                        "carrier-session inspection is unavailable: {error:?}"
                    )))
                }
                std::task::Poll::Ready(Ok(_)) => {}
            }
        }
        let next = instance.get().map_or(0, |plane| {
            door_line::tick(plane, given.head().ticket(), given.now_ns());
            let next = door_listen::tick(plane, given.head().ticket(), given.now_ns());
            door_sessions::tick(plane);
            next
        });
        out.set(|o| &o.next_tick_ns, next);
        Outcome::Ready
    }

    /// `drive`: the subscriptions held as sessions whose step is due ([`door_listen::drive`]).
    fn drive(
        instance: Instance<'_, Self>,
        input: Lent<'_, PlaneDriveIn>,
        mut out: Out<'_, PlaneDriveOut>,
    ) -> Outcome {
        match instance.get() {
            Some(plane) => {
                let existing =
                    door_inspection::retained_bytes(input.drive().head().extensions().bytes());
                match door_inspection::maintain(&instance, plane, input, &mut out, existing) {
                    std::task::Poll::Pending => return Outcome::Pending,
                    std::task::Poll::Ready(Err(error)) => {
                        return out.fail(Refusal::refused(format!(
                            "carrier-session inspection is unavailable: {error:?}"
                        )))
                    }
                    std::task::Poll::Ready(Ok(Some(now_ns))) => {
                        door_line::tick(plane, input.drive().head().ticket(), now_ns);
                        door_listen::tick(plane, input.drive().head().ticket(), now_ns);
                        door_sessions::tick(plane);
                    }
                    std::task::Poll::Ready(Ok(None)) => {}
                }

                let pending = door_legacy::drive(
                    &instance,
                    plane,
                    input.drive().head().host(),
                    input.drive().head().extensions().bytes(),
                );
                let pending = match pending {
                    Ok(pending) => pending,
                    Err(error) => {
                        return out.fail(Refusal::refused(format!(
                            "MCP legacy completion retirement is unavailable: {error:?}"
                        )))
                    }
                };
                match door_listen::drive(plane, input, &mut out) {
                    Outcome::Ready => {
                        let queued = match door_legacy::acknowledge(plane, &mut out) {
                            Ok(queued) => queued,
                            Err(error) => {
                                return out.fail(Refusal::refused(format!(
                                    "MCP legacy completion retirement is unavailable: {error:?}"
                                )))
                            }
                        };
                        if pending || queued {
                            Outcome::Pending
                        } else {
                            Outcome::Ready
                        }
                    }
                    outcome => outcome,
                }
            }
            None => Outcome::Ready,
        }
    }

    /// `cancel`: the cancelled unit's state is dropped, found by its ticket or, cancelled before any
    fn cancel(
        instance: Instance<'_, Self>,
        input: Lent<'_, PlaneCancelIn>,
        mut out: Out<'_, PlaneCancelOut>,
    ) -> Outcome {
        let (stopped, creating_records, answered) = instance.get().map_or_else(
            || (Vec::new(), Vec::new(), false),
            |plane| cancel_unit_state(plane, UnitCancel::of(&input)),
        );

        let (mut records, mut arena) = (input.records_buf(), input.arena_buf());
        for id in &stopped {
            records.push(audit_write(
                &mut arena,
                &crate::call::AuditRow::task_cancel(id),
            ));
        }
        for (key, value) in &creating_records {
            records.push(RecordWrite {
                kind: crate::statement::RECORD_TASK,
                op: RECORD_PUT,
                key: arena.span(key),
                value: arena.span(value),
            });
        }
        if !(records.fits() && arena.fits()) {
            return Outcome::Fault;
        }
        let (rw, _) = records.settle(false);
        let (aw, _) = arena.settle(false);
        out.set(|o| &o.records_written, rw as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.cancel.disposition, cancel_disposition(answered));
        Outcome::Ready
    }
}

/// The actual unit-state cancellation, separated from writing its caller's ABI buffers.
fn cancel_unit_state(
    plane: &McpDoor,
    named: UnitCancel,
) -> (Vec<String>, crate::tool_tasks::Records, bool) {
    let mut creating_records = Vec::new();
    let ticket = named.ticket;

    let mut stopped = door_tasks::cancelled(plane, ticket);
    let answered = named.end(
        &plane.units,
        Ending::Remove,
        |u| u.ticket,
        |u| {
            if let Some((reference, records)) = door_tasks::abandoned_create(plane, u) {
                stopped.push(reference);
                creating_records.extend(records);
            }
            u.relay.as_ref().is_some_and(|r| r.status != 0)
        },
    );
    door_inspection::cancelled(plane, ticket, named.unit);

    abandon_fetches(plane, |lease| {
        lease.ticket == ticket || lease.owner == named.unit
    });
    let abandoned = plane.connecting.with_all(|fetches| {
        let keys: Vec<_> = fetches
            .keys()
            .filter(|(_, slot, generation)| {
                *slot == ticket.slot && *generation == ticket.generation
            })
            .cloned()
            .collect();
        keys.into_iter()
            .filter_map(|key| fetches.remove(&key))
            .collect::<Vec<_>>()
    });
    drop(abandoned);
    plane.list_fetch.with_all(|fetches| {
        for lease in fetches.values_mut() {
            lease.waiters.retain(|waiting| *waiting != ticket);
        }
    });
    door_listen::cancelled(plane, ticket);
    door_line::abandoned(plane, ticket, named.unit);
    door_sessions::cancelled(plane, ticket);
    door_legacy::cancelled(plane, ticket);
    (stopped, creating_records, answered)
}

/// The most units the instance keeps state for at once; past it, a new arrival is refused.
pub const MAX_UNITS: usize = 4096;

/// THE WORDS OF AN ARRIVAL REFUSED FOR A FULL UNIT TABLE ([`MAX_UNITS`]), at 429: the planes' one
pub const UNITS_FULL_TEXT: &str =
    "busbar is holding as many MCP calls as it admits at once; retry once one has ended";

/// The most principals the instance keeps a roots epoch of its own for ([`McpDoor::roots`]).
pub const MAX_ROOTS_PRINCIPALS: usize = MAX_UNITS;

/// `principal`'s roots changed (`notifications/roots/list_changed`): its epoch moves, or, the
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
/// ONE SERVER'S TOOL-LIST FETCH IN FLIGHT (single-flight, `docs/mcp.md`: concurrent callers share
/// one fetch): the unit making it, the monotonic time its lease lapses (the fetch is bounded by the
/// server's `timeout:`, so a lease past it belongs to a fetch that will never land and the next
/// call takes it over), and the tickets of the calls waiting on it, woken when it lands.
#[derive(Debug, Clone)]
struct ListFetch {
    owner: u64,
    ticket: Ticket,
    attempt: u32,
    until_ms: Option<u64>,
    waiters: Vec<Ticket>,
}

type ListKey = (u64, String);

fn list_key(held: &Held, server: &str) -> ListKey {
    (held.catalogue.generation(), server.to_string())
}

struct ConnectFetch {
    held: Arc<Held>,
    negotiating: Option<Box<door_sessions::Negotiating>>,
}

struct Verified {
    sighting: crate::trust::Sighting,
    sight_seq: u32,
    receipt: Option<Result<(), String>>,
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
    attempt: u32,
    /// The relayed call, once admitted.
    relay: Option<Relay>,
    /// What it is writing, part way through.
    pending: Option<Pending>,
    /// The approval it is claiming on the host's ledger: the nonce, the handle the claim was
    claim: Option<(String, u32, u64)>,
    /// Verify-on-call's sighting, kept while the kernel's trust book stamps it.
    verified: Option<Verified>,
    /// THE FETCH THIS CALL JOINED (single-flight): the server's landed-fetch count when it found
    joined_fetch: Option<(ListKey, u32, u64)>,
    /// The door's own exchange with a stdio member's child, while it pends ([`door_program`]).
    program: Option<(door_program::Purpose, crate::tool_program::ProgramExchange)>,
    program_list: Option<door_program::ProgramList>,
    /// The attempt whose stdio member the door greeted ([`door_program::ready`]).
    readied: Option<u32>,
    /// The exact checked launch stamp greeted for this attempt, required on rooted eager bodies.
    program_ready: Option<(u32, u64)>,
    /// What the unit is to the tasks extension ([`door_tasks`]).
    task: Option<door_tasks::TaskUnit>,
    /// What the unit is to the line carrier: its session and what its line was ([`door_line`]).
    line: Option<door_line::LineUnit>,
    /// The retry of a stdio child's relayed ask: its work handle found, bound and settled.
    child_work: ChildWork,
    /// What the unit is to the session revisions ([`door_sessions`]).
    session: Option<door_sessions::SessionUnit>,
    /// An upstream conversation under negotiation, parked across PENDING entries
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
    asked: Option<(Value, u32, crate::ask::ChildLeg)>,
    /// The handle number that opening was issued under.
    work_slot: Option<u32>,
    /// When the round's request was handed to the kernel's walk, on the kernel's monotonic clock
    dispatched_ms: Option<u64>,
    /// A stdio call waiting its turn on its member's child ([`door_program::in_line`]): its
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
    local: Option<crate::local_output::Output>,
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
pub(crate) fn server_lane(server: &str) -> String {
    format!("{}:{server}", statement::SCOPE)
}

/// The kernel's one clock (`clock.now`) on a fresh handle of the unit's ticket; `None` when the
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
fn clock_s(services: Option<StaticServices>, ticket: Ticket, unit: &mut CallUnit) -> Option<u64> {
    clock(services, ticket, &mut unit.issued).map(|r| r.wall_ns / 1_000_000_000)
}

/// The kernel's wall clock in Unix milliseconds; `None` with no clock or a failed read, which is
fn wall_ms(services: Option<StaticServices>, ticket: Ticket, issued: &mut u32) -> Option<u64> {
    clock(services, ticket, issued).map(|r| r.wall_ns / 1_000_000)
}

/// The kernel's monotonic clock, whole milliseconds.
fn mono_ms(services: Option<StaticServices>, ticket: Ticket, unit: &mut CallUnit) -> Option<u64> {
    clock(services, ticket, &mut unit.issued).map(|r| r.mono_ns / 1_000_000)
}

/// Whether the walk spent the server's `timeout:` on a dispatched call: the unit handed its relayed request to the walk, and at least the server's
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
    fn local(local: crate::local_renderer::Local, framing: Option<&Framing>) -> Self {
        let len = local.len();
        let output = match framing {
            Some(framing) => {
                let mut output = crate::local_output::Output::default();
                output.bytes(framing.local_prefix());
                output.event(local, None);
                output
            }
            None => crate::local_output::Output::json(local),
        };
        let mut pending = Self::answer(200, Vec::new(), None, &[]);
        pending.fields = match framing {
            Some(_) => vec![
                (CONTENT_TYPE.to_string(), EVENT_STREAM.to_string()),
                (CACHE_CONTROL.to_string(), NO_STORE.to_string()),
            ],
            None => vec![
                (CONTENT_TYPE.to_string(), JSON.to_string()),
                (CONTENT_LENGTH.to_string(), len.to_string()),
            ],
        };
        pending.local = Some(output);
        pending
    }

    /// With the call log's record of `line`, under `scope` and `generation`, at `ts` (the host
    fn logged(
        mut self,
        line: Option<&crate::call::CallLine>,
        scope: &str,
        generation: u64,
        ts: Option<u64>,
    ) -> Self {
        let Some(line) = line else {
            return self;
        };
        if let Some(ts) = ts {
            self.records.push((
                statement::RECORD_CALL,
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
    fn unbilled(mut self) -> Self {
        self.units.retain(|u| u.class != statement::CLASS_FEE_INDEX);
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
            vec![
                (CONTENT_TYPE.to_string(), JSON.to_string()),
                (CONTENT_LENGTH.to_string(), bytes.len().to_string()),
            ]
        };

        let units = if (200..=299).contains(&status) {
            vec![UnitCount {
                class: statement::CLASS_FEE_INDEX,
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

/// Session revisions carry complete local results without stateless-only members. Their own
fn local_revision(unit: &CallUnit) -> bool {
    matches!(
        unit.session,
        Some(door_sessions::SessionUnit::Message { checked: true, .. })
            | Some(door_sessions::SessionUnit::Line)
    )
}

fn local_answer(
    framing: Option<&Framing>,
    revision: bool,
    answer: Result<crate::local_renderer::Local, crate::tool_arrival::Refusal>,
) -> Pending {
    let framing = if revision { None } else { framing };
    match answer {
        Ok(local) => Pending::local(local, framing),
        Err(refusal) => Pending::answer(refusal.status, refusal.body(), framing, &[]),
    }
}

/// The operation class a disposition is counted under: its row's, or the notification class. A
fn op_class(disposition: &Disposition) -> Option<u32> {
    match disposition {
        Disposition::Request { row, .. } => statement::op_class_index(row.op),
        Disposition::Notice { .. } => statement::op_class_index(crate::tool_ops::OP_NOTIFICATION),
        Disposition::Refused(_) => None,
    }
}

/// A refusal as the text a refused arrival carries: the plane's own words, read back by
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
pub const UNSERVED: u32 = 2;

/// [`ArriveOut::refusal`]: the arrival is refused in the plane's own words, which `refusal`
pub const REFUSED_IN_OWN_WORDS: u32 = 1;

/// REFUSED in the plane's own `text`, at `status` ([`ArriveOut::refusal`]
fn refused_arrival(out: &mut Out<'_, ArriveOut>, status: u32, text: String) -> Outcome {
    out.set(|o| &o.refusal, REFUSED_IN_OWN_WORDS);
    out.set(|o| &o.refusal_status, status);
    out.fail(Refusal::refused(text))
}

/// The words of an arrival on a verb the endpoint does not serve.
const NOT_ALLOWED_TEXT: &str = r#"{"allow":"POST"}"#;

/// The words of an arrival from a browser origin the deployment does not admit.
const FORBIDDEN_ORIGIN_TEXT: &str = r#"{"origin":"forbidden"}"#;

/// Why a unit that needs a time is refused when the host's clock read fails: a failed read is never
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
        let claim = statement::ROUTES.get(input.claim() as usize);
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
        let mut origins = fields.iter().filter(|field| {
            field.field(|f| &f.name).as_str().is_ok_and(|name| name.eq_ignore_ascii_case("origin"))
        });
        let origin = origins.next();
        if origins.next().is_some() || origin.is_some_and(|field| {
            !field.field(|f| &f.value).as_str().is_ok_and(|value| {
                busbar_contract::jsonrpc::origin_admitted(value, &plane.origins)
            })
        }) {
            return refused_arrival(
                &mut out,
                statement::STATUS_FORBIDDEN_ORIGIN,
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
                    statement::STATUS_METHOD_NOT_ALLOWED,
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
        let task_run = (input.claim() as usize == statement::TASK_RUN_ROUTE)
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
                message: UNITS_FULL_TEXT.to_string(),
                data: Some(serde_json::json!({ "reason": "capacity" })),
            };
            return refused_arrival(&mut out, refusal.status, refusal_text(&refusal));
        }
        // A line of the line carrier: what it is to the carrier session it arrived
        // over, and the bytes the one dispatch decides on (none: the unit answers its preset).
        let line_route = input.claim() as usize == statement::LINE_ROUTE;
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
                    class: statement::CLASS_FEE_INDEX,
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
            joined_fetch: None,
            program: None,
            program_list: None,
            readied: None,
            program_ready: None,
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
            .filter(|s| s.signature.len() == crate::seal::SIGNATURE_LEN)
            .map(|s| s.signature.to_vec())
    }

    /// The kernel's wall clock, in Unix seconds; `None` when the host's clock cannot be read. A
    fn now(&mut self) -> Option<u64> {
        clock(Some(self.services), self.ticket, self.issued).map(|r| r.wall_ns / 1_000_000_000)
    }
}

/// THE HOST A SEALED STATE IS MINTED AND JUDGED AGAINST: its signature and its wall clock, beside
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

            std::task::Poll::Ready(Ok(won)) => won,

            std::task::Poll::Ready(Err(
                ServiceError::Declined(Outcome::Refused) | ServiceError::Unserved,
            )) => true,

            std::task::Poll::Ready(Err(_)) => false,
        }
    }
}

/// ONE SERVER'S PUBLISHED TOOL LIST: the sighting a re-fetch landed, under the generation its
/// publish bumped to. It is replaced whole, in one swap ([`publish`]), and a reader takes one copy
/// and judges every tool it reads against that copy's digests ([`trust_of`]): never a mix of two
/// lists, and never a list half landed on the kernel's trust book.
#[derive(Debug, Clone, Default)]
struct PublishedList {
    /// Moved by one on every publish of the server's list; `0` = never published.
    generation: u64,
    sighting: crate::trust::Sighting,
}

/// PUBLISH `sighting` as `server`'s tool list, under its next generation, in ONE swap: a reader
fn publish(plane: &McpDoor, key: &ListKey, sighting: crate::trust::Sighting) -> u64 {
    plane.sightings.with_all(|lists| {
        let generation = lists
            .get(key)
            .map_or(0, |list| list.generation)
            .saturating_add(1);
        lists.insert(
            key.clone(),
            PublishedList {
                generation,
                sighting,
            },
        );
        generation
    })
}

fn published_in(plane: &McpDoor, held: &Held, server: &str) -> PublishedList {
    plane
        .sightings
        .get(&list_key(held, server))
        .unwrap_or_default()
}

/// The answer to the caller's body: from what the plane holds, or the relayed call admitted.
enum Looked {
    /// The sighting the gate reads is fresh: judge the call.
    Fresh,
    /// A host service pended (the fetch, or the stamp): called again on its wake.
    Pending,
    /// A joined fetch also wakes at its lease boundary if its owner never returns.
    Wait(u64),
}

/// VERIFY-ON-CALL (the rug-pull defence, before the call): the called server's live tool list is
fn verify_on_call(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    held: &Held,
    (server, caller): (&str, &str),
) -> Looked {
    let Some(def) = held.section.servers.get(server) else {
        return Looked::Fresh;
    };

    let program = door_program::is_program(def);
    if (def.url.is_empty() && !program) || !plane.host.is_some_and(|h| h.lends_connector()) {
        return Looked::Fresh;
    }
    let Some(services) = plane.services else {
        return Looked::Fresh;
    };

    let now_ms = wall_ms(Some(services), ticket, &mut unit.issued);
    let key = list_key(held, server);
    abandon_fetches(plane, |lease| {
        lease.owner == unit.key && lease.attempt != unit.attempt
    });
    let mut verified = match unit.verified.take() {
        Some(kept) => {
            let mono =
                clock(Some(services), ticket, &mut unit.issued).map(|r| r.mono_ns / 1_000_000);
            match join_fetch(plane, &key, ticket, unit, mono, def.timeout_ms()) {
                FetchTurn::Landed => return Looked::Fresh,
                FetchTurn::Wait(until) => {
                    unit.verified = Some(kept);
                    return until.map_or(Looked::Pending, |until| {
                        Looked::Wait(until.saturating_mul(1_000_000))
                    });
                }
                FetchTurn::Owner => kept,
            }
        }
        None => {
            let ttl_ms = busbar_contract::duration::parse_duration_secs(
                def.verify_ttl
                    .as_deref()
                    .unwrap_or(crate::tools_config::DEFAULT_MCP_VERIFY_TTL),
            )
            .unwrap_or(0)
            .saturating_mul(1000);
            let fresh = now_ms.is_some_and(|now| {
                plane
                    .checked
                    .get(&key)
                    .is_some_and(|at| ttl_ms > 0 && now >= at && now - at < ttl_ms)
            });
            if fresh {
                unit.joined_fetch = None;
                return Looked::Fresh;
            }
            let mono =
                clock(Some(services), ticket, &mut unit.issued).map(|r| r.mono_ns / 1_000_000);
            match join_fetch(plane, &key, ticket, unit, mono, def.timeout_ms()) {
                FetchTurn::Landed => return Looked::Fresh,
                FetchTurn::Wait(until) => {
                    return until.map_or(Looked::Pending, |until| {
                        Looked::Wait(until.saturating_mul(1_000_000))
                    })
                }
                FetchTurn::Owner => {}
            }
            let base = VERIFY_SEQ.saturating_add(unit.attempt.saturating_mul(ROUND_SEQ_SPAN));
            let sighting = if program {
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
                let timeout_ms = def.timeout_ms();

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
            };
            let seq = door_tasks::handle(ticket, &mut unit.issued, &mut None).seq;
            Verified {
                sighting,
                sight_seq: seq,
                receipt: None,
            }
        }
    };

    if verified.receipt.is_none() {
        match record_sighting(
            &services,
            ticket,
            verified.sight_seq,
            &mut unit.issued,
            &held.catalogue,
            server,
            &verified.sighting,
        ) {
            std::task::Poll::Pending => {
                unit.verified = Some(verified);
                return Looked::Pending;
            }
            std::task::Poll::Ready(receipt) => verified.receipt = Some(receipt),
        }
    }
    match landed_fetch(plane, &key, unit.key, unit.attempt, verified, now_ms) {
        Ok(()) => {
            unit.joined_fetch = None;
            Looked::Fresh
        }
        Err(verified) => {
            unit.verified = Some(verified);
            let mono = clock(Some(services), ticket, &mut unit.issued).map(|r| r.mono_ns);
            Looked::Wait(mono.unwrap_or(0).saturating_add(1))
        }
    }
}

enum FetchTurn {
    Owner,
    Landed,
    Wait(Option<u64>),
}

fn join_fetch(
    plane: &McpDoor,
    key: &ListKey,
    ticket: Ticket,
    unit: &mut CallUnit,
    mono: Option<u64>,
    timeout: u64,
) -> FetchTurn {
    plane.list_fetch.with_all(|fetches| {
        let count = plane.list_landed.get(key).unwrap_or(0);
        if unit
            .joined_fetch
            .as_ref()
            .is_some_and(|(joined, attempt, at)| {
                joined == key && *attempt == unit.attempt && count > *at
            })
        {
            unit.joined_fetch = None;
            return FetchTurn::Landed;
        }
        let mut waiters = Vec::new();
        if let Some(lease) = fetches.get_mut(key) {
            if lease.owner == unit.key && lease.attempt == unit.attempt {
                return FetchTurn::Owner;
            }

            if mono
                .zip(lease.until_ms)
                .is_none_or(|(now, until)| now < until)
            {
                if !lease.waiters.contains(&ticket) {
                    lease.waiters.push(ticket);
                }
                unit.joined_fetch = Some((key.clone(), unit.attempt, count));
                return FetchTurn::Wait(lease.until_ms);
            }
            waiters = std::mem::take(&mut lease.waiters);
            if !waiters.contains(&lease.ticket) {
                waiters.push(lease.ticket);
            }
        }
        waiters.retain(|waiting| *waiting != ticket);
        unit.joined_fetch = Some((key.clone(), unit.attempt, count));
        fetches.insert(
            key.clone(),
            ListFetch {
                owner: unit.key,
                ticket,
                attempt: unit.attempt,
                until_ms: mono.map(|now| now.saturating_add(timeout)),
                waiters,
            },
        );
        FetchTurn::Owner
    })
}

/// Publication, completion count and lease removal share the join lock. A join can see either
fn landed_fetch(
    plane: &McpDoor,
    key: &ListKey,
    owner: u64,
    attempt: u32,
    mut verified: Verified,
    now_ms: Option<u64>,
) -> Result<(), Verified> {
    let waiters = plane.list_fetch.with_all(|fetches| {
        if !fetches
            .get(key)
            .is_some_and(|lease| lease.owner == owner && lease.attempt == attempt)
        {
            return None;
        }
        let sighting = match verified.receipt.as_ref()? {
            Ok(()) => std::mem::take(&mut verified.sighting),
            Err(reason) => crate::trust::Sighting::Failed(reason.clone()),
        };
        let landed = matches!(sighting, crate::trust::Sighting::Seen(_));
        publish(plane, key, sighting);
        match now_ms {
            Some(now) if landed => {
                plane.checked.insert(key.clone(), now);
            }
            _ => {
                plane.checked.remove(key);
            }
        }
        plane.list_landed.with_all(|counts| {
            let count = counts.entry(key.clone()).or_default();
            *count = count.saturating_add(1);
        });
        fetches.remove(key).map(|lease| lease.waiters)
    });
    let Some(waiters) = waiters else {
        return Err(verified);
    };
    wake_fetches(plane, waiters);
    Ok(())
}

fn wake_fetches(plane: &McpDoor, waiters: Vec<Ticket>) {
    if let Some(wake) = plane.wake {
        for ticket in waiters {
            wake.wake(ticket);
        }
    }
}

fn abandon_fetches(plane: &McpDoor, mut abandoned: impl FnMut(&ListFetch) -> bool) {
    let waiters = plane.list_fetch.with_all(|fetches| {
        let keys: Vec<_> = fetches
            .iter()
            .filter(|(_, lease)| abandoned(lease))
            .map(|(key, _)| key.clone())
            .collect();
        keys.into_iter()
            .filter_map(|key| fetches.remove(&key))
            .flat_map(|lease| lease.waiters)
            .collect::<Vec<_>>()
    });
    wake_fetches(plane, waiters);
}

/// THE SIGHTING ON THE KERNEL'S TRUST BOOK (`trust.sight` of the observed catalogue, or
fn record_sighting(
    services: &Services,
    ticket: Ticket,
    sight_seq: u32,
    seq: &mut u32,
    catalogue: &Catalogue,
    server: &str,
    sighting: &crate::trust::Sighting,
) -> std::task::Poll<Result<(), String>> {
    use crate::trust::Sighting;
    let handle = handle_at(ticket, sight_seq);
    let sighted = match sighting {
        Sighting::Seen(obs) => {
            services.trust_sight(handle, server, &crate::trust::catalogue_hash(obs))
        }
        Sighting::Failed(_) => services.trust_unreachable(handle, server),
        Sighting::Never => std::task::Poll::Ready(Ok(0)),
    };
    match sighted {
        std::task::Poll::Pending => return std::task::Poll::Pending,
        std::task::Poll::Ready(Err(error)) => {
            return std::task::Poll::Ready(Err(format!(
                "the kernel could not record server `{server}`'s trust sighting: {error:?}"
            )))
        }
        std::task::Poll::Ready(Ok(_)) => {}
    }
    if let Sighting::Seen(obs) = sighting {
        for entry in catalogue.tools_of(server) {
            if let Some(digest) = obs.capabilities.get(&entry.tool) {
                let handle = door_tasks::handle(ticket, seq, &mut None);
                if let Err(error) = services.trust_sight_item(handle, server, &entry.tool, digest) {
                    return std::task::Poll::Ready(Err(format!("the kernel could not record server `{server}` tool `{}`'s trust sighting: {error:?}", entry.tool)));
                }
            }
        }
    }
    std::task::Poll::Ready(Ok(()))
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
fn kernel_items(
    plane: &McpDoor,
    ticket: Ticket,
    server: &str,
) -> Result<Vec<crate::trust::KernelItem>, String> {
    use busbar_contract::abi::sdk::services::ServiceError;
    let Some(services) = plane.services else {
        return Err("the kernel lends no trust-state service".to_string());
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
        Ok(items) => Ok(items),

        Err(ServiceError::Short { bytes, items }) => read(
            usize::try_from(bytes).unwrap_or(usize::MAX),
            usize::try_from(items).unwrap_or(usize::MAX),
        )
        .map_err(|error| {
            format!("the kernel could not read server `{server}`'s trust state: {error:?}")
        }),
        Err(error) => Err(format!(
            "the kernel could not read server `{server}`'s trust state: {error:?}"
        )),
    }
}

/// The kernel's Approve on one tool, as the route leg asks it: `trust.serves` over the tool's registration (the counterparty) and its trust key
fn trust_of(
    plane: &McpDoor,
    ticket: Ticket,
    issued: &mut u32,
    entry: &crate::catalogue::ToolEntry,
    list: &PublishedList,
) -> crate::call::Trust {
    use crate::call::Trust;
    use crate::trust::Sighting;
    let digest = match &list.sighting {
        Sighting::Failed(reason) => return Trust::Unreached(reason.clone()),
        Sighting::Seen(observed) => match observed.capabilities.get(&entry.tool) {
            Some(digest) => Some(digest.as_str()),
            None => {
                return Trust::Verdict(busbar_contract::abi::host::service::DISTRUST_UNKNOWN_ITEM)
            }
        },
        Sighting::Never => None,
    };
    let Some(services) = plane.services else {
        return Trust::Verdict(busbar_contract::abi::host::service::DISTRUST_UNKNOWN);
    };
    let handle = door_tasks::handle(ticket, issued, &mut None);
    match services.trust_serves(handle, &entry.server, Some(&entry.tool), digest) {
        Ok(code) => Trust::Verdict(code),

        Err(_) => Trust::Verdict(busbar_contract::abi::host::service::DISTRUST_UNKNOWN),
    }
}

/// One whole published-list snapshot per server and the same hiding rule as `tools/list`.
fn hidden_tools(
    plane: &McpDoor,
    ticket: Ticket,
    issued: &mut u32,
    held: &Held,
    admit: &impl Fn(&str, &str) -> bool,
) -> std::collections::BTreeSet<String> {
    use busbar_contract::abi::host::service::{DISTRUST_CHANGED, DISTRUST_QUARANTINED};
    let mut lists = BTreeMap::new();
    let mut hidden = std::collections::BTreeSet::new();
    for entry in held.catalogue.tools_for(admit) {
        let list = lists
            .entry(entry.server.clone())
            .or_insert_with(|| published_in(plane, held, &entry.server));
        let hides = match trust_of(plane, ticket, issued, entry, list) {
            crate::call::Trust::Verdict(DISTRUST_QUARANTINED) => true,
            crate::call::Trust::Verdict(DISTRUST_CHANGED) => {
                matches!(list.sighting, crate::trust::Sighting::Seen(_))
            }
            _ => false,
        };
        if hides {
            hidden.insert(entry.namespaced.clone());
        }
    }
    hidden
}

/// Recheck a task's selected entry at its actual send boundary, including after a pending greeting
fn admit_task_send(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    held: &Held,
    entry: &crate::catalogue::ToolEntry,
    arguments: &Value,
) -> Result<(), String> {
    let grants = [
        (crate::statement::SCOPE, entry.server.as_str()),
        (crate::statement::SCOPE_TOOL, entry.namespaced.as_str()),
    ];
    for (kind, name) in grants {
        unit.entitled.remove(&format!("{kind}:{name}"));
    }
    ask_entitlements(plane.services, ticket, unit, &grants);
    let mut list = published_in(plane, held, &entry.server);

    if matches!(list.sighting, crate::trust::Sighting::Failed(_)) {
        list.sighting = crate::trust::Sighting::Never;
    }
    let trust = trust_of(plane, ticket, &mut unit.issued, entry, &list);
    crate::call::admits_entry(entry, &admit(&unit.entitled), trust)?;
    let schema = entry
        .input_schema
        .clone()
        .unwrap_or_else(|| serde_json::json!({"type":"object"}));
    crate::argguard::guard(&schema, arguments, |dest| {
        let h = door_tasks::handle(ticket, &mut unit.issued, &mut None);
        plane
            .services
            .and_then(|services| dest_verdict(services, h, held, entry, dest))
    })
    .map(|_| ())
    .map_err(|refused| refused.to_string())
}

/// A QUEUED STDIO CALL'S TURN, the synchronous call's and a task's continuation's alike: `Ok` the
fn queued_turn(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
) -> Option<Result<Step, String>> {
    let deadline = unit.relay.as_ref()?.queued.as_ref()?.1;
    let now = mono_ms(plane.services, ticket, unit);
    if deadline != 0 && now.is_some_and(|now| now >= deadline) {
        let relay = unit.relay.as_mut()?;
        relay.queued = None;
        relay.program = None;
        return Some(Err(format!(
            "the MCP upstream call failed: {}",
            door_program::BUSY
        )));
    }
    let relay = unit.relay.as_ref()?;
    let first = relay
        .program
        .as_ref()
        .is_none_or(|p| door_program::in_line(plane, p, now, ticket));
    if first {
        if door_tasks::is_run(unit) {
            let held = unit.held.as_ref()?.clone();
            let entry = relay.admitted.entry.clone();
            let arguments = relay.admitted.arguments.clone();
            if let Err(words) = admit_task_send(plane, ticket, unit, &held, &entry, &arguments) {
                let relay = unit.relay.as_mut()?;
                relay.queued = None;
                relay.program = None;
                return Some(Err(words));
            }
        }
        let relay = unit.relay.as_mut()?;
        let (outbound, _) = relay.queued.take()?;
        relay.dispatched_ms = now;
        unit.pending = Some(Pending::far(outbound).laned(&relay.admitted.entry.server));
        return Some(Ok(Step::Write));
    }
    let wake_at = unit
        .relay
        .as_ref()
        .and_then(|relay| relay.program.as_ref())
        .map_or(deadline, |program| {
            door_program::queue_wake_at(plane, program, deadline, now)
        });
    Some(Ok(Step::Wait(wake_at.saturating_mul(1_000_000))))
}

/// A stdio call waiting its turn, called again on the wake of the call ahead of it
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

    let principal = principal_of(caller);

    door_line::reconfirm(plane, ticket, principal, unit);

    if let Some(step) = door_sessions::answer(plane, ticket, caller, unit) {
        return Some(step);
    }

    if let Some(pending) = door_line::preset(plane, ticket, unit) {
        unit.pending = Some(pending);
        return Some(Step::Write);
    }
    if let Some(pending) = door_line::listen(plane, ticket, principal, unit) {
        unit.pending = Some(pending);
        return Some(Step::Write);
    }

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
    let local_revision = local_revision(unit);
    if let Some(step) = take_turn(plane, ticket, principal, held.catalogue.generation(), unit) {
        return Some(step);
    }
    let mut params = unit.params.clone();
    let disposition = unit.disposition.clone();

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

    let called = named_tool
        .as_ref()
        .and_then(|_| params.as_ref()?.get("name")?.as_str())
        .and_then(|name| held.catalogue.tool(name));

    let grants = match (&named_tool, called) {
        (Some(_), Some(t)) => vec![
            (statement::SCOPE, t.server.as_str()),
            (statement::SCOPE_TOOL, t.namespaced.as_str()),
        ],
        (Some(_), None) => Vec::new(),
        (None, _) => held.catalogue.grants(),
    };
    ask_entitlements(services, ticket, unit, &grants);

    if let Some(t) = called.filter(|t| {
        let admit = admit(&unit.entitled);
        admit(statement::SCOPE, &t.server) && admit(statement::SCOPE_TOOL, &t.namespaced)
    }) {
        match verify_on_call(instance, plane, ticket, unit, &held, (&t.server, caller)) {
            Looked::Pending => return Some(Step::Pending),
            Looked::Wait(until) => return Some(Step::Wait(until)),
            Looked::Fresh => {}
        }

        if let Some(member) = unit.member.clone() {
            if let Looked::Pending = door_program::ready(plane, ticket, unit, &held, &member) {
                return Some(Step::Pending);
            }
        }
    }

    let mut lists: BTreeMap<String, PublishedList> = BTreeMap::new();
    let mut list_of = |server: &str| {
        lists
            .entry(server.to_string())
            .or_insert_with(|| published_in(plane, &held, server))
            .clone()
    };
    let verdict = called.map(|entry| {
        let list = list_of(&entry.server);
        (
            entry.namespaced.clone(),
            trust_of(plane, ticket, &mut unit.issued, entry, &list),
        )
    });
    let listing = matches!(&disposition, Disposition::Request { row, .. }
        if row.op == crate::tool_ops::OP_TOOLS_LIST || row.op == crate::tool_ops::OP_DISCOVER);
    let hidden = if listing {
        hidden_tools(
            plane,
            ticket,
            &mut unit.issued,
            &held,
            &admit(&unit.entitled),
        )
    } else {
        std::collections::BTreeSet::new()
    };
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

            Admission::Unreached(body, line) => (200, body, Some(line), true),
            Admission::Refused(refusal, line) => (refusal.status, refusal.body(), line, false),

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
                    unit.relay = Some(Relay::of(admitted));
                    return Some(Step::Taken);
                };

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

    if let Disposition::Request { row, id } = &disposition {
        if row.op == crate::tool_ops::OP_RESOURCE_READ {
            let rendered = crate::local_renderer::Local::resource(
                held.clone(),
                id.clone(),
                params.take(),
                &admit,
                local_revision,
            );
            unit.pending = Some(local_answer(
                unit.framing.as_ref(),
                local_revision,
                rendered,
            ));
            return Some(Step::Write);
        }
        if row.op == crate::tool_ops::OP_PROMPT_GET {
            let retried = params.as_ref().is_some_and(|p| {
                p.get("inputResponses").is_some() || p.get("requestState").is_some()
            });
            match crate::reads::prompt_named(&held.catalogue, id, params.as_ref(), &admit) {
                Ok(prompt) if prompt.ask_caller.is_empty() && !retried => {
                    let published = prompt.namespaced.clone();
                    let rendered = crate::local_renderer::Local::prompt(
                        held.clone(),
                        published,
                        id.clone(),
                        params.take(),
                        local_revision,
                    );
                    unit.pending = Some(local_answer(
                        unit.framing.as_ref(),
                        local_revision,
                        rendered,
                    ));
                    return Some(Step::Write);
                }
                Err(refusal) => {
                    unit.pending = Some(Pending::answer(
                        refusal.status,
                        refusal.body(),
                        unit.framing.as_ref(),
                        &[],
                    ));
                    return Some(Step::Write);
                }
                _ => {}
            }
        }
    }

    let answer = crate::answer::answer(
        &disposition,
        params.as_ref(),
        &held.catalogue,
        &admit,
        |entry: &crate::catalogue::ToolEntry| hidden.contains(&entry.namespaced),
    );

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
                        let published = prompt.namespaced.clone();
                        let rendered = crate::local_renderer::Local::prompt(
                            held.clone(),
                            published,
                            id.clone(),
                            params.take(),
                            local_revision,
                        );
                        unit.pending = Some(local_answer(
                            unit.framing.as_ref(),
                            local_revision,
                            rendered,
                        ));
                        return Some(Step::Write);
                    }
                    AskDecision::Refuse(refusal) => {
                        audit = Some(crate::call::AuditRow::prompt_ask(&prompt.namespaced, false));
                        let r = refusal.refusal(id);
                        (r.status, r.body())
                    }

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

    let mut seal = seal;
    if !site.rounds.is_empty() && seal.as_deref_mut().is_some_and(|s| s.sign(b"").is_none()) {
        seal = None;
    }

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
    RefuseChild(Vec<Value>, crate::call::AskRefusal),
}

/// The record of the work handle a stdio child's relayed ask is correlated under: the child's
fn child_record(member: &str, child: &crate::ask::ChildLeg) -> Vec<u8> {
    if let Some((instance, generation)) = child.launch {
        return format!(
            "a2|{instance}|{generation}|{}|{}|{}",
            child.generation,
            child.wait,
            busbar_contract::redacted::sha256_hex(member.as_bytes())
        )
        .into_bytes();
    }
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

    if work_slot.is_none() {
        door_listen::wake_driver(plane);
    }
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

            let Some(now_ms) = now_ms else {
                door_relay_cleanup::hold(plane, opened.handle, 0);
                *asked = None;
                return ChildOpened::Refused(
                    c,
                    crate::call::AskRefusal::Unavailable {
                        server: server.to_string(),
                        reason: CLOCK_UNREAD.to_string(),
                    },
                );
            };
            door_relay_cleanup::hold(
                plane,
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

/// A STDIO CHILD'S ASKS (their `ids`) REFUSED on its input in `refusal`'s words (the operator's
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
fn bind_child_work(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    member: &str,
    child: &crate::ask::ChildLeg,
    require_local: bool,
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

    if require_local
        && !plane
            .relays
            .with_all(|owned| owned.contains_key(&st.handle))
    {
        return Poll::Ready(false);
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
    Judged(Box<AdmittedCall>, crate::call::AskRefusal),
    /// The work handle a stdio child's relayed ask is correlated under is gone, another's or spent.
    Spent(Box<AdmittedCall>),
}

/// The one member-send: an admitted call sent to `member`,
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
    let child_launch = child.as_ref().map(|child| child.launch);
    let checked_program = child.as_ref().map(|child| child.generation).or_else(|| {
        unit.program_ready
            .filter(|(attempt, _)| *attempt == unit.attempt)
            .map(|(_, stamp)| stamp)
    });
    let guarded_fields = if def.pin.mechanism == crate::tools_config::McpPinMechanism::LocalProgram
    {
        let expected = checked_program.and_then(|stamp| {
            plane.program_versions.with_all(|all| {
                all.get(&()).and_then(|versions| match child_launch {
                    Some(launch) => versions.expected_child_fields(member, stamp, launch),
                    None => versions.expected_fields(member, stamp),
                })
            })
        });
        let Some(expected) = expected else {
            return Some(MemberSend::Decline);
        };
        Some(expected)
    } else {
        None
    };
    let mut outbound = if let Some(child) = child {
        if !door_program::is_program(def) {
            return Some(MemberSend::Decline);
        }
        match bind_child_work(
            plane,
            ticket,
            unit,
            member,
            &child,
            def.pin.mechanism == crate::tools_config::McpPinMechanism::LocalProgram,
        ) {
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
            child.wait.clone(),
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
        let id = crate::tool_program::call_id(unit.key, round);
        relay.program = Some(door_program::ProgramRelay::waiting(
            plane,
            member,
            id.clone(),
        ));
        crate::call::outbound_program(&relay.admitted, member, def, continuation.as_ref(), id)?
    } else {
        crate::call::outbound(&relay.admitted, member, def, round, continuation.as_ref())?
    };
    if let Some(expected) = guarded_fields {
        outbound.fields.extend(expected);
    }

    if relay.program.is_none() {
        let scope = exchange_scope(services, ticket, unit, held, member, &relay.admitted);
        scoped(&mut outbound.fields, scope.as_deref());

        let original = door_sessions::original(&def.url, &outbound);

        let negotiating = door_sessions::Negotiating::begin(plane, member, caller, original);
        if let Some(first) = negotiating.first_request() {
            outbound.fields.clone_from(&first.headers);
            outbound.body.clone_from(&first.body);
        }
        unit.negotiating = Some(Box::new(negotiating));
    }

    let now = mono_ms(services, ticket, unit);
    if door_program::serialised(def)
        && relay
            .program
            .as_ref()
            .is_some_and(|p| !door_program::in_line(plane, p, now, ticket))
    {
        let deadline = now.map_or(0, |now| now.saturating_add(def.timeout_ms()));
        let wake_at = relay.program.as_ref().map_or(deadline, |program| {
            door_program::queue_wake_at(plane, program, deadline, now)
        });
        relay.queued = Some((outbound, deadline));
        unit.relay = Some(relay);
        return Some(MemberSend::Step(Step::Wait(
            wake_at.saturating_mul(1_000_000),
        )));
    }
    relay.dispatched_ms = now;
    unit.pending = Some(Pending::far(outbound).laned(&relay.admitted.entry.server));
    unit.relay = Some(relay);
    Some(MemberSend::Step(Step::Write))
}

/// The down-scope a `token_exchange:` member's token is asked for on this unit's call
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
            || crate::tools_config::namespaced(member, &admitted.entry.tool),
            |t| t.namespaced.clone(),
        );
    let mut names = vec![String::new()];
    names.extend(
        held.catalogue
            .tools_for(&|kind: &str, name: &str| kind != statement::SCOPE || name == member)
            .into_iter()
            .map(|t| t.namespaced.clone()),
    );
    let grants: Vec<(&'static str, &str)> = names
        .iter()
        .map(|n| (statement::SCOPE_TOOL, n.as_str()))
        .collect();
    ask_entitlements(services, ticket, unit, &grants);
    let admit = admit(&unit.entitled);
    let entitled = |name: &str| admit(statement::SCOPE_TOOL, name);
    Some(crate::tool_scope::caller_downscope(
        &held.catalogue,
        member,
        &called,
        entitled(""),
        &entitled,
    ))
}

/// State `scope` on a request bound for a `token_exchange:` member: the host's own field
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
        let mut caller = input.caller_ref().as_str().unwrap_or_default().to_string();
        let inspected = match door_inspection::poll_unit(&instance, plane, input, &mut out, key) {
            std::task::Poll::Pending => return Outcome::Pending,
            std::task::Poll::Ready(Some(retained)) => { caller = retained; true },
            std::task::Poll::Ready(None) => false,
        };
        let bytes = input.bytes().bytes();
        let far_type = head(input.head_fields(), CONTENT_TYPE);
        // A session revision's far end names its session in its head.
        let far_session = head(input.head_fields(), crate::adapt::H_SESSION_ID).map(str::to_string);
        let mut step = plane.units.with(&key, |unit| {
            let unit = unit?;
            unit.ticket = Some(ticket);
            // A re-call after `more = 1` carries nothing new: write what is still pending.
            if unit.pending.is_some() {
                return Some(Step::Write);
            }
            if inspected {
                return answer_body(&instance, plane, ticket, &caller, unit);
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
                    unit.program_list = None;
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
                    let mut response_id = Value::from(crate::client::jsonrpc::dispatch_request_id(relay.round));
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
                            let head = if piece.flags() & PIECE_HAS_STATUS != 0 {
                                Some(if program.head_seen {
                                    Err(crate::program_trust::REPEATED.to_string())
                                } else {
                                    door_program::program_generation(plane, member, def, piece.status_code(),
                                        input.head_fields().iter().map(|field| (field.name().bytes(), field.value().bytes())))
                                })
                            } else { None };
                            let far = match head {
                                Some(Err(reason)) => door_program::Far::Settled(Err(reason)),
                                head => door_program::far(plane, ticket, member, def, program,
                                    head.and_then(Result::ok), bytes, last),
                            };
                            let wait = program.wait.clone();
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
                                            launch: (def.pin.mechanism == crate::tools_config::McpPinMechanism::LocalProgram)
                                                .then(|| plane.program_versions.with_all(|all| {
                                                    all.get(&()).and_then(|versions| versions.observed(member, program.generation))
                                                })).flatten().map(|observed| (observed.instance, observed.generation)),
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
                                    response_id = wait.clone();
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
                                if let Some(sent) = sent.as_ref() {
                                    response_id = Value::from(*sent);
                                }
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
                    let task_leg = task_run.then(|| crate::call::leg_of(&settled, &relay.far, relay.sse, response_id));
                    let Settled::Answer { status, body, line } = settled else {
                        return None;
                    };
                    // A TASK'S CONTINUATION ends in its task, never in a caller's answer.
                    if let Some(leg) = task_leg {
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
        if matches!(step, Some(Step::Pending)) {
            match door_inspection::poll_unit(&instance, plane, input, &mut out, key) {
                std::task::Poll::Pending => return Outcome::Pending,
                std::task::Poll::Ready(None) => {},
                std::task::Poll::Ready(Some(retained)) => {
                    caller = retained;
                    step = plane.units.with(&key, |unit| unit.and_then(|unit| answer_body(&instance, plane, ticket, &caller, unit)));
                }
            }
        }
        match step {
            // A piece the plane refuses ends the unit: its state is dropped with it.
            None | Some(Step::Declined) => {
                plane.units.remove(&key);
                plane.inspection_units.remove(&key);
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
                        plane.inspection_units.remove(&key);
                        if let Some(unit) = plane.units.remove(&key) {
                            door_line::completed(plane, &unit);
                        }
                        Outcome::Ready
                    }
                }
            }
        }
    }
);

/// The far end's progress frames, mapped to the caller's own `progressToken` (none when the caller
fn relay_progress(admitted: &AdmittedCall, mut frames: Vec<Value>) -> Vec<Value> {
    let Some(token) = admitted.progress_token.clone() else {
        return Vec::new();
    };

    frames.truncate(256);
    for f in &mut frames {
        if let Some(p) = f.get_mut("params").and_then(Value::as_object_mut) {
            p.insert("progressToken".to_string(), token.clone());
        }
    }
    frames
}

/// An admin audit row as the `RECORD_AUDIT` write it rides as (the kernel folds it into its own
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
    let n = match pending.local.as_mut() {
        Some(local) => local.write_with(|bytes| reply.stream(bytes)),
        None => {
            let n = reply.stream(pending.bytes.get(pending.sent..).unwrap_or_default());
            pending.sent += n;
            n
        }
    };
    out.set(|o| &o.emitted, n as u64);
    let mut flags = 0;
    if pending.request.is_some() {
        flags |= EMIT_TO_FAR_END;
    }
    let more = pending
        .local
        .as_ref()
        .map_or(pending.sent < pending.bytes.len(), |local| !local.done());
    if more {
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
        let (unit_id, called, creates_task, run_reference, called_server, run_receipt) = instance
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
                    let server = called.as_deref().and_then(|name| {
                        unit.held.as_ref()?.catalogue.tool(name).map(|entry| entry.server.clone())
                    });
                    Some((id, called, door_tasks::creates_task(unit), door_tasks::run_reference(unit), server, door_tasks::refusal_receipt(unit)))
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
        if let Some(plane) = instance.get() {
            abandon_fetches(plane, |lease| lease.owner == given.unit());
        }
        // Its failure is written to the host's records here, at the refusal.
        let mut task_records = Vec::new();
        if let (Some(plane), Some(reference)) = (instance.get(), run_reference.as_deref()) {
            let message = std::str::from_utf8(text).unwrap_or_default();
            task_records = door_tasks::continuation_refused(plane, given.unit(), reference, run_receipt, message);
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
                (statement::STATUS_METHOD_NOT_ALLOWED, statement::method_not_allowed_body(), true)
            } else if text == FORBIDDEN_ORIGIN_TEXT.as_bytes() {
                (statement::STATUS_FORBIDDEN_ORIGIN, statement::forbidden_origin_body(), false)
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
                door_tasks::budget_refused(unit_id.clone(), given.status(), message)
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
                kind: statement::RECORD_TASK,
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
struct Sighted(Arc<Held>, crate::trust::Sighting);

/// The completion handle `trust.sight` is issued on: past every handle the connect's exchange
const SIGHT_SEQ: u32 = 1 << 30;

/// The first handle verify-on-call's fetch numbers its connector services from on a unit's ticket:
const VERIFY_SEQ: u32 = 1 << 29;

/// How many handles one attempt's verify-on-call exchange may number.
const ROUND_SEQ_SPAN: u32 = 1 << 12;

/// The first handle seq a relayed call's negotiation (its hops after the walk's) numbers its
const NEGOTIATE_SEQ: u32 = 1 << 28;

/// ONE EXCHANGE ON A UNIT'S TICKET, its connector services numbered from `base` (a unit's ticket
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
fn sighting_of(
    answer: Result<busbar_contract::abi::sdk::exchange::ExchangeResponse, String>,
    sent_id: impl Into<Value>,
) -> crate::trust::Sighting {
    use crate::client::jsonrpc::{parse_response_id, RpcOutcome};
    use crate::trust::Sighting;
    let response = match answer {
        Ok(r) => r,
        Err(reason) => return Sighting::Failed(reason),
    };
    let failed = Sighting::Failed;
    match parse_response_id(&response.body, &sent_id.into()) {
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
        let name = verb_subject(input.target().bytes());
        let ticket = instance.ticket();
        let connect_key = name.as_ref().map(|name| (name.clone(), ticket.slot, ticket.generation));
        let connecting = connect_key.as_ref().and_then(|key| plane.connecting.remove(key));
        let sighted = instance.resume::<Sighted>();
        let held = sighted.as_ref().map(|s| s.0.clone())
            .or_else(|| connecting.as_ref().map(|fetch| fetch.held.clone()))
            .or_else(|| plane.current());
        let verb = statement::ADMIN_VERBS.get(route).map_or("", |(_, t)| t.rsplit('/').next().unwrap_or(""));
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
            let last = published_in(plane, held, name).sighting;
            let items = match kernel_items(plane, instance.ticket(), name) {
                Ok(items) => items,
                Err(reason) => return out.answer(&input, 503, &[(CONTENT_TYPE, "text/plain")], reason.as_bytes(), 0),
            };
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
        let sighting = match sighted {
            Some(sighted) => sighted.1,
            // A `transport: stdio` server is fetched from its own child.
            None if door_program::is_program(&def) => {
                let std::task::Poll::Ready((answer, id)) =
                    door_program::connect_child(&instance, plane, &def, name)
                else {
                    if let Some(key) = connect_key {
                        plane.connecting.insert(key, ConnectFetch { held: held.clone(), negotiating: None });
                    }
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
                let mut slot = connecting.and_then(|fetch| fetch.negotiating);
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
                    if let Some(key) = connect_key {
                        plane.connecting.insert(key, ConnectFetch { held: held.clone(), negotiating: slot });
                    }
                    return Outcome::Pending;
                };
                sighting_of(answer, CONNECT_REQUEST_ID)
            }
        };
        // THE KERNEL'S TRUST BOOK records the observed catalogue (it stamps the re-verification
        // clock); the answer is the plane's comparison, which is what the operator is looking at.
        let key = list_key(held, name);
        let Some(services) = plane.services else {
            return out.answer(&input, 503, &[(CONTENT_TYPE, "text/plain")], b"the kernel lends no trust-sighting service", AUDIT_REJECTED);
        };
        let mut seq = SIGHT_SEQ + 3;
        match record_sighting(&services, instance.ticket(), SIGHT_SEQ, &mut seq, &held.catalogue, name, &sighting) {
            std::task::Poll::Pending => {
                instance.park(Sighted(held.clone(), sighting));
                return Outcome::Pending;
            }
            std::task::Poll::Ready(Err(reason)) => {
                plane.checked.remove(&key);
                return out.answer(&input, 503, &[(CONTENT_TYPE, "text/plain")], reason.as_bytes(), AUDIT_REJECTED);
            }
            std::task::Poll::Ready(Ok(())) => {}
        }
        publish(plane, &key, sighting.clone());
        // THE FRESHNESS CLOCK records that the operator's connect SAW the list: a call within
        // `verify_ttl` of it reuses this sighting rather than fetching the list again. A contact
        // that failed stamps nothing: the next call fetches again, never
        // answered "never sent" off the operator's failed refresh for `verify_ttl`.
        plane.checked.remove(&key);
        if let Sighting::Seen(_) = &sighting {
            if let Ok(now) = services.clock_now(handle_at(instance.ticket(), SIGHT_SEQ + 1)) {
                plane.checked.insert(key, now.wall_ns / 1_000_000);
            }
        }
        let items = match kernel_items(plane, instance.ticket(), name) {
            Ok(items) => items,
            Err(reason) => return out.answer(&input, 503, &[(CONTENT_TYPE, "text/plain")], reason.as_bytes(), AUDIT_REJECTED),
        };
        let view = crate::trust::trust_view(name, &def, &sighting, &items);
        out.answer(&input, 200, &[(CONTENT_TYPE, JSON)], view.as_bytes(), AUDIT_APPLIED)
    }
);

slot!(
    /// `hydrate`: nothing to restore (the plane's durable records are the host's, and the trust
    /// state they feed is the kernel's).
    Hydrate, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `start`: no background work (re-verification is the kernel's trust tick, and a stale server
    /// is re-verified on the call that names it).
    Start, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

busbar_contract::own_seal!(ProjectionOwner);
type ProjectionBytes = busbar_contract::Secret<Vec<u8>, ProjectionOwner>;
type ProjectionText = busbar_contract::Secret<String, ProjectionOwner>;

slot!(
    /// `project`: a `tools/call` as the hook kind's request view: one turn of tool arguments
    /// ([`crate::call::invocation`]), named by the plane's key, the `{tool, arguments}` body, and the
    /// prompt view a content-granted hook reads (the one `user` turn, the arguments as JSON text).
    /// A request-stage hook's rewrite
    /// ([`crate::call::rewritten`]) is applied first: the rewritten request is answered in
    /// `rewritten` (the body the kernel keeps and re-pushes from then on) and is the body projected.
    /// Any other request carries an empty view (absent body) for the hook.
    Project, ProjectIn, ProjectOut, |instance, input, mut out| {
        // THE BODY IS PARSED ONCE: rewritten in place, its params kept, its arguments projected.
        let mut request = serde_json::from_slice::<Value>(input.body().bytes()).ok();
        let rewrite = input.rewrite().bytes();
        let rewritten = request
            .as_mut()
            .filter(|_| !rewrite.is_empty())
            .and_then(|r| {
                crate::call::rewritten(r, rewrite).and_then(|()| serde_json::to_vec(&*r).ok())
            })
            .map(ProjectionBytes::held);
        // The rewritten params, kept before the arguments are moved into the invocation.
        let mut params = rewritten
            .is_some()
            .then(|| request.as_ref().and_then(|v| v.get("params").cloned()))
            .flatten()
            .map(|arguments| busbar_contract::ir::invoke::InvokeReq {
                tool: String::new(), arguments, extra: Default::default(),
            });
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
        if let (Some(params), Some(plane)) = (params.as_mut(), instance.get()) {
            plane.units.with(&input.unit(), |unit| {
                if let Some(unit) = unit {
                    unit.params = Some(Value::take(&mut params.arguments));
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
        let turns: Vec<(&str, ProjectionText)> = busbar_contract::ir::facts::IrFacts::content(&invocation)
            .iter()
            .map(|item| (item.author(), ProjectionText::held(item.screenable_text().into_owned())))
            .collect();
        #[derive(serde::Serialize)]
        struct Projection<'a> { arguments: &'a Value, tool: &'a str }
        let projected = ProjectionBytes::held(serde_json::to_vec(&Projection {
            arguments: &invocation.arguments, tool: &invocation.tool,
        }).unwrap_or_default());
        let (mut arena, signals, mut messages) =
            (input.arena_buf(), input.signals_buf(), input.messages_buf());
        let pool = arena.span(entry.as_bytes());
        let session = session.as_deref().map(|s| arena.span(s.as_bytes()));
        let dialect = arena.span(crate::PLANE_KEY.as_bytes());
        let seal = ProjectionOwner::here();
        let body = arena.span(projected.expose_own(&seal));
        let rewritten = rewritten.as_ref().map(|r| arena.span(r.expose_own(&seal)));
        let turns: Vec<_> = turns
            .iter()
            .map(|(role, text)| (arena.span(role.as_bytes()), arena.span(text.expose_own(&seal).as_bytes())))
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
    lifecycle: plane_life(McpDoor),
    kind_ops: {
        arrive: Safe<Arrive>, on_piece: Safe<OnPiece>, refusal: Safe<RefusalSlot>,
        serve: Safe<Serve>, hydrate: Safe<Hydrate>, start: Safe<Start>, project: Safe<Project>,
    },
}

/// THE SUBSCRIPTIONS HELD AS SESSIONS ON THE HTTP CARRIER (Q-L3B-K6-HTTP (a)): a child of the door,
#[path = "door_listen.rs"]
mod door_listen;

#[path = "door_legacy.rs"]
mod door_legacy;

#[path = "door_relay_cleanup.rs"]
mod door_relay_cleanup;

#[path = "door_inspection.rs"]
mod door_inspection;
/// The line carrier's units: a process's own stdin/stdout, one carrier session, one unit per line.
#[path = "door_line.rs"]
mod door_line;
/// THE STDIO SERVERS' LEG (Q-L3B-STDIO-UPSTREAM (A)): a child of the door, so it reads the door's own
#[path = "door_program.rs"]
mod door_program;
/// The session revisions and the legacy event stream, both directions: a child of the door, so it reads the door's own unit, answer and stream state.
#[path = "door_sessions.rs"]
mod door_sessions;
/// The tasks extension's units: a child of the door, so it
#[path = "door_tasks.rs"]
mod door_tasks;

/// The door's money answers, pure: what a unit reports beside the answer its caller is written.
#[cfg(test)]
#[path = "tests/door_money.rs"]
mod door_money;

#[cfg(test)]
#[path = "tests/published_scope.rs"]
mod published_scope;

#[cfg(test)]
#[path = "tests/reported_progress.rs"]
mod reported_progress;
