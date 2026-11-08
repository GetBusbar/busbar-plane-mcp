// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The session revisions and the legacy event stream, served, in both directions.

use std::collections::VecDeque;
use std::task::Poll;

use serde_json::{json, Value};

use super::door_listen::{self, mono_ns};
use super::door_tasks::handle;
use super::{
    admit, ask_entitlements, exchange_at, wall_ms, write, CallUnit, Held, McpDoor, Pending, Step,
    Written,
};
use crate::adapt::{self, SessionMethod};
use crate::catalogue::Lookup;
use crate::client::jsonrpc::OutboundRequest;
use crate::client::negotiate::{Action, HopAnswer, Negotiator, Refusal as Refused};
use crate::codec::{
    CODE_INTERNAL, CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND, CODE_REFUSED,
    H_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use crate::framing::{CONTENT_LENGTH, CONTENT_TYPE, EVENT_STREAM};
use crate::revision::{self, Revision};
use crate::tool_arrival::{Disposition, Refusal};
use crate::tool_sessions::{
    OpenRefused, Owner, Remembered, ReplayData, ReplayTable, UpstreamTable,
};
use busbar_contract::abi::mechanism::call::{Outcome, SEVERITY_WARN};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{OnPieceIn, OnPieceOut, FROM_CALLER, FROM_KERNEL, PIECE_LAST};
use busbar_contract::abi::sdk::{Instance, Lent, Out};

/// Local cursors enter history without expansion only when the existing quota will immediately
/// trim them. Retainable answers become ordinary text, releasing original inputs and generation.
#[derive(Clone, Debug)]
pub(super) enum Data {
    Text(String),
    Local(crate::local_renderer::Local),
}

impl From<String> for Data {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl ReplayData for Data {
    fn encoded_len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Local(local) => local.len(),
        }
    }
}

pub(super) type Sessions = ReplayTable<Data>;

fn history_data(table: &Sessions, data: Data) -> Result<Data, ()> {
    match data {
        Data::Local(local) if table.retained_event_fits(local.len()) => {
            Ok(Data::Text(crate::local_output::buffered(local)?))
        }
        data => Ok(data),
    }
}

/// THE INSTANCE'S DIAGNOSTIC that an ungoverned chain's sessions are unisolated, latched on its
/// first `2024-11-05` stream (the index of its id in the Statement's diagnostic ids).
pub(super) const UNGOVERNED_LEGACY_STREAM: u32 = 0;

/// The names of the Statement's diagnostic ids, in index order: each the `BUSBAR-NNNN` banner of
/// the catalog code it raises (`declares.json`), so the host's log resolves its entry.
pub(super) const DIAG_NAMES: &[&str] = &["BUSBAR-7108"];

/// The Statement's diagnostic ids, in index order ([`DIAG_NAMES`]).
pub(super) const DIAG_IDS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[busbar_contract::abi::sdk::door::abi_str(DIAG_NAMES[0])];

/// The words of [`UNGOVERNED_LEGACY_STREAM`].
const UNGOVERNED_WORDS: &str =
    "an MCP 2024-11-05 event stream opened on the ungoverned chain: every \
     caller there is one owner, so a session id (which this revision carries in a URL) isolates \
     nothing between callers; govern the deployment to bind each session to its key";

/// The status a session that is not the caller's (unknown, ended, expired, or another owner's) is
/// answered with, on every path.
const STATUS_NOT_FOUND: u32 = 404;
/// The status of a session request whose version header disagrees with its session.
const STATUS_BAD_REQUEST: u32 = 400;
/// The status a session that cannot be opened is answered with.
const STATUS_UNAVAILABLE: u32 = 503;
/// The status of a message accepted and answered elsewhere (a notification, or a `2024-11-05`
/// message whose answer goes on its stream).
const STATUS_ACCEPTED: u32 = 202;

/// The status a held stream past its owner's quota is refused with (as a subscription past its own).
const STATUS_QUOTA: u32 = 429;

/// The most held session streams (`GET`s, the `2024-11-05` stream's included) one owner holds open
/// at once: the per-owner quota, the same bound
/// `subscriptions/listen` holds a caller to. A caller at it is refused its next one; no held stream
/// is evicted for it.
const MAX_STREAMS_PER_OWNER: usize = super::door_listen::MAX_LISTENS_PER_OWNER;

/// The most resource subscriptions one owner holds across its sessions.
const MAX_OWNER_SUBSCRIPTIONS: usize = 256;
/// The ceiling on one retained subscription uri, in bytes.
const MAX_RESOURCE_SUB_URI_BYTES: usize = 2048;
/// The most announced updates a session holds until its stream collects them; past it, the oldest
/// gives way.
const MAX_PENDING_UPDATES: usize = 64;

/// How a session message arrived. A session is carried on the event stream exactly when its
/// revision is the event-stream revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Carriage {
    /// The single endpoint, the session named in `Mcp-Session-Id`.
    Endpoint,
    /// The `2024-11-05` message address, the session named in its query.
    EventStream,
}

/// What a unit is to the session machinery.
#[derive(Debug, Clone)]
pub(super) enum SessionUnit {
    /// A malformed opening message: no session is allocated.
    Rejected(Box<Refusal>),
    /// An opening notification: acknowledged without creating a session or replying.
    Notification,
    /// `initialize` POSTed to the endpoint: it opens a session. `id` is the request's id.
    Open {
        id: Value,
        requested: Option<String>,
    },
    /// A message in `session`, carried as `carriage`, with the version header it carried.
    Message {
        session: String,
        carriage: Carriage,
        header: Option<String>,
        kind: Kind,
        /// The session check passed: its answer is lowered (and, on the `2024-11-05` stream,
        /// delivered there).
        checked: Option<Revision>,
    },
    /// A GET stream: a session's (`Some`), or the `2024-11-05` stream opening (`None`). `mount`
    /// is the path the arrival named, the message address's own.
    Stream {
        session: Option<String>,
        last_event_id: Option<String>,
        mount: String,
        header: Option<String>,
    },
    /// DELETE of `session`.
    Delete {
        session: String,
        header: Option<String>,
    },
    /// A line of a carrier session that negotiated a session revision: its answer is lowered.
    Line,
}

/// What a session message asks.
#[derive(Debug, Clone)]
pub(super) enum Kind {
    /// A method of the one dispatch, raised.
    Dispatch,
    /// Answered here: `ping`, the session's own verbs, `initialize` inside a `2024-11-05` session,
    /// or a method no session revision has.
    Here(Value),
    /// A notification or a client's response: accepted, unanswered.
    Accept(Value),
    /// Refused as it arrived, answered only once the session is the caller's.
    Refused(Box<Refusal>),
}

/// One arrival the session machinery takes.
pub(super) struct Arrival {
    pub(super) unit: SessionUnit,
    /// The raised body the one dispatch decides on; `None` = the unit is answered here.
    pub(super) dispatch: Option<Vec<u8>>,
    /// The head fields the raised body implies: read ahead of the caller's own.
    pub(super) mirror: Vec<(String, String)>,
}

/// What `arrive` makes of an arrival on the endpoint.
pub(super) enum SessionArrived {
    /// The stateless path, untouched.
    Stateless,
    /// `405`.
    NotAllowed,
    /// The session machinery's.
    Session(Box<Arrival>),
}

/// THE OWNER a unit's session is bound to: the kernel's caller reference (derived from the
/// principal's key id), or the ungoverned chain's one constant.
pub(super) fn owner_of(caller: &str) -> Owner {
    let who = super::principal_of(caller);
    Owner {
        principal: who.to_string(),
        credential: who.to_string(),
    }
}

/// READ ONE ARRIVAL on the endpoint (`verb`, `target`, `body`, and a reader over its head fields).
pub(super) fn arrive(
    held: Option<&Held>,
    verb: &str,
    target: &str,
    body: &[u8],
    field: &dyn Fn(&str) -> Option<String>,
) -> SessionArrived {
    let session = field(adapt::H_SESSION_ID).filter(|s| !s.is_empty());
    let (mount, query) = target
        .split_once('?')
        .map_or((target, None), |(p, q)| (p, Some(q)));
    match verb {
        "GET" => {
            let streams = field("accept").is_some_and(|a| a.contains(EVENT_STREAM));
            if !streams {
                return SessionArrived::NotAllowed;
            }
            let opens = session.is_some()
                || revision::sessionless_get_streams(field(H_PROTOCOL_VERSION).as_deref());
            if !opens {
                return SessionArrived::NotAllowed;
            }
            local(SessionUnit::Stream {
                session,
                last_event_id: field(adapt::H_LAST_EVENT_ID),
                mount: mount.to_string(),
                header: field(H_PROTOCOL_VERSION),
            })
        }
        "DELETE" => match session {
            Some(session) => local(SessionUnit::Delete {
                session,
                header: field(H_PROTOCOL_VERSION),
            }),
            None => SessionArrived::NotAllowed,
        },
        "POST" => {
            let value = crate::codec::wire_json::parse(body).ok();
            let message_session = adapt::message_session_of(query).map(str::to_string);
            let kind = match &value {
                Some(v) => adapt::classify_post(v, session.as_deref(), message_session.as_deref()),
                None if message_session.is_some() => adapt::PostKind::EventStreamMessage,
                None if session.is_some() => adapt::PostKind::InSession,
                None => adapt::PostKind::Stateless,
            };
            match (kind, value) {
                (adapt::PostKind::Initialize, Some(v)) => match crate::tool_arrival::request(&v) {
                    Ok(busbar_contract::jsonrpc::Envelope::Request { id, .. }) => {
                        local(SessionUnit::Open {
                            id,
                            requested: v
                                .pointer("/params/protocolVersion")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                        })
                    }
                    Ok(busbar_contract::jsonrpc::Envelope::Notification { .. }) => {
                        local(SessionUnit::Notification)
                    }
                    Err(refusal) => local(SessionUnit::Rejected(Box::new(refusal))),
                },
                (adapt::PostKind::InSession, value) => SessionArrived::Session(message(
                    held,
                    session.unwrap_or_default(),
                    Carriage::Endpoint,
                    field(H_PROTOCOL_VERSION),
                    value,
                )),
                (adapt::PostKind::EventStreamMessage, value) => SessionArrived::Session(message(
                    held,
                    message_session.unwrap_or_default(),
                    Carriage::EventStream,
                    None,
                    value,
                )),
                _ => SessionArrived::Stateless,
            }
        }
        _ => SessionArrived::NotAllowed,
    }
}

/// A unit the session machinery answers itself.
fn local(unit: SessionUnit) -> SessionArrived {
    SessionArrived::Session(Box::new(Arrival {
        unit,
        dispatch: None,
        mirror: Vec::new(),
    }))
}

/// One message in a session: what it asks, and the raised body when the one dispatch answers it.
fn message(
    held: Option<&Held>,
    session: String,
    carriage: Carriage,
    header: Option<String>,
    value: Option<Value>,
) -> Box<Arrival> {
    let unit = |kind| SessionUnit::Message {
        session,
        carriage,
        header,
        kind,
        checked: None,
    };
    let Some(mut value) = value else {
        let refusal = Refusal {
            status: STATUS_BAD_REQUEST,
            id: None,
            code: busbar_contract::jsonrpc::PARSE_ERROR,
            message: crate::tool_arrival::NOT_JSON.to_string(),
            data: None,
        };
        return Box::new(Arrival {
            unit: unit(Kind::Refused(Box::new(refusal))),
            dispatch: None,
            mirror: Vec::new(),
        });
    };
    let envelope = if value.get("method").is_some() {
        crate::tool_arrival::request(&value).map(|_| ())
    } else {
        let id = value
            .get("id")
            .filter(|id| id.is_string() || id.is_number())
            .cloned();
        busbar_contract::jsonrpc::read_response(&value, id.as_ref().unwrap_or(&Value::Null))
            .map(|_| ())
            .map_err(|_| Refusal {
            status: STATUS_BAD_REQUEST,
            id,
            code: CODE_INVALID_REQUEST,
            message: "a session message must be one JSON-RPC 2.0 request, notification or response object".to_string(),
            data: None,
        })
    };
    if let Err(refused) = envelope {
        return Box::new(Arrival {
            unit: unit(Kind::Refused(Box::new(refused))),
            dispatch: None,
            mirror: Vec::new(),
        });
    }
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_string);
    let has_id = value.get("id").is_some_and(|i| !i.is_null());
    let (kind, dispatch, mirror) = match adapt::session_method(method.as_deref(), has_id) {
        SessionMethod::Accept => (Kind::Accept(value), None, Vec::new()),
        SessionMethod::Ping | SessionMethod::Session | SessionMethod::NotFound => {
            (Kind::Here(value), None, Vec::new())
        }
        SessionMethod::Dispatch => match adapt::raise(&mut value) {
            None => (Kind::Here(value), None, Vec::new()),
            Some(()) => {
                let mut mirror: Vec<(String, String)> = crate::codec::mirrored(&value)
                    .into_iter()
                    .filter(|(name, _)| name != "accept")
                    .collect();

                if method.as_deref() == Some(crate::codec::METHOD_TOOLS_CALL) {
                    let schema = value
                        .pointer("/params/name")
                        .and_then(Value::as_str)
                        .and_then(|n| held?.catalogue.tool(n)?.input_schema.clone());
                    let arguments = value.pointer("/params/arguments");
                    for (name, v) in adapt::param_mirror(schema.as_ref(), arguments) {
                        mirror.push((name.to_ascii_lowercase(), v));
                    }
                }
                let dispatch = serde_json::to_vec(&value).unwrap_or_default();
                (Kind::Dispatch, Some(dispatch), mirror)
            }
        },
    };
    Box::new(Arrival {
        unit: unit(kind),
        dispatch,
        mirror,
    })
}

/// The disposition a session unit answered here is decided under, and counted as: an `initialize`
/// or a message answered here is a discovery, a stream holds open as a subscription does, and a
/// DELETE or an accepted message is a notification.
pub(super) fn disposition(unit: &SessionUnit) -> Disposition {
    let request = |method: &str, id: Value| match crate::tool_ops::method_row_for(method) {
        Some(row) => Disposition::Request { row, id },
        None => Disposition::Notice {
            method: String::new(),
        },
    };
    match unit {
        SessionUnit::Rejected(refusal) => {
            request("server/discover", refusal.id.clone().unwrap_or(Value::Null))
        }
        SessionUnit::Notification => Disposition::Notice {
            method: String::new(),
        },
        SessionUnit::Open { id, .. } => request("server/discover", id.clone()),
        SessionUnit::Stream { .. } => request("subscriptions/listen", Value::Null),
        SessionUnit::Message { kind, .. } => match kind {
            Kind::Here(_) | Kind::Refused(_) => request("server/discover", id_of(kind)),
            Kind::Accept(v) => Disposition::Notice {
                method: v
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            },
            Kind::Dispatch => Disposition::Notice {
                method: String::new(),
            },
        },
        SessionUnit::Delete { .. } | SessionUnit::Line => Disposition::Notice {
            method: String::new(),
        },
    }
}

/// A session unit's arrival refused by the one dispatch: answered once the session is the
/// caller's, never before (a mismatch answers `404` on every path).
pub(super) fn refused_in_session(unit: &mut SessionUnit, refusal: &Refusal) -> bool {
    match unit {
        SessionUnit::Message { kind, .. } => {
            *kind = Kind::Refused(Box::new(refusal.clone()));
            true
        }
        _ => false,
    }
}

/// Runs `f` on busbar's memory of its upstream conversations.
fn upstreams(plane: &McpDoor, f: impl FnOnce(&mut UpstreamTable)) {
    plane.upstreams.with(&(), |t| t.map(f));
}

/// The wall clock (ms) and the monotonic clock (ns), both read; `None` when either failed.
fn clocks(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit) -> Option<(u64, u64)> {
    let wall = wall_ms(plane.services, ticket, &mut unit.issued);
    wall.zip(mono_ns(plane.services, ticket, unit))
}

/// The session table.
fn with_sessions<R>(plane: &McpDoor, f: impl FnOnce(&mut Sessions) -> R) -> Option<R> {
    plane.sessions.with(&(), |t| t.map(f))
}

/// OPENS a session for `owner`: 128 bits from the host's CSPRNG (a collision draws again once).
fn open_session(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    owner: &Owner,
    revision: Revision,
    now: u64,
) -> Result<String, (u32, &'static str)> {
    for _ in 0..2 {
        let mut entropy = [0_u8; 16];
        let drawn = plane.services.is_some_and(|s| {
            s.random_fill(handle(ticket, &mut unit.issued, &mut None), &mut entropy)
                .is_ok()
        });
        if !drawn {
            return Err((
                STATUS_UNAVAILABLE,
                "the host's random source did not answer, so no session id can be minted",
            ));
        }
        let opened = with_sessions(plane, |t| t.open(entropy, owner.clone(), revision, now));
        match opened {
            Some(Ok(id)) => return Ok(id),
            Some(Err(OpenRefused::Collision)) => {}
            Some(Err(OpenRefused::NoEntropy)) => {
                return Err((
                    STATUS_UNAVAILABLE,
                    "the host's random source answered no entropy",
                ));
            }
            Some(Err(OpenRefused::OwnerFull)) => {
                return Err((
                    STATUS_QUOTA,
                    "this caller holds as many MCP sessions as this node keeps for one caller, \
                     each with a live stream: end one (DELETE it, or close its stream) and open \
                     again",
                ));
            }
            Some(Err(OpenRefused::Full)) | None => {
                return Err((
                    STATUS_UNAVAILABLE,
                    "this node holds as many MCP sessions as it keeps, and none of this caller's \
                     is idle to give way",
                ));
            }
        }
    }
    Err((STATUS_UNAVAILABLE, "two fresh session ids collided"))
}

/// A JSON-RPC error envelope.
fn rpc_error(id: &Value, code: i64, message: &str) -> Vec<u8> {
    busbar_contract::jsonrpc::error_bytes(&crate::codec::json(id), code, message, None)
}

/// A whole JSON answer.
fn answer_of(status: u32, body: Vec<u8>) -> Pending {
    Pending::answer(status, body, None, &[])
}

/// A `503` naming `why`.
fn unavailable(id: &Value, why: &str) -> Pending {
    answer_of(STATUS_UNAVAILABLE, rpc_error(id, CODE_INTERNAL, why))
}

/// The answer to a session that is not the caller's.
fn not_found(id: &Value) -> Pending {
    answer_of(
        STATUS_NOT_FOUND,
        rpc_error(
            id,
            CODE_REFUSED,
            "Session not found: it ended, expired, or is not this caller's. Send `initialize` \
             without Mcp-Session-Id to open a new one.",
        ),
    )
}

/// The id a session message carries.
fn id_of(kind: &Kind) -> Value {
    match kind {
        Kind::Here(v) | Kind::Accept(v) => v.get("id").cloned().unwrap_or(Value::Null),
        Kind::Refused(r) => r.id.clone().unwrap_or(Value::Null),
        Kind::Dispatch => Value::Null,
    }
}

/// ANSWER A SESSION UNIT on its caller's piece, the session first checked against its owner:
/// `None` for a unit the one dispatch answers (its session checked).
pub(super) fn answer(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
) -> Option<Step> {
    let session_unit = unit.session.clone()?;
    let owner = owner_of(caller);
    if matches!(session_unit, SessionUnit::Line | SessionUnit::Stream { .. }) {
        return None;
    }
    let now = if matches!(
        &session_unit,
        SessionUnit::Rejected(_) | SessionUnit::Notification
    ) {
        0
    } else {
        let Some(now) = wall_ms(plane.services, ticket, &mut unit.issued) else {
            return Some(written(
                unit,
                unavailable(&Value::Null, super::CLOCK_UNREAD),
            ));
        };
        now
    };
    let pending = match session_unit {
        SessionUnit::Rejected(refusal) => answer_of(refusal.status, refusal.body()),
        SessionUnit::Notification => answer_of(STATUS_ACCEPTED, Vec::new()),
        SessionUnit::Line | SessionUnit::Stream { .. } => return None,
        SessionUnit::Open { id, requested } => {
            open_endpoint(plane, ticket, unit, &owner, &id, requested.as_deref(), now)
        }
        SessionUnit::Delete { session, header } => {
            let revision = with_sessions(plane, |t| t.revision(&session, &owner, now)).flatten();
            let Some(revision) = revision else {
                return Some(written(unit, not_found(&Value::Null)));
            };
            if revision.is_event_stream_revision() {
                return Some(written(unit, not_found(&Value::Null)));
            }
            if revision::header_disagrees(revision, header.as_deref()) {
                return Some(written(
                    unit,
                    answer_of(
                        STATUS_BAD_REQUEST,
                        rpc_error(
                            &Value::Null,
                            CODE_INVALID_REQUEST,
                            "The MCP-Protocol-Version header names another revision than this session's.",
                        ),
                    ),
                ));
            }
            if with_sessions(plane, |t| t.close(&session, &owner, now)) == Some(true) {
                plane.session_state.remove(&session);

                due(plane, &session);
                answer_of(200, Vec::new())
            } else {
                not_found(&Value::Null)
            }
        }
        SessionUnit::Message {
            session,
            carriage,
            header,
            kind,
            ..
        } => {
            let held = with_sessions(plane, |t| t.revision(&session, &owner, now))
                .flatten()
                .filter(|r| r.is_event_stream_revision() == (carriage == Carriage::EventStream));
            let Some(revision) = held else {
                return Some(written(unit, not_found(&id_of(&kind))));
            };
            if revision::header_disagrees(revision, header.as_deref()) {
                let body = rpc_error(
                    &id_of(&kind),
                    CODE_INVALID_REQUEST,
                    "The MCP-Protocol-Version header names another revision than this session's.",
                );
                return Some(written(unit, answer_of(STATUS_BAD_REQUEST, body)));
            }
            if let Some(SessionUnit::Message { checked, .. }) = unit.session.as_mut() {
                *checked = Some(revision);
            }
            match kind {
                Kind::Dispatch => return None,
                Kind::Accept(_) => answer_of(STATUS_ACCEPTED, Vec::new()),
                Kind::Refused(r) => answer_of(r.status, r.body()),
                Kind::Here(v) => {
                    let body = here(
                        plane,
                        ticket,
                        unit,
                        (session.as_str(), &owner),
                        revision,
                        &v,
                    );
                    answer_of(200, body)
                }
            }
        }
    };
    Some(written(unit, pending))
}

/// `pending` kept as the unit's answer.
fn written(unit: &mut CallUnit, pending: Pending) -> Step {
    unit.pending = Some(pending);
    Step::Write
}

/// The discovery document this caller is entitled to, as `initialize` answers from it.
fn discovery(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit, id: &Value) -> Option<Value> {
    let held = unit.held.clone().or_else(|| plane.current())?;
    ask_entitlements(plane.services, ticket, unit, &held.catalogue.grants());
    let document = crate::answer::discover(&held.catalogue, id, &admit(&unit.entitled));
    crate::codec::wire_json::parse(&document)
        .ok()?
        .get("result")
        .cloned()
}

/// `initialize` on the endpoint: the revision negotiation picks, a session opened in it.
fn open_endpoint(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    owner: &Owner,
    id: &Value,
    requested: Option<&str>,
    now: u64,
) -> Pending {
    let revision = match revision::negotiate(requested) {
        r if r.is_event_stream_revision() => revision::SESSION_REVISIONS[0],
        r => r,
    };
    let Some(discovered) = discovery(plane, ticket, unit, id) else {
        return unavailable(id, "this node publishes no MCP catalogue yet");
    };
    let session = match open_session(plane, ticket, unit, owner, revision, now) {
        Ok(session) => session,
        Err((status, why)) => return answer_of(status, rpc_error(id, CODE_REFUSED, why)),
    };
    let result = adapt::initialize_result(&discovered, revision);
    let body = busbar_contract::jsonrpc::result_bytes(
        &crate::codec::json(id),
        &crate::codec::json(&result),
    );
    let mut pending = answer_of(200, body);
    pending
        .fields
        .push((adapt::H_SESSION_ID.to_string(), session));
    pending
}

/// A message the session answers itself.
fn here(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    (session, owner): (&str, &Owner),
    revision: Revision,
    value: &Value,
) -> Vec<u8> {
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let method = value.get("method").and_then(Value::as_str).unwrap_or("");
    let ok = |result: Value| {
        busbar_contract::jsonrpc::result_bytes(
            &crate::codec::json(&id),
            &crate::codec::json(&result),
        )
    };
    let invalid = |message: &str| rpc_error(&id, CODE_INVALID_PARAMS, message);
    let uri = value.pointer("/params/uri").and_then(Value::as_str);
    match method {
        adapt::METHOD_PING => ok(json!({})),

        adapt::METHOD_INITIALIZE if revision.is_event_stream_revision() => {
            match discovery(plane, ticket, unit, &id) {
                Some(d) => ok(adapt::initialize_result(&d, revision)),
                None => rpc_error(
                    &id,
                    CODE_INTERNAL,
                    "this node publishes no MCP catalogue yet",
                ),
            }
        }
        adapt::METHOD_INITIALIZE => rpc_error(
            &id,
            CODE_INVALID_REQUEST,
            "this session is already open: send `initialize` without Mcp-Session-Id to open \
             another",
        ),
        "resources/subscribe" => {
            let Some(uri) = uri else {
                return invalid("`params.uri` is required: the resource to watch.");
            };
            if uri.len() > MAX_RESOURCE_SUB_URI_BYTES {
                return invalid(
                    "`params.uri` is longer than a session retains: a subscription is held for \
                     the session, so it is bounded.",
                );
            }
            let Some(held) = unit.held.clone().or_else(|| plane.current()) else {
                return invalid("this node publishes no MCP catalogue yet");
            };
            ask_entitlements(plane.services, ticket, unit, &held.catalogue.grants());
            let admit = admit(&unit.entitled);
            if !matches!(held.catalogue.resource_by_uri(&admit, uri), Lookup::One(_)) {
                return invalid("`params.uri` names no resource this caller may read.");
            }
            if subscribe(plane, session, owner, uri) {
                ok(json!({}))
            } else {
                invalid(
                    "this caller already holds as many resource subscriptions as this node \
                     watches for it: unsubscribe from one before subscribing to another.",
                )
            }
        }
        "resources/unsubscribe" => {
            let Some(uri) = uri else {
                return invalid("`params.uri` is required: the resource to stop watching.");
            };
            plane.session_state.with(&session.to_string(), |s| {
                if let Some(s) = s {
                    s.uris.retain(|u| u != uri);
                }
            });
            ok(json!({}))
        }
        "logging/setLevel" => {
            let level = value.pointer("/params/level").and_then(Value::as_str);
            match level.filter(|l| crate::framing::SEVERITIES.contains(l)) {
                Some(level) => {
                    state_of(plane, session, owner, |s| s.level = Some(level.to_string()));
                    ok(json!({}))
                }
                None => invalid(
                    "`params.level` must name an RFC 5424 severity: the floor this session's \
                     `notifications/message` records are filtered at.",
                ),
            }
        }
        _ => rpc_error(
            &id,
            CODE_METHOD_NOT_FOUND,
            &format!("Method `{method}` is not implemented by this server for this revision."),
        ),
    }
}

/// A session's own state: its owner, the resources it watches, its log floor, and the updates
/// announced for it its stream has not collected.
#[derive(Debug, Clone, Default)]
pub(super) struct SessionState {
    owner: Option<Owner>,
    uris: Vec<String>,
    level: Option<String>,
    updates: VecDeque<(String, String)>,
}

/// Runs `f` on `session`'s state, made for `owner` when it has none.
fn state_of(plane: &McpDoor, session: &str, owner: &Owner, f: impl FnOnce(&mut SessionState)) {
    plane.session_state.with_all(|m| {
        let s = m.entry(session.to_string()).or_default();
        s.owner.get_or_insert_with(|| owner.clone());
        f(s);
    });
}

/// Subscribes `session` to `uri`: `false` past the owner's subscription quota.
fn subscribe(plane: &McpDoor, session: &str, owner: &Owner, uri: &str) -> bool {
    plane.session_state.with_all(|m| {
        if m.get(session)
            .is_some_and(|s| s.uris.iter().any(|u| u == uri))
        {
            return true;
        }
        let held: usize = m
            .values()
            .filter(|s| s.owner.as_ref() == Some(owner))
            .map(|s| s.uris.len())
            .sum();
        if held >= MAX_OWNER_SUBSCRIPTIONS {
            return false;
        }
        let s = m.entry(session.to_string()).or_default();
        s.owner.get_or_insert_with(|| owner.clone());
        s.uris.push(uri.to_string());
        true
    })
}

/// AN UPSTREAM ANNOUNCED that `uri` of its registration `server` changed: every session watching
/// that uri holds it until its stream collects it, where the subscriber's entitlement is asked
/// again (Listen's relay rule: the uri resolves under its live grant to the announcing server's
/// declared resource).
pub(super) fn announce(plane: &McpDoor, server: &str, uri: &str) {
    let sessions: Vec<String> = plane.session_state.with_all(|m| {
        let mut hit = Vec::new();
        for (session, s) in m.iter_mut() {
            if s.uris.iter().any(|u| u == uri) {
                if s.updates.len() >= MAX_PENDING_UPDATES {
                    s.updates.pop_front();
                }
                s.updates.push_back((server.to_string(), uri.to_string()));
                hit.push(session.clone());
            }
        }
        hit
    });
    for session in sessions {
        due(plane, &session);
    }

    door_listen::announced(plane, server, uri);
}

/// THE RATE LIMIT on an upstream's list-changed notifications: at most one is accepted per server
/// in this window (monotonic ms). Its timing is all busbar reads of it, and an accepted one only
/// makes the next call re-fetch, so the window bounds how often an upstream can make busbar fetch.
pub const LIST_CHANGED_MIN_INTERVAL_MS: u64 = 30_000;

/// AN UPSTREAM SAID ITS LISTS CHANGED (`notifications/{tools,prompts,resources}/list_changed`):
/// accepted under [`LIST_CHANGED_MIN_INTERVAL_MS`], it marks `server`'s list stale, so the next
/// call re-verifies against the authoritative `tools/list`. The body is never read; nothing is
/// installed, approved or promoted. A clock that cannot be read never suppresses one: stale is the
/// safe direction.
pub(super) fn list_changed(plane: &McpDoor, server: &str, now_ms: Option<u64>) {
    let key = server.to_string();
    if let (Some(now), Some(last)) = (now_ms, plane.list_noticed.get(&key)) {
        if now >= last && now - last < LIST_CHANGED_MIN_INTERVAL_MS {
            return;
        }
    }
    if let Some(now) = now_ms {
        plane.list_noticed.insert(key.clone(), now);
    }
    plane
        .checked
        .with_all(|m| m.retain(|(_, name), _| name != server));
}

/// WHAT AN UPSTREAM SAID ON ITS EVENT STREAM beside a relayed call's answer: its resource updates
/// are announced to every watching session, its list-changed notifications mark its list stale
/// ([`list_changed`], at `mono_ms`), and, for a caller in a session, its log records past the
/// session's floor are delivered on that session's stream.
pub(super) fn heard(
    plane: &McpDoor,
    server: &str,
    raw: &[u8],
    session: Option<(&str, &Owner, u64)>,
    mono_ms: Option<u64>,
) {
    let mut reader = crate::client::compat::EventReader::new(raw.len());
    for event in reader.feed(raw) {
        let data = event.data;
        let Ok(frame) = crate::codec::wire_json::parse_str(&data) else {
            continue;
        };
        match frame.get("method").and_then(Value::as_str) {
            Some("notifications/resources/updated") => {
                if let Some(uri) = frame.pointer("/params/uri").and_then(Value::as_str) {
                    announce(plane, server, uri);
                }
            }
            Some(
                "notifications/tools/list_changed"
                | "notifications/prompts/list_changed"
                | "notifications/resources/list_changed",
            ) => list_changed(plane, server, mono_ms),
            Some("notifications/message") => {
                let Some((id, owner, now)) = session else {
                    continue;
                };
                let floor = plane
                    .session_state
                    .with(&id.to_string(), |s| s.and_then(|s| s.level.clone()));
                let level = frame.pointer("/params/level").and_then(Value::as_str);
                let rank = crate::framing::severity_of;
                let Some(level) = level.and_then(rank) else {
                    tracing::warn!(
                        "MCP upstream log notification carried no recognized severity; it was not relayed"
                    );
                    continue;
                };
                let passes = match floor.as_deref().and_then(rank) {
                    Some(floor) => level >= floor,
                    None => true,
                };

                if passes {
                    let _delivered = deliver_frame(plane, id, owner, data.trim(), now);
                }
            }
            _ => {}
        }
    }
}

/// The session a unit's caller is in, when it is in one whose check passed.
pub(super) fn session_of(unit: &Option<SessionUnit>) -> Option<String> {
    match unit {
        Some(SessionUnit::Message {
            session,
            checked: Some(_),
            ..
        }) => Some(session.clone()),
        _ => None,
    }
}

/// LOWERS the answer a session unit's dispatch wrote, before its first byte: the session
/// revision's shape (a result no session revision can carry becomes an error), every JSON-RPC
/// dispatch answer at `200` (a malformed message keeps its refusal status); on the `2024-11-05` stream, the answer goes on the stream and the POST is
/// accepted (`202`).
pub(super) fn lower(plane: &McpDoor, ticket: Ticket, caller: &str, unit: &mut CallUnit) {
    let malformed = matches!(
        &unit.session,
        Some(SessionUnit::Message {
            kind: Kind::Refused(_),
            ..
        })
    );
    let (line, legacy) = match &unit.session {
        Some(SessionUnit::Message {
            checked: Some(_),
            carriage,
            session,
            ..
        }) => (
            false,
            (*carriage == Carriage::EventStream).then(|| session.clone()),
        ),
        Some(SessionUnit::Line) => (true, None),
        _ => return,
    };
    let lowerable = unit.pending.as_ref().is_some_and(|p| {
        !p.headed && p.request.is_none() && (p.local.is_some() || !p.bytes.is_empty())
    });
    if !lowerable {
        return;
    }
    let now = match legacy {
        Some(_) => wall_ms(plane.services, ticket, &mut unit.issued),
        None => Some(0),
    };
    let Some(pending) = unit.pending.as_mut() else {
        return;
    };

    let Some(now) = now else {
        replace_wire_answer(pending, unavailable(&Value::Null, super::CLOCK_UNREAD));
        return;
    };

    if pending.local.is_some() {
        if let Some(session) = legacy {
            let local = pending
                .local
                .take()
                .and_then(|mut output| output.take_json());
            let id = local
                .as_ref()
                .map(|local| local.id().clone())
                .unwrap_or(Value::Null);
            let delivered = match local
                .map(|local| {
                    deliver_data(plane, &session, &owner_of(caller), Data::Local(local), now)
                })
                .transpose()
            {
                Ok(delivered) => delivered.unwrap_or(false),
                Err(()) => {
                    replace_wire_answer(
                        pending,
                        unavailable(&id, "the local answer could not be buffered"),
                    );
                    return;
                }
            };
            if delivered {
                pending.bytes.clear();
                pending.fields.clear();
                pending.status = STATUS_ACCEPTED;
            } else {
                replace_wire_answer(pending, not_found(&id));
            }
        } else if !line {
            pending.status = 200;
        }
        return;
    }
    let Ok(v) = crate::codec::wire_json::parse(&pending.bytes) else {
        return;
    };
    let rpc = v.get("jsonrpc").is_some() && (v.get("result").is_some() || v.get("error").is_some());

    let bytes = match adapt::lower_answer(&pending.bytes) {
        None => return,
        Some(adapt::Lowered::Unchanged) => std::mem::take(&mut pending.bytes),
        Some(adapt::Lowered::Spliced(bytes)) => bytes,
        Some(adapt::Lowered::Inexpressible) => {
            let id = v.get("id").cloned().unwrap_or(Value::Null);
            busbar_contract::jsonrpc::error_bytes(
                &crate::codec::json(&id),
                CODE_REFUSED,
                "this answer asks for input or names a task, which this session's MCP revision \
                 cannot carry",
                None,
            )
        }
    };
    if line {
        pending.bytes = bytes;
        return;
    }
    match legacy {
        Some(session) => {
            let delivered = deliver_frame(
                plane,
                &session,
                &owner_of(caller),
                &String::from_utf8_lossy(&bytes),
                now,
            );

            if delivered {
                pending.bytes.clear();
                pending.fields.clear();
                pending.status = STATUS_ACCEPTED;
            } else {
                replace_wire_answer(
                    pending,
                    not_found(&v.get("id").cloned().unwrap_or(Value::Null)),
                );
            }
        }
        None => {
            if rpc && !malformed {
                pending.status = 200;
            }
            for (name, value) in &mut pending.fields {
                if name.as_str() == CONTENT_LENGTH {
                    *value = bytes.len().to_string();
                }
            }
            pending.bytes = bytes;
        }
    }
}

fn replace_wire_answer(pending: &mut Pending, answer: Pending) {
    pending.status = answer.status;
    pending.fields = answer.fields;
    pending.bytes = answer.bytes;
    pending.local = answer.local;

    pending
        .units
        .retain(|u| u.class != crate::statement::CLASS_FEE_INDEX);
}

/// One held GET stream, by its unit.
#[derive(Debug, Clone)]
pub(super) struct Stream {
    session: String,
    owner: Owner,
    /// The session table's stream the events are buffered on.
    stream: u32,
    /// The last event seq written to the caller.
    delivered: u64,
    /// The `2024-11-05` stream (no event ids).
    legacy: bool,
    /// The session's caller-side ticket.
    ticket: Ticket,
    /// The stream owes a collection.
    due: bool,
    /// When it last wrote (the host's monotonic clock).
    last_write_ns: u64,
}

/// Whether `unit` is a held session stream (its pieces are this module's).
pub(super) fn holds(plane: &McpDoor, unit: u64) -> bool {
    plane.units.with(&unit, |u| {
        u.is_some_and(|u| matches!(u.session, Some(SessionUnit::Stream { .. })))
    })
}

/// `data` buffered on `session`'s stream, and the stream named due: `false` when no live stream
/// took it.
fn deliver_frame(plane: &McpDoor, session: &str, owner: &Owner, data: &str, now: u64) -> bool {
    let target = plane
        .streams
        .with_all(|m| m.values().find(|s| s.session == session).map(|s| s.stream));
    let Some(stream) = target else {
        return false;
    };
    let pushed = with_sessions(plane, |t| t.push(session, owner, stream, data, now))
        .flatten()
        .is_some();
    if pushed {
        due(plane, session);
    }
    pushed
}

fn deliver_data(
    plane: &McpDoor,
    session: &str,
    owner: &Owner,
    data: Data,
    now: u64,
) -> Result<bool, ()> {
    let target = plane
        .streams
        .with_all(|m| m.values().find(|s| s.session == session).map(|s| s.stream));
    let Some(stream) = target else {
        return Ok(false);
    };
    let pushed = with_sessions(plane, |t| {
        t.push_prepared(session, owner, stream, data, history_data, now)
            .map(|id| id.is_some())
    })
    .unwrap_or(Ok(false))?;
    if pushed {
        due(plane, session);
    }
    Ok(pushed)
}

/// Every stream of `session` named due, and the driver woken.
fn due(plane: &McpDoor, session: &str) {
    let any = plane.streams.with_all(|m| {
        let mut any = false;
        for s in m.values_mut().filter(|s| s.session == session) {
            s.due = true;
            any = true;
        }
        any
    });
    if any {
        door_listen::wake_driver(plane);
    }
}

/// The streams owing a collection.
pub(super) fn due_streams(plane: &McpDoor) -> Vec<u64> {
    plane
        .streams
        .with_all(|m| m.iter().filter(|(_, s)| s.due).map(|(k, _)| *k).collect())
}

/// The streams named to the host: no longer owing.
pub(super) fn taken(plane: &McpDoor, named: &[u64]) {
    plane.streams.with_all(|m| {
        for key in named {
            if let Some(s) = m.get_mut(key) {
                s.due = false;
            }
        }
    });
}

/// THE TICK: every held stream owes a collection (its keepalive, or its end once its session is
/// gone), and the state of every session the table no longer holds is dropped.
pub(super) fn tick(plane: &McpDoor) {
    let any = plane.streams.with_all(|m| {
        for s in m.values_mut() {
            s.due = true;
        }
        !m.is_empty()
    });
    let gone: Vec<String> = plane
        .session_state
        .with_all(|m| m.keys().cloned().collect());
    let gone: Vec<String> = gone
        .into_iter()
        .filter(|id| with_sessions(plane, |t| !t.holds(id)).unwrap_or(true))
        .collect();
    plane.session_state.with_all(|m| {
        for id in &gone {
            m.remove(id);
        }
    });
    if any {
        door_listen::wake_driver(plane);
    }
}

/// The op on `ticket` was cancelled: the stream it carried is ended.
pub(super) fn cancelled(plane: &McpDoor, ticket: Ticket) {
    let keys: Vec<u64> = plane.streams.with_all(|m| {
        m.iter()
            .filter(|(_, s)| s.ticket == ticket)
            .map(|(k, _)| *k)
            .collect()
    });
    for key in keys {
        end_stream(plane, key);
    }
}

/// ENDS the held stream of unit `key`: it is no longer live work, so its cursor (kept for a
/// resuming GET) and its session may give way again.
fn end_stream(plane: &McpDoor, key: u64) -> Option<Stream> {
    let ended = plane.streams.remove(&key)?;
    with_sessions(plane, |t| {
        t.release_stream(&ended.session, ended.stream);

        if ended.legacy {
            t.end(&ended.session);
        }
    });
    if ended.legacy {
        plane.session_state.remove(&ended.session);
    }
    Some(ended)
}

/// What an idle stream writes to say it is alive.
const KEEPALIVE: &[u8] = b": keepalive\n\n";

/// ONE PIECE OF A HELD SESSION STREAM: the caller's piece opens it, a collection writes what its
/// session buffered (or a keepalive, or its end), and the caller's side ending ends it.
pub(super) fn piece(
    plane: &McpDoor,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> Outcome {
    let given = input;
    let (key, ticket) = (given.unit(), given.head().ticket());
    let caller = input.caller_ref().as_str().unwrap_or_default().to_string();
    let owner = owner_of(&caller);
    let mut say_ungoverned = false;
    let step = plane.units.with(&key, |unit| {
        let unit = unit?;
        unit.ticket = Some(ticket);
        if unit.pending.is_some() {
            return Some(true);
        }
        match given.from() {
            FROM_CALLER if given.flags() & PIECE_LAST != 0 => {
                end_stream(plane, key);
                unit.pending = Some(door_listen::frame(Vec::new(), true, true));
                Some(true)
            }
            FROM_CALLER => {
                let (wrote, legacy_ungoverned) = open_stream(plane, ticket, &owner, unit)?;
                say_ungoverned = legacy_ungoverned;
                Some(wrote)
            }
            FROM_KERNEL if given.attempt_no() == 0 => step_stream(plane, ticket, unit),
            FROM_KERNEL => Some(false),
            _ => None,
        }
    });

    if say_ungoverned {
        plane.said_ungoverned.with_all(|said| {
            if !said.contains_key(&())
                && out.diag(UNGOVERNED_LEGACY_STREAM, SEVERITY_WARN, UNGOVERNED_WORDS)
            {
                said.insert((), ());
            }
        });
    }
    match step {
        None => Outcome::Refused,
        Some(false) => Outcome::Ready,
        Some(true) => {
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
                    end_stream(plane, key);
                    Outcome::Ready
                }
            }
        }
    }
}

/// The events after a stream's cursor, framed without expanding local results.
fn frames(events: Vec<(String, Data)>, legacy: bool) -> (crate::local_output::Output, Option<u64>) {
    let mut output = crate::local_output::Output::default();
    let mut last = None;
    for (id, data) in events {
        let id_word = (!legacy).then_some(id.as_str());
        match data {
            Data::Text(text) => {
                output.bytes(adapt::frame(id_word, Some(adapt::EVENT_MESSAGE), &text).into_bytes())
            }
            Data::Local(local) => output.event(local, id_word),
        }
        last = id.split_once('-').and_then(|(_, q)| q.parse().ok());
    }
    (output, last)
}

fn stream_frame(output: crate::local_output::Output, headed: bool) -> Pending {
    let mut pending = door_listen::frame(Vec::new(), false, headed);
    pending.local = Some(output);
    pending
}

fn stream_bytes(bytes: Vec<u8>) -> crate::local_output::Output {
    let mut output = crate::local_output::Output::default();
    output.bytes(bytes);
    output
}

/// OPENS the stream the unit's GET asks for: `(wrote, an ungoverned 2024-11-05 stream)`.
fn open_stream(
    plane: &McpDoor,
    ticket: Ticket,
    owner: &Owner,
    unit: &mut CallUnit,
) -> Option<(bool, bool)> {
    let Some(SessionUnit::Stream {
        session,
        last_event_id,
        mount,
        header,
    }) = unit.session.clone()
    else {
        return None;
    };
    if plane.streams.with(&unit.key, |s| s.is_some()) {
        return Some((false, false));
    }

    let held = plane
        .streams
        .with_all(|m| m.values().filter(|s| s.owner == *owner).count());
    if held >= MAX_STREAMS_PER_OWNER {
        let refusal = Refusal {
            status: STATUS_QUOTA,
            id: None,
            code: CODE_REFUSED,
            message: format!(
                "this caller holds {MAX_STREAMS_PER_OWNER} open MCP session streams, the most one \
                 caller may hold; close one and open again"
            ),
            data: Some(json!({ "reason": "stream_quota" })),
        };
        unit.pending = Some(Pending::answer(refusal.status, refusal.body(), None, &[]));
        return Some((true, false));
    }
    let Some((now, mono)) = clocks(plane, ticket, unit) else {
        unit.pending = Some(unavailable(&Value::Null, super::CLOCK_UNREAD));
        return Some((true, false));
    };
    let ungoverned = owner.principal == crate::ask::UNGOVERNED;
    let (session, stream, delivered, legacy, output) = match session {
        None => {
            let opened = open_session(plane, ticket, unit, owner, Revision::R2024_11_05, now);
            let session = match opened {
                Ok(session) => session,
                Err((status, why)) => {
                    let body = rpc_error(&Value::Null, CODE_REFUSED, why);
                    unit.pending = Some(answer_of(status, body));
                    return Some((true, false));
                }
            };
            let Some(stream) =
                with_sessions(plane, |t| t.open_stream(&session, owner, now)).flatten()
            else {
                with_sessions(plane, |t| t.close(&session, owner, now));
                plane.session_state.remove(&session);
                unit.pending = Some(unavailable(
                    &Value::Null,
                    "the new MCP session could not open its stream",
                ));
                return Some((true, false));
            };
            let endpoint = adapt::endpoint_event(&mount, &session);
            (
                session,
                stream,
                0,
                true,
                stream_bytes(endpoint.into_bytes()),
            )
        }
        Some(session) => {
            let revision = with_sessions(plane, |t| t.revision(&session, owner, now)).flatten();
            if !revision.is_some_and(|r| !r.is_event_stream_revision()) {
                unit.pending = Some(not_found(&Value::Null));
                return Some((true, false));
            }
            if revision
                .is_some_and(|revision| revision::header_disagrees(revision, header.as_deref()))
            {
                unit.pending = Some(answer_of(
                    STATUS_BAD_REQUEST,
                    rpc_error(
                        &Value::Null,
                        CODE_INVALID_REQUEST,
                        "The MCP-Protocol-Version header names another revision than this session's.",
                    ),
                ));
                return Some((true, false));
            }
            let cursor_seq = last_event_id
                .as_deref()
                .and_then(|cursor| cursor.split_once('-'))
                .and_then(|(_, sequence)| sequence.parse::<u64>().ok());
            let resumed = last_event_id
                .as_deref()
                .and_then(|cursor| with_sessions(plane, |t| t.replay(&session, owner, cursor, now)))
                .flatten();
            match resumed {
                Some(replay) => {
                    let (output, last) = frames(replay.events, false);
                    let delivered = last.or(cursor_seq).unwrap_or(0);
                    let output = if output.done() {
                        stream_bytes(KEEPALIVE.to_vec())
                    } else {
                        output
                    };
                    (session, replay.stream, delivered, false, output)
                }
                None => {
                    let opened =
                        with_sessions(plane, |t| t.open_stream(&session, owner, now)).flatten();

                    let Some(stream) = opened else {
                        let refusal = Refusal {
                            status: STATUS_QUOTA,
                            id: None,
                            code: CODE_REFUSED,
                            message: "this MCP session holds as many open streams as a session \
                                      keeps; close one and open again"
                                .to_string(),
                            data: Some(json!({ "reason": "stream_quota" })),
                        };
                        unit.pending =
                            Some(Pending::answer(refusal.status, refusal.body(), None, &[]));
                        return Some((true, false));
                    };
                    (session, stream, 0, false, stream_bytes(KEEPALIVE.to_vec()))
                }
            }
        }
    };

    with_sessions(plane, |t| t.hold_stream(&session, stream));

    plane.streams.insert(
        unit.key,
        Stream {
            session,
            owner: owner.clone(),
            stream,
            delivered,
            legacy,
            ticket,
            due: false,
            last_write_ns: mono,
        },
    );
    unit.pending = Some(stream_frame(output, false));
    Some((true, legacy && ungoverned))
}

/// ONE COLLECTION of a held stream: the updates announced for its session (each re-judged under
/// the caller's live grants), then every event buffered after its cursor; a keepalive when quiet;
/// its end once its session is gone.
fn step_stream(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit) -> Option<bool> {
    let held_stream = plane.streams.get(&unit.key)?;

    let Some((now, mono)) = clocks(plane, ticket, unit) else {
        return Some(false);
    };
    if door_listen::standing(plane, ticket, &held_stream.owner.principal, unit)
        != crate::subscribe::Standing::Live
    {
        end_stream(plane, unit.key);
        unit.pending = Some(door_listen::frame(Vec::new(), true, true));
        return Some(true);
    }
    let held = plane.current().or_else(|| unit.held.clone());
    let updates: Vec<(String, String)> = if held.is_some() {
        plane
            .session_state
            .with(&held_stream.session, |s| {
                s.map(|s| s.updates.drain(..).collect::<Vec<_>>())
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if !updates.is_empty() {
        if let Some(held) = held {
            door_listen::entitled_afresh(plane, ticket, unit, &held);
            let admit = admit(&unit.entitled);
            for (server, uri) in updates {
                let theirs = matches!(
                    held.catalogue.resource_by_uri(&admit, &uri),
                    Lookup::One(entry) if entry.server == server
                );
                if theirs {
                    let note = json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/updated",
                        "params": { "uri": uri },
                    });
                    with_sessions(plane, |t| {
                        t.push(
                            &held_stream.session,
                            &held_stream.owner,
                            held_stream.stream,
                            &note.to_string(),
                            now,
                        )
                    });
                }
            }
        }
    }
    let cursor = format!("{}-{}", held_stream.stream, held_stream.delivered);
    let replay = with_sessions(plane, |t| {
        t.replay(&held_stream.session, &held_stream.owner, &cursor, now)
    })
    .flatten();
    let Some(replay) = replay else {
        end_stream(plane, unit.key);
        unit.pending = Some(door_listen::frame(Vec::new(), true, true));
        return Some(true);
    };
    let (output, last) = frames(replay.events, held_stream.legacy);
    let output = if !output.done() {
        output
    } else if mono.saturating_sub(held_stream.last_write_ns) >= crate::subscribe::KEEPALIVE_NS {
        stream_bytes(KEEPALIVE.to_vec())
    } else {
        return Some(false);
    };
    plane.streams.with(&unit.key, |s| {
        if let Some(s) = s {
            if let Some(last) = last {
                s.delivered = last;
            }
            s.last_write_ns = mono;
        }
    });
    unit.pending = Some(stream_frame(output, true));
    Some(true)
}

/// How many connector handles one hop of a negotiation may number.
pub(super) const HOP_SPAN: u32 = 1 << 9;

/// What busbar remembers about the conversation `key` names ([`crate::tool_sessions::upstream_key`]:
/// a member and the caller binding it was negotiated for), and the next request id of its session.
fn remembered(plane: &McpDoor, key: &str) -> (Option<Remembered>, Option<u64>) {
    plane
        .upstreams
        .with(&(), |t| t.map(|t| (t.get(key), t.next_id(key))))
        .unwrap_or((None, None))
}

/// One hop's answer as the connector read it: its status, its head fields (lower-case names) and
/// its body.
type Hop = (u16, Vec<(String, String)>, Vec<u8>);

/// What a negotiation came to.
pub(super) enum Negotiated {
    /// The answer to hand on: the status, the body as the upstream sent it, and whether it is an
    /// event stream.
    Answer(u16, Vec<u8>, bool, Option<u64>),
    /// No answer: why, in words, for the caller's upstream-failure answer.
    Failed(String),
}

/// ONE UPSTREAM CONVERSATION, NEGOTIATED ([`Negotiator`]), parked on its unit across PENDING
/// entries: the action under way, the hops sent, and what the answers so far said.
#[derive(Debug)]
pub(super) struct Negotiating {
    negotiator: Negotiator,
    /// The exact id of the current HTTP hop, including initialize and session renumbering.
    reply_id: Option<Value>,
    list_pages: Option<crate::client::jsonrpc::ToolPages>,
    next: Option<Action>,
    hops: u32,
    /// The first hop is the stateless request, not yet answered.
    probing: bool,
    /// The upstream answered the stateless revision before: it is not renegotiated.
    stateless_known: bool,
    /// The walk's answer was fed (a resumed FAR-END piece carries it again).
    pub(super) fed: bool,
    /// The session the walk's answer named (its head crosses with its first piece).
    pub(super) walk_session: Option<String>,
    /// The last answer's body as sent, and whether it is an event stream.
    raw: (Vec<u8>, bool),
    /// The conversation's key: the member and the caller binding it is negotiated for. What busbar
    /// learns is kept under it, so one caller's session is never another's.
    key: String,
    /// The upstream is known to speak only the `2024-11-05` event stream: the walk's refusal of the
    /// stateless request goes straight to the held stream ([`super::door_legacy`]).
    legacy_known: bool,
    /// The call's place on the held stream, while it waits there.
    legacy: Option<super::door_legacy::Calling>,
    /// The id the call carried on the held stream, once answered.
    legacy_id: Option<u64>,
    /// Replies no call waited for on the held stream, dropped since its last answer.
    dropped: u32,
    /// The statuses of the hops that refused, for the words of a failure.
    refused: Vec<u16>,
    /// Why the last hop had no answer at all.
    failure: Option<String>,
}

impl Negotiating {
    /// A conversation carrying `original` (a stateless request) to `member` for the caller bound
    /// as `binding` (the caller reference the kernel lends; empty for the ungoverned chain), and the
    /// request its first hop is: `original` itself, or lowered into the session busbar remembers
    /// for that member AND that caller, under that session's own next id.
    pub(super) fn begin(
        plane: &McpDoor,
        member: &str,
        binding: &str,
        original: OutboundRequest,
    ) -> Self {
        let key = crate::tool_sessions::upstream_key(member, binding);
        let (remembered, session_id) = remembered(plane, &key);

        let original = match session_id {
            Some(_) => original,
            None => with_progress_token(plane, original),
        };
        let stateless_known = remembered
            .as_ref()
            .is_some_and(|r| r.revision == Revision::R2026_07_28);
        let legacy_known = remembered
            .as_ref()
            .is_some_and(|r| r.revision.is_event_stream_revision());

        let probing = legacy_known
            || !remembered
                .as_ref()
                .is_some_and(|r| r.revision.has_sessions());
        let mut negotiator =
            Negotiator::new(original, remembered, super::VERSION).with_session_id(session_id);
        let first = negotiator.start();
        let reply_id = match &first {
            Action::Send { request } => request_id(request),
            _ => None,
        };
        Negotiating {
            negotiator,
            reply_id,
            list_pages: None,
            next: Some(first),
            hops: 0,
            probing,
            stateless_known,
            fed: false,
            walk_session: None,
            raw: (Vec::new(), false),
            key,
            legacy_known,
            legacy: None,
            legacy_id: None,
            dropped: 0,
            refused: Vec::new(),
            failure: None,
        }
    }

    /// The id the conversation's request carried in a session, when it is not the original's.
    pub(super) fn sent_id(&self) -> Option<u64> {
        self.negotiator.sent_id().or(self.legacy_id)
    }

    /// Replies no call waited for on the call's held stream, dropped since its last answer: each
    /// is audited on this call's answer, rejected.
    pub(super) fn dropped(&self) -> u32 {
        self.dropped
    }

    /// The request the first hop sends, when it is one.
    pub(super) fn first_request(&self) -> Option<&OutboundRequest> {
        match &self.next {
            Some(Action::Send { request }) => Some(request),
            _ => None,
        }
    }

    /// Feeds one hop's answer (`None`: none at all) and answers the next action.
    fn feed(&mut self, answer: Option<Hop>) -> Action {
        let probing = std::mem::replace(&mut self.probing, false);
        let Some((status, fields, body)) = answer else {
            return self.negotiator.on_answer(None);
        };
        let sse = fields
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case(CONTENT_TYPE) && v.starts_with(EVENT_STREAM));
        let (json, raw) = if sse {
            let json = match &self.reply_id {
                Some(id) => crate::call::answer_body(&body, true, id),
                None => crate::call::last_sse_data(&body),
            };
            (json, body)
        } else {
            (body, Vec::new())
        };
        self.raw = (raw, sse);
        let hop = HopAnswer {
            status,
            fields,
            body: json,
        };

        if probing && self.legacy_known {
            return if (200..300).contains(&status) {
                Action::Finish(hop)
            } else {
                Action::OpenStream
            };
        }

        if probing && (self.stateless_known || matches!(status, 401 | 403 | 407 | 429)) {
            return Action::Finish(hop);
        }
        if !(200..300).contains(&status) {
            self.refused.push(status);
        }
        self.negotiator.on_answer(Some(hop))
    }

    /// DRIVES the conversation over the door's connector, hop by hop, from `base`: PENDING while a
    /// hop pends (the action kept), READY with what it came to. What busbar learnt is kept for the
    /// next call to `member`.
    fn drive(
        &mut self,
        instance: &Instance<'_, McpDoor, busbar_contract::plugin::markers::PlaneKind>,
        plane: &McpDoor,
        base: u32,
        member: &str,
        timeout_ms: u64,
    ) -> Poll<Negotiated> {
        loop {
            match self.next.take() {
                Some(Action::Send { request }) => {
                    self.reply_id = request_id(&request);
                    if self.list_pages.is_some() && self.hops >= super::ROUND_SEQ_SPAN / HOP_SPAN {
                        return Poll::Ready(Negotiated::Failed("the complete tool list exceeds this fetch's existing service-handle range".to_string()));
                    }
                    let at = base.saturating_add(self.hops.saturating_mul(HOP_SPAN));
                    let polled = exchange_at(
                        instance,
                        plane.host.as_ref(),
                        at,
                        &request.url,
                        member,
                        || exchange_request(&request, timeout_ms),
                    );
                    let Poll::Ready(answered) = polled else {
                        self.next = Some(Action::Send { request });
                        return Poll::Pending;
                    };
                    self.hops += 1;
                    let answered = match answered {
                        Ok(r) => Some((
                            r.status,
                            r.fields
                                .iter()
                                .map(|(n, v)| {
                                    (
                                        String::from_utf8_lossy(n).to_ascii_lowercase(),
                                        String::from_utf8_lossy(v).into_owned(),
                                    )
                                })
                                .collect(),
                            r.body,
                        )),
                        Err(e) => {
                            self.failure = Some(e.to_string());
                            None
                        }
                    };
                    self.next = Some(self.feed(answered));
                }
                Some(Action::Finish(answer)) => {
                    self.keep(plane);
                    let (raw, sse) = std::mem::take(&mut self.raw);
                    let raw = if raw.is_empty() { answer.body } else { raw };
                    return Poll::Ready(Negotiated::Answer(
                        answer.status,
                        raw,
                        sse,
                        self.negotiator.sent_id(),
                    ));
                }
                Some(Action::Fail(refusal)) => {
                    self.keep(plane);
                    return Poll::Ready(self.failed(&refusal, member));
                }

                Some(Action::OpenStream)
                    if plane.host.as_ref().is_some_and(|h| h.lends_connector()) =>
                {
                    if self.list_pages.is_some() && self.hops >= super::ROUND_SEQ_SPAN / HOP_SPAN {
                        return Poll::Ready(Negotiated::Failed("the complete tool list exceeds this fetch's existing service-handle range".to_string()));
                    }
                    let at = base.saturating_add(self.hops.saturating_mul(HOP_SPAN));
                    let original = self.negotiator.original().clone();
                    let called = super::door_legacy::call(
                        instance,
                        plane,
                        (&self.key, member),
                        &original,
                        &mut self.legacy,
                        (at, timeout_ms),
                    );
                    match called {
                        Poll::Pending => {
                            self.next = Some(Action::OpenStream);
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok((body, sse, id, dropped))) => {
                            self.hops += 1;
                            self.dropped = dropped;
                            self.legacy_id = Some(id);
                            let legacy = Remembered {
                                revision: Revision::R2024_11_05,
                                session: None,
                            };
                            upstreams(plane, |t| t.put(&self.key, legacy));
                            return Poll::Ready(Negotiated::Answer(200, body, sse, Some(id)));
                        }
                        Poll::Ready(Err(why)) => {
                            upstreams(plane, |t| t.forget(&self.key));
                            return Poll::Ready(Negotiated::Failed(why));
                        }
                    }
                }

                Some(Action::OpenStream) | None => {
                    self.keep(plane);
                    return Poll::Ready(Negotiated::Failed(self.legacy_only(member)));
                }
            }
        }
    }

    /// What busbar learnt, kept (or forgotten) for the next call to the same member by the same
    /// caller.
    fn keep(&self, plane: &McpDoor) {
        upstreams(plane, |t| match self.negotiator.remembered() {
            Some(r) => t.put(&self.key, r),
            None => t.forget(&self.key),
        });
    }

    /// The words of an upstream that refused every revision busbar carries as a client.
    fn legacy_only(&self, member: &str) -> String {
        let statuses: Vec<String> = self.refused.iter().map(u16::to_string).collect();
        format!(
            "MCP server `{member}` refused the stateless {PROTOCOL_VERSION} request and refused \
             `initialize` (HTTP {}); the one revision left is 2024-11-05 (HTTP+SSE), whose event \
             stream busbar holds over the connector, and none is lent here",
            statuses.join(", ")
        )
    }

    /// A failed conversation, in words; an answer it did get is handed on as it came.
    fn failed(&mut self, refusal: &Refused, member: &str) -> Negotiated {
        match refusal {
            Refused::Unreachable(Some(answer)) => {
                let (raw, sse) = std::mem::take(&mut self.raw);
                let raw = if raw.is_empty() {
                    answer.body.clone()
                } else {
                    raw
                };
                Negotiated::Answer(answer.status, raw, sse, self.negotiator.sent_id())
            }
            Refused::Unreachable(None) => Negotiated::Failed(
                self.failure
                    .clone()
                    .unwrap_or_else(|| format!("MCP server `{member}` could not be reached")),
            ),
            Refused::OfferedUnsupported => Negotiated::Failed(format!(
                "MCP server `{member}` answered `initialize` with an MCP revision busbar does not \
                 carry as a client (it carries 2025-11-25 and 2025-06-18 on a session)"
            )),
        }
    }
}

/// One hop as the connector's exchange sends it.
pub(super) fn exchange_request(
    request: &OutboundRequest,
    timeout_ms: u64,
) -> busbar_contract::abi::sdk::exchange::Request {
    busbar_contract::abi::sdk::exchange::Request {
        method: b"POST".to_vec(),

        target: crate::call::path_of(&request.url).into_bytes(),
        fields: request
            .headers
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect(),
        body: request.body.clone(),
        timeout_ms,
    }
}

/// A FETCH OF THE DOOR'S OWN (verify-on-call's `tools/list`), negotiated: every hop over the
/// connector from `base`, the conversation parked on the unit while one pends.
pub(super) fn fetch_in(
    instance: &Instance<'_, McpDoor, busbar_contract::plugin::markers::PlaneKind>,
    plane: &McpDoor,
    slot: &mut Option<Box<Negotiating>>,
    (base, member, binding, timeout_ms): (u32, &str, &str, u64),
    original: OutboundRequest,
) -> Poll<Result<busbar_contract::abi::sdk::exchange::ExchangeResponse, String>> {
    use crate::client::jsonrpc::{parse_response_id, Paged, RpcOutcome, ToolPages};
    let original_id = crate::codec::wire_json::parse(&original.body)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(Value::Null);
    loop {
        let negotiating = slot.get_or_insert_with(|| {
            Box::new(Negotiating::begin(plane, member, binding, original.clone()))
        });
        negotiating
            .list_pages
            .get_or_insert_with(ToolPages::default);
        let Poll::Ready(done) = negotiating.drive(instance, plane, base, member, timeout_ms) else {
            return Poll::Pending;
        };
        super::door_legacy::recount(plane, &negotiating.key, negotiating.dropped);
        let response = match done {
            Negotiated::Answer(status, ..) if (300..400).contains(&status) => Err(format!(
                "the upstream answered HTTP {status}, a redirect; busbar never follows one, and nothing it carried is read"
            )),
            Negotiated::Answer(status, raw, sse, sent) => {
                let body = if sse {
                    let sent_id = sent.map(Value::from).unwrap_or_else(|| original_id.clone());
                    crate::call::answer_body(&raw, true, &sent_id)
                } else {
                    raw
                };
                Ok(busbar_contract::abi::sdk::exchange::ExchangeResponse {
                    status,
                    body: match sent {
                        Some(sent) => with_id(body, sent, original_id.clone()),
                        None => body,
                    },
                    ..Default::default()
                })
            }
            Negotiated::Failed(reason) => Err(reason),
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                *slot = None;
                return Poll::Ready(Err(error));
            }
        };
        if !(200..300).contains(&response.status) {
            *slot = None;
            return Poll::Ready(Err(format!(
                "the upstream answered HTTP {}; no complete tool list was received",
                response.status
            )));
        }
        if let RpcOutcome::Result(result) = parse_response_id(&response.body, &original_id) {
            let mut pages = negotiating
                .list_pages
                .take()
                .expect("a list fetch retains its pages");
            match pages.take(result) {
                Ok(Paged::Next(cursor)) => {
                    let request =
                        match crate::client::jsonrpc::next_list_request(&original, &cursor) {
                            Ok(request) => request,
                            Err(error) => {
                                *slot = None;
                                return Poll::Ready(Err(error));
                            }
                        };
                    let hops = negotiating.hops;
                    let mut next = Negotiating::begin(plane, member, binding, request);
                    next.hops = hops;
                    next.list_pages = Some(pages);
                    **negotiating = next;
                    continue;
                }
                Ok(Paged::Done(result)) => {
                    let body = if pages.pages() == 1 {
                        response.body
                    } else {
                        busbar_contract::jsonrpc::result_bytes(
                            &crate::codec::json(&original_id),
                            &crate::codec::json(&result),
                        )
                    };
                    *slot = None;
                    return Poll::Ready(Ok(
                        busbar_contract::abi::sdk::exchange::ExchangeResponse { body, ..response },
                    ));
                }
                Err(error) => {
                    *slot = None;
                    return Poll::Ready(Err(error));
                }
            }
        }
        *slot = None;
        return Poll::Ready(Ok(response));
    }
}

fn request_id(request: &OutboundRequest) -> Option<Value> {
    crate::codec::wire_json::parse(&request.body)
        .ok()?
        .get("id")
        .cloned()
}

/// `request` with the progress token it carries (when it asks for progress at all) replaced by one
/// no other request of this instance carries: `busbar-` and an id from the instance's one counter.
fn with_progress_token(plane: &McpDoor, mut request: OutboundRequest) -> OutboundRequest {
    let Ok(mut body) = crate::codec::wire_json::parse(&request.body) else {
        return request;
    };
    let Some(token) = body
        .pointer_mut("/params/_meta/progressToken")
        .filter(|t| !t.is_null())
    else {
        return request;
    };
    let Some(n) = plane.upstreams.with(&(), |t| t.map(|t| t.take_id())) else {
        return request;
    };
    *token = Value::from(format!("busbar-{n}"));
    if let Ok(bytes) = serde_json::to_vec(&body) {
        request.body = bytes;
    }
    request
}

/// `body` (one JSON-RPC answer) with its top-level `id` put back to `id` when it is `sent`, the
/// id the request carried in its session: the answer as the request that asked it is correlated.
fn with_id(body: Vec<u8>, sent: u64, id: serde_json::Value) -> Vec<u8> {
    let Ok(mut doc) = crate::codec::wire_json::parse(&body) else {
        return body;
    };
    match doc.as_object_mut() {
        Some(obj) if obj.get("id") == Some(&serde_json::Value::from(sent)) => {
            obj.insert("id".to_string(), id);
            serde_json::to_vec(&doc).unwrap_or(body)
        }
        _ => body,
    }
}

/// THE WALK'S ANSWER to a relayed call's first hop (`status`, event stream or not, `far`), and the
/// conversation from there: READY with what it came to, `None` when the answer is handed on as it
/// came (the stateless path, or no connector to negotiate over).
pub(super) fn far_answer(
    instance: &Instance<'_, McpDoor, busbar_contract::plugin::markers::PlaneKind>,
    plane: &McpDoor,
    negotiating: &mut Negotiating,
    (base, member, timeout_ms): (u32, &str, u64),
    (status, sse, far): (u32, bool, &[u8]),
) -> Poll<Option<Negotiated>> {
    if !negotiating.fed {
        negotiating.fed = true;
        let mut fields = Vec::new();
        if sse {
            fields.push((CONTENT_TYPE.to_string(), EVENT_STREAM.to_string()));
        }
        if let Some(session) = negotiating.walk_session.clone() {
            fields.push((adapt::H_SESSION_ID.to_string(), session));
        }
        let status = u16::try_from(status).unwrap_or(0);
        let next = negotiating.feed(Some((status, fields, far.to_vec())));

        let lends = plane.host.is_some_and(|h| h.lends_connector());
        match next {
            Action::Finish(_) => {
                negotiating.keep(plane);
                return Poll::Ready(None);
            }
            Action::Send { .. } if !lends => return Poll::Ready(None),
            next => negotiating.next = Some(next),
        }
    }
    negotiating
        .drive(instance, plane, base, member, timeout_ms)
        .map(Some)
}

/// The stateless request a relayed call's outbound is, for its negotiation.
pub(super) fn original(url: &str, outbound: &crate::call::OutboundCall) -> OutboundRequest {
    OutboundRequest {
        url: url.to_string(),
        headers: outbound.fields.clone(),
        body: outbound.body.clone(),
    }
}

#[cfg(test)]
#[path = "tests/local_history.rs"]
mod local_history;

#[cfg(test)]
#[path = "tests/door_sessions_audit.rs"]
mod door_sessions_audit;
