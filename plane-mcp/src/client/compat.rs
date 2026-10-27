// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLIENT HALF OF THE SESSION REVISIONS: how busbar, calling an upstream that does not speak
//! the stateless `2026-07-28` revision, speaks `2025-11-25`, `2025-06-18` or `2024-11-05`. A request
//! is built once, stateless, and LOWERED here ([`lower_request`]); the answers are read back for
//! the ladder ([`super::negotiate`]). Pure: no I/O, no clock, no randomness.

use serde_json::Value;

use super::jsonrpc::OutboundRequest;
use crate::adapt::H_SESSION_ID;
use crate::codec::{
    CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND,
    CODE_UNSUPPORTED_PROTOCOL_VERSION, H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION,
    META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION,
};
use crate::revision::{Revision, StepOutcome};

/// The id busbar's own `initialize` carries: `2^53 - 1`, the largest integer a JavaScript peer
/// reads back exactly, above every other id busbar sends.
pub const INITIALIZE_ID: u64 = (1 << 53) - 1;

/// Reads what a stateless request's answer says about the upstream's revision.
///
/// A status in `400..500`, or a JSON-RPC error that says the method, the request shape or the
/// revision is not understood, is a refusal of the revision and moves the ladder. A `5xx`, or no
/// answer, says nothing about the revision. Anything else answered.
#[must_use]
pub fn probe_outcome(status: u16, body: &[u8]) -> StepOutcome {
    if (500..600).contains(&status) {
        return StepOutcome::Unreachable;
    }
    if (400..500).contains(&status) {
        return StepOutcome::Refused4xx;
    }
    let code = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.pointer("/error/code").and_then(Value::as_i64));
    match code {
        Some(c)
            if c == CODE_METHOD_NOT_FOUND
                || c == CODE_INVALID_REQUEST
                || c == CODE_INVALID_PARAMS
                || c == CODE_UNSUPPORTED_PROTOCOL_VERSION =>
        {
            StepOutcome::Refused4xx
        }
        _ => StepOutcome::Answered,
    }
}

/// Reads what the answer to busbar's STATELESS request says about the upstream's revision: the
/// ladder moves only on a refusal that names the revision or a session, and any other answer, an
/// upstream's own JSON-RPC error included, is the stateless path's answer, handed on as it came (THE
/// DESIGN section 2, the mcp bullet: the stateless path of the `2026-07-28` revision stays
/// byte-identical).
///
/// A refusal of the revision is what a server of an earlier revision answers a request that opens
/// no session:
///
/// - a `4xx` whose body is no JSON-RPC error: a `2024-11-05` server's `404`/`405` at its event
///   stream's endpoint, a session server's bare `400` or `404` for the session it was not named;
/// - a `405`, whatever its body: the endpoint takes no POST;
/// - a JSON-RPC error `-32022` (the revision is unsupported), at any status;
/// - a JSON-RPC error whose message names the session or the initialization the request skipped
///   (`Bad Request: No valid session ID provided`, `Server not initialized`), at any status.
///
/// A `5xx`, or no answer, says nothing about the revision.
#[must_use]
pub fn stateless_outcome(status: u16, body: &[u8]) -> StepOutcome {
    if (500..600).contains(&status) {
        return StepOutcome::Unreachable;
    }
    let error = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").filter(|e| e.is_object()).cloned());
    let Some(error) = error else {
        return if (400..500).contains(&status) {
            StepOutcome::Refused4xx
        } else {
            StepOutcome::Answered
        };
    };
    let code = error.get("code").and_then(Value::as_i64);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let names_session = message.contains("session") || message.contains("initializ");
    if status == 405 || code == Some(CODE_UNSUPPORTED_PROTOCOL_VERSION) || names_session {
        StepOutcome::Refused4xx
    } else {
        StepOutcome::Answered
    }
}

/// The `initialize` request (id [`INITIALIZE_ID`]), sent to `url` with the credential `template`
/// carries. `client_version` is the caller's own version string.
#[must_use]
pub fn initialize_request(
    template: &OutboundRequest,
    url: &str,
    asked: Revision,
    client_version: &str,
) -> OutboundRequest {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": INITIALIZE_ID,
        "method": crate::adapt::METHOD_INITIALIZE,
        "params": {
            "protocolVersion": asked.wire(),
            "capabilities": {},
            "clientInfo": { "name": "busbar", "version": client_version },
        },
    });
    session_envelope(template, url, &body, None, None)
}

/// `notifications/initialized`, completing the opening of `revision`'s session.
#[must_use]
pub fn initialized_notification(
    template: &OutboundRequest,
    url: &str,
    revision: Revision,
    session: Option<&str>,
) -> OutboundRequest {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": crate::adapt::METHOD_INITIALIZED,
    });
    session_envelope(template, url, &body, Some(revision), session)
}

/// The revision an `initialize` answer names, when this plane can carry it. `None` is an upstream
/// busbar must not continue with: the spec's rule for a client offered a revision it cannot speak.
#[must_use]
pub fn offered_revision(body: &[u8]) -> Option<Revision> {
    let v: Value = serde_json::from_slice(body).ok()?;
    crate::revision::accept_offered(v.pointer("/result/protocolVersion")?.as_str()?)
}

/// LOWERS a stateless request into `revision`: the stateless `_meta` members go (a session
/// revision states them once, in `initialize`), the stateless mirror headers go, the version
/// header names `revision` (where the revision has one) and the session header names `session`.
/// The URL is `url` (the endpoint, or a `2024-11-05` message address). The credential and every
/// other header `req` carries are kept. `id`, when given, replaces the request's own (a session's
/// own next id: a session revision forbids reusing one).
#[must_use]
pub fn lower_request(
    req: &OutboundRequest,
    url: &str,
    revision: Revision,
    session: Option<&str>,
    id: Option<u64>,
) -> OutboundRequest {
    let mut body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    if let (Some(id), Some(obj)) = (id, body.as_object_mut()) {
        obj.insert("id".to_string(), Value::from(id));
    }
    if let Some(params) = body.get_mut("params").and_then(Value::as_object_mut) {
        let empty = params
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
            .map(|meta| {
                meta.remove(META_PROTOCOL_VERSION);
                meta.remove(META_CLIENT_CAPABILITIES);
                meta.is_empty()
            })
            .unwrap_or(false);
        if empty {
            params.remove("_meta");
        }
    }
    session_envelope(req, url, &body, Some(revision), session)
}

/// The shared session-revision envelope: `template`'s headers without the stateless mirror, plus
/// the version and session headers `revision` and `session` call for.
fn session_envelope(
    template: &OutboundRequest,
    url: &str,
    body: &Value,
    revision: Option<Revision>,
    session: Option<&str>,
) -> OutboundRequest {
    let mut headers: Vec<(String, String)> = template
        .headers
        .iter()
        .filter(|(k, _)| {
            k != H_PROTOCOL_VERSION
                && k != H_MCP_METHOD
                && k != H_MCP_NAME
                && k != H_SESSION_ID
                && !k.starts_with("mcp-param-")
        })
        .cloned()
        .collect();
    if let Some(r) = revision.filter(|r| r.requires_version_header()) {
        headers.push((H_PROTOCOL_VERSION.to_string(), r.wire().to_string()));
    }
    if let Some(s) = session {
        headers.push((H_SESSION_ID.to_string(), s.to_string()));
    }
    OutboundRequest {
        url: url.to_string(),
        headers,
        body: serde_json::to_vec(body).unwrap_or_default(),
    }
}

/// Why a `2024-11-05` stream's message address was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressRefused {
    /// The address names another origin than the registered endpoint's. Following it would let
    /// the upstream point busbar's POSTs, credential and all, at a host the operator never
    /// registered.
    CrossOrigin,
    /// The address is not a path or an absolute address busbar can read.
    Malformed,
}

/// The `(scheme, authority)` of an absolute address, or `None`.
fn origin_of(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if scheme.is_empty() || authority.is_empty() {
        return None;
    }
    Some((scheme, authority))
}

/// THE MESSAGE ADDRESS a `2024-11-05` stream's `endpoint` event names, resolved against the
/// registered endpoint `base`. A path is joined to `base`'s origin; an absolute address must have
/// exactly `base`'s origin. Anything else is refused.
///
/// # Errors
/// [`AddressRefused`] for another origin or an unreadable address.
pub fn message_address(base: &str, event_data: &str) -> Result<String, AddressRefused> {
    let data = event_data.trim();
    if data.is_empty() || data.chars().any(char::is_whitespace) || data.starts_with("//") {
        return Err(AddressRefused::Malformed);
    }
    let (scheme, authority) = origin_of(base).ok_or(AddressRefused::Malformed)?;
    if data.starts_with('/') {
        return Ok(format!("{scheme}://{authority}{data}"));
    }
    match origin_of(data) {
        Some(o) if o.0.eq_ignore_ascii_case(scheme) && o.1.eq_ignore_ascii_case(authority) => {
            Ok(data.to_string())
        }
        Some(_) => Err(AddressRefused::CrossOrigin),
        None => Err(AddressRefused::Malformed),
    }
}

/// One event read off an event stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamEvent {
    /// The `event:` name, when the event named one.
    pub event: Option<String>,
    /// The `data:` lines, joined with `\n`.
    pub data: String,
}

/// AN INCREMENTAL EVENT-STREAM READER: bytes in, whole events out, the unfinished tail kept.
/// Bounded: a tail that grows past `max_pending` bytes without completing an event is dropped and
/// [`Self::overflowed`] says so, so a peer that never ends an event cannot grow busbar's memory.
#[derive(Debug)]
pub struct EventReader {
    pending: Vec<u8>,
    max_pending: usize,
    overflowed: bool,
}

impl EventReader {
    /// A reader holding at most `max_pending` bytes of an unfinished event.
    #[must_use]
    pub fn new(max_pending: usize) -> Self {
        Self {
            pending: Vec::new(),
            max_pending,
            overflowed: false,
        }
    }

    /// Whether an unfinished event was ever dropped for exceeding the bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Feeds `chunk` and returns every event it completed, in order. Comment lines and events with
    /// neither a name nor data are skipped.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<StreamEvent> {
        // A carriage return only ever ends a line here, so it is dropped as it arrives and every
        // line end reads as `\n`.
        self.pending
            .extend(chunk.iter().copied().filter(|b| *b != b'\r'));
        let mut out = Vec::new();
        while let Some(end) = self.pending.windows(2).position(|w| w == b"\n\n") {
            let raw: Vec<u8> = self.pending.drain(..end + 2).collect();
            let raw = String::from_utf8_lossy(&raw[..end]);
            let mut event = StreamEvent {
                event: None,
                data: String::new(),
            };
            let mut data: Vec<&str> = Vec::new();
            for line in raw.lines() {
                if line.starts_with(':') {
                    continue;
                }
                let (field, value) = line.split_once(':').unwrap_or((line, ""));
                let value = value.strip_prefix(' ').unwrap_or(value);
                match field {
                    "event" => event.event = Some(value.to_string()),
                    "data" => data.push(value),
                    _ => {}
                }
            }
            event.data = data.join("\n");
            if event.event.is_some() || !event.data.is_empty() {
                out.push(event);
            }
        }
        if self.pending.len() > self.max_pending {
            self.pending.clear();
            self.overflowed = true;
        }
        out
    }
}

#[cfg(test)]
#[path = "tests/compat_tests.rs"]
mod tests;
