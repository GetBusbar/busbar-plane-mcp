// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLIENT HALF OF THE SESSION REVISIONS: how busbar, calling an upstream that does not speak
//! the stateless `2026-07-28` revision, speaks `2025-11-25`, `2025-06-18` or `2024-11-05`. A request
//! is built once, stateless, and LOWERED here ([`lower_request`]); the answers are read back for
//! the ladder ([`super::negotiate`]). Pure: no I/O, no clock, no randomness.

use serde_json::Value;

use super::jsonrpc::OutboundRequest;
use crate::adapt::H_SESSION_ID;
use crate::codec::json;
use crate::codec::{
    CODE_HEADER_MISMATCH, CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND,
    CODE_MISSING_CLIENT_CAPABILITY, CODE_REFUSED, CODE_UNSUPPORTED_PROTOCOL_VERSION, H_MCP_METHOD,
    H_MCP_NAME, H_PROTOCOL_VERSION, META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION,
};
use crate::revision::{Revision, StepOutcome};

/// The id busbar's own `initialize` carries: `2^53 - 1`, the largest integer a JavaScript peer
/// reads back exactly, above every other id busbar sends.
pub const INITIALIZE_ID: u64 = (1 << 53) - 1;

/// Reads whether an initialize response permits trying the older HTTP+SSE transport.
/// Only the transport detection statuses (400, 404, 405) or an unrecognized initialization
/// refusal move the ladder. Recognized modern errors and other HTTP refusals do not.
#[must_use]
pub fn probe_outcome(status: u16, body: &[u8]) -> StepOutcome {
    if (500..600).contains(&status) {
        return StepOutcome::Unreachable;
    }
    if modern_error(body).is_some()
        || (status == 404
            && crate::codec::wire_json::parse(body)
                .ok()
                .as_ref()
                .and_then(response_error)
                == Some(CODE_METHOD_NOT_FOUND))
    {
        return StepOutcome::Answered;
    }
    if matches!(status, 400 | 404 | 405) {
        return StepOutcome::Refused4xx;
    }
    if (400..500).contains(&status) {
        return StepOutcome::Answered;
    }
    let code = crate::codec::wire_json::parse(body)
        .ok()
        .and_then(|v| v.pointer("/error/code").and_then(Value::as_i64));
    match code {
        Some(c)
            if c == CODE_METHOD_NOT_FOUND
                || c == CODE_INVALID_REQUEST
                || c == CODE_INVALID_PARAMS =>
        {
            StepOutcome::Refused4xx
        }
        _ => StepOutcome::Answered,
    }
}

/// A recognized modern protocol error, independent of the transport status. These codes
/// establish the peer's era; they must never trigger an initialization fallback.
fn modern_error(body: &[u8]) -> Option<i64> {
    let value: Value = crate::codec::wire_json::parse(body).ok()?;
    let code = response_error(&value)?;
    matches!(
        code,
        CODE_HEADER_MISMATCH | CODE_MISSING_CLIENT_CAPABILITY | CODE_UNSUPPORTED_PROTOCOL_VERSION
    )
    .then_some(code)
}

fn response_error(value: &Value) -> Option<i64> {
    if value.get("jsonrpc")?.as_str()? != "2.0" || value.get("result").is_some() {
        return None;
    }
    let error = value.get("error")?;
    error.get("message")?.as_str()?;
    error.get("code")?.as_i64()
}

/// Classifies a stateless request's response without discarding modern protocol errors.
/// A recognized modern error establishes the peer's era and is handed back for correction,
/// including HTTP 404/-32601. Only an unrecognized 400/404/405, or a known missing-session
/// response from an older implementation, permits initialization. Authentication, rate-limit
/// and other application refusals are terminal; 5xx or no answer is not a revision signal.
#[must_use]
pub fn stateless_outcome(status: u16, body: &[u8]) -> StepOutcome {
    if (500..600).contains(&status) {
        return StepOutcome::Unreachable;
    }
    let value = crate::codec::wire_json::parse(body).ok();
    if modern_error(body).is_some()
        || (status == 404 && value.as_ref().and_then(response_error) == Some(CODE_METHOD_NOT_FOUND))
    {
        return StepOutcome::Answered;
    }
    if matches!(status, 400 | 404 | 405) {
        return StepOutcome::Refused4xx;
    }
    if (400..500).contains(&status) {
        return StepOutcome::Answered;
    }
    let error = value.and_then(|v| v.get("error").filter(|e| e.is_object()).cloned());
    let Some(error) = error else {
        return StepOutcome::Answered;
    };
    let code = error.get("code").and_then(Value::as_i64);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let names_session = matches!(
        code,
        Some(CODE_INVALID_REQUEST | CODE_INVALID_PARAMS | CODE_REFUSED)
    ) && matches!(
        message.trim().trim_end_matches('.'),
        "server not initialized"
            | "server is not initialized"
            | "not initialized"
            | "bad request: no valid session id provided"
            | "no valid session id provided"
            | "missing session id"
            | "session id is required"
            | "invalid session id"
    );
    if names_session {
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
    let params = serde_json::json!({
        "protocolVersion": asked.wire(),
        "capabilities": {},
        "clientInfo": { "name": "busbar", "version": client_version },
    });
    let body = busbar_contract::jsonrpc::request_bytes(
        &json(&INITIALIZE_ID),
        crate::adapt::METHOD_INITIALIZE,
        Some(&json(&params)),
    );
    session_envelope(template, url, body, None, None)
}

/// `notifications/initialized`, completing the opening of `revision`'s session.
#[must_use]
pub fn initialized_notification(
    template: &OutboundRequest,
    url: &str,
    revision: Revision,
    session: Option<&str>,
) -> OutboundRequest {
    let body = busbar_contract::jsonrpc::notification_bytes(crate::adapt::METHOD_INITIALIZED, None);
    session_envelope(template, url, body, Some(revision), session)
}

/// The revision an `initialize` answer names, when this plane can carry it. `None` is an upstream
/// busbar must not continue with: the spec's rule for a client offered a revision it cannot speak.
#[must_use]
pub fn offered_revision(body: &[u8]) -> Option<Revision> {
    let v: Value = crate::codec::wire_json::parse(body).ok()?;
    let busbar_contract::jsonrpc::Reply::Result(result) =
        busbar_contract::jsonrpc::read_response(&v, &Value::from(INITIALIZE_ID)).ok()?
    else {
        return None;
    };
    crate::revision::accept_offered(result.get("protocolVersion")?.as_str()?)
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
    let mut body: Value = crate::codec::wire_json::parse(&req.body).unwrap_or(Value::Null);
    if let (Some(id), Some(obj)) = (id, body.as_object_mut()) {
        obj.insert("id".to_string(), Value::from(id));

        if let Some(token) = obj
            .get_mut("params")
            .and_then(|p| p.get_mut("_meta"))
            .and_then(|m| m.get_mut("progressToken"))
            .filter(|t| !t.is_null())
        {
            *token = Value::from(super::jsonrpc::progress_token(&Value::from(id)));
        }
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
    session_envelope(req, url, json(&body), Some(revision), session)
}

/// The shared session-revision envelope: `template`'s headers without the stateless mirror, plus
/// the version and session headers `revision` and `session` call for.
fn session_envelope(
    template: &OutboundRequest,
    url: &str,
    body: Vec<u8>,
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
        body,
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

/// THE MESSAGE ADDRESS a `2024-11-05` stream's `endpoint` event names, resolved against the
/// registered endpoint `base`. A path is joined to `base`'s origin; an absolute address must have
/// exactly `base`'s origin. Anything else is refused.
///
/// # Errors
/// [`AddressRefused`] for another origin or an unreadable address.
pub fn message_address(base: &str, event_data: &str) -> Result<String, AddressRefused> {
    let data = event_data.trim();
    if data.is_empty()
        || data
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
        || data.starts_with("//")
    {
        return Err(AddressRefused::Malformed);
    }
    let base = url::Url::parse(base).map_err(|_| AddressRefused::Malformed)?;
    let address = base.join(data).map_err(|_| AddressRefused::Malformed)?;
    if !matches!(address.scheme(), "http" | "https")
        || !address.username().is_empty()
        || address.password().is_some()
        || address.fragment().is_some()
    {
        return Err(AddressRefused::Malformed);
    }
    if base.origin() != address.origin() {
        return Err(AddressRefused::CrossOrigin);
    }
    Ok(address.into())
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
///
/// Lines end as the event-stream grammar ends them: CRLF, a lone LF or a lone CR. A CR ends its
/// line as it arrives (an LF right after it, in this chunk or the next, is the rest of that one
/// terminator), so an event whose blank line is `\r\r` is handed on at once, never held for a byte
/// the far end may not send.
///
/// Bounded: retained fields plus the unfinished line may hold at most `max_pending` bytes.
/// Completed comments and ignored fields release their budget. An oversized retained event or
/// unfinished line is dropped and [`Self::overflowed`] says so.
#[derive(Debug)]
pub struct EventReader {
    /// The current line, its terminator not yet seen.
    line: Vec<u8>,
    /// The unfinished event's `event:` name.
    event: Option<String>,
    /// The unfinished event's joined `data:` lines, with their trailing newline until dispatch.
    data: String,
    has_data: bool,
    first_line: bool,
    /// Retained event fields plus the current unfinished line.
    held: usize,
    /// The last byte ended a line with a CR: an LF next is the rest of that CRLF.
    after_cr: bool,
    max_pending: usize,
    overflowed: bool,
}

impl EventReader {
    /// A reader holding at most `max_pending` bytes of an unfinished event.
    #[must_use]
    pub fn new(max_pending: usize) -> Self {
        Self {
            line: Vec::new(),
            event: None,
            data: String::new(),
            has_data: false,
            first_line: true,
            held: 0,
            after_cr: false,
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
        let mut out = Vec::new();
        if self.overflowed {
            return out;
        }
        for &b in chunk {
            if std::mem::take(&mut self.after_cr) && b == b'\n' {
                continue;
            }
            self.held = self.held.saturating_add(1);
            if self.held > self.max_pending {
                self.line.clear();
                self.event = None;
                self.data.clear();
                self.has_data = false;
                self.held = 0;
                self.overflowed = true;
                break;
            }
            match b {
                b'\r' => {
                    self.after_cr = true;
                    self.end_line(&mut out);
                }
                b'\n' => self.end_line(&mut out),
                _ => self.line.push(b),
            }
        }
        out
    }

    /// A blank line dispatches an event only if at least one data field was read; other lines
    /// update retained fields or are ignored.
    fn end_line(&mut self, out: &mut Vec<StreamEvent>) {
        if std::mem::take(&mut self.first_line) && self.line.starts_with(&[0xef, 0xbb, 0xbf]) {
            drop(self.line.drain(..3));
        }
        if self.line.is_empty() {
            let event = self.event.take();
            let mut data = std::mem::take(&mut self.data);
            let has_data = std::mem::take(&mut self.has_data);
            if has_data {
                data.pop();
            }
            if has_data {
                out.push(StreamEvent { event, data });
            }
            self.held = 0;
            return;
        }
        let line = String::from_utf8_lossy(&self.line).into_owned();
        self.line.clear();
        if line.starts_with(':') {
            self.held = self.data.len() + self.event.as_ref().map_or(0, String::len);
            return;
        }
        let (field, value) = line.split_once(':').unwrap_or((&line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => self.event = (!value.is_empty()).then(|| value.to_string()),
            "data" => {
                self.data.push_str(value);
                self.data.push('\n');
                self.has_data = true;
            }
            _ => {}
        }
        self.held = self.data.len() + self.event.as_ref().map_or(0, String::len);
    }
}

#[cfg(test)]
#[path = "tests/compat_tests.rs"]
pub(super) mod tests;
