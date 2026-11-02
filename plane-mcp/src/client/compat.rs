// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLIENT HALF OF THE SESSION REVISIONS: how busbar, calling an upstream that does not speak

use serde_json::Value;

use super::jsonrpc::OutboundRequest;
use crate::adapt::H_SESSION_ID;
use crate::codec::json;
use crate::codec::{
    CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND,
    CODE_UNSUPPORTED_PROTOCOL_VERSION, H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION,
    META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION,
};
use crate::revision::{Revision, StepOutcome};

/// The id busbar's own `initialize` carries: `2^53 - 1`, the largest integer a JavaScript peer
pub const INITIALIZE_ID: u64 = (1 << 53) - 1;

/// Reads what a stateless request's answer says about the upstream's revision.
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
#[must_use]
pub fn stateless_outcome(status: u16, body: &[u8]) -> StepOutcome {
    if (500..600).contains(&status) {
        return StepOutcome::Unreachable;
    }
    if (400..500).contains(&status) {
        return StepOutcome::Refused4xx;
    }
    let error = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").filter(|e| e.is_object()).cloned());
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
        Some(CODE_INVALID_REQUEST | CODE_INVALID_PARAMS | -32000)
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
    if code == Some(CODE_UNSUPPORTED_PROTOCOL_VERSION) || names_session {
        StepOutcome::Refused4xx
    } else {
        StepOutcome::Answered
    }
}

/// The `initialize` request (id [`INITIALIZE_ID`]), sent to `url` with the credential `template`
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
#[must_use]
pub fn offered_revision(body: &[u8]) -> Option<Revision> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let busbar_contract::jsonrpc::Reply::Result(result) =
        busbar_contract::jsonrpc::read_response(&v, &Value::from(INITIALIZE_ID)).ok()?
    else {
        return None;
    };
    crate::revision::accept_offered(result.get("protocolVersion")?.as_str()?)
}

/// LOWERS a stateless request into `revision`: the stateless `_meta` members go (a session
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

        if let Some(token) = obj
            .get_mut("params")
            .and_then(|p| p.get_mut("_meta"))
            .and_then(|m| m.get_mut("progressToken"))
            .filter(|t| !t.is_null())
        {
            *token = Value::from(format!("busbar-{id}"));
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
///
/// Lines end as the event-stream grammar ends them: CRLF, a lone LF or a lone CR. A CR ends its
/// line as it arrives (an LF right after it, in this chunk or the next, is the rest of that one
/// terminator), so an event whose blank line is `\r\r` is handed on at once, never held for a byte
/// the far end may not send.
///
/// Bounded: an unfinished event that grows past `max_pending` bytes, every byte held counted
/// (carriage returns included), is dropped and [`Self::overflowed`] says so, so a peer that never
/// ends an event cannot grow busbar's memory.
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
    /// The bytes read since the last event ended: what the bound counts.
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

    /// The current line ended: a blank line ends the event (handed on when it named or carried
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
            if event.is_some() || has_data {
                out.push(StreamEvent { event, data });
            }
            self.held = 0;
            return;
        }
        let line = String::from_utf8_lossy(&self.line).into_owned();
        self.line.clear();
        if line.starts_with(':') {
            return;
        }
        let (field, value) = line.split_once(':').unwrap_or((&line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => self.event = Some(value.to_string()),
            "data" => {
                self.data.push_str(value);
                self.data.push('\n');
                self.has_data = true;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "tests/compat_tests.rs"]
pub(super) mod tests;
