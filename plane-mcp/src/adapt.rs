// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION REVISIONS, READ INTO AND WRITTEN OUT OF THE ONE DISPATCH.
//!
//! The plane has one method dispatch, written against the stateless `2026-07-28` shape: every
//! request carries its revision and the client's capabilities in `params._meta`, and mirrors its
//! method (and target name) into request headers. A session revision states those facts once, in
//! `initialize`, and then relies on the session. So a session request is RAISED into the stateless
//! shape before dispatch ([`raise`]), and the answer is LOWERED back into the session revision after
//! it ([`lower_result`]). There is no second dispatch table.
//!
//! What a session client is allowed to reach is decided here too ([`session_method`]): the methods
//! the session revisions define. The stateless revision's own methods (`server/discover`,
//! `subscriptions/listen`, the tasks extension) are never offered to a session client, whether it
//! asks for them by name or reads the capabilities `initialize` answered with. The session's own
//! verbs (`resources/subscribe`, `resources/unsubscribe`, `logging/setLevel`) stay for the old
//! revisions (THE DESIGN section 2, the mcp bullet) and are answered from the session's state.
//!
//! The `2024-11-05` event-stream framing lives here as values ([`frame`], [`endpoint_event`]);
//! writing them to a connection is the caller's.

use serde_json::{Map, Value};

use crate::codec::{META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION, PROTOCOL_VERSION};
use crate::revision::Revision;

/// The method that opens a session.
pub const METHOD_INITIALIZE: &str = "initialize";
/// The notification that completes the opening.
pub const METHOD_INITIALIZED: &str = "notifications/initialized";
/// The liveness request every session revision defines.
pub const METHOD_PING: &str = "ping";
/// The response header that names a session, and the request header that carries it back.
pub const H_SESSION_ID: &str = "mcp-session-id";
/// The request header a resuming GET names its cursor in.
pub const H_LAST_EVENT_ID: &str = "last-event-id";
/// The query member the `2024-11-05` message address carries the session in.
pub const QUERY_SESSION_ID: &str = "sessionId";

/// How a POST to the endpoint is to be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostKind {
    /// The stateless revision's request, carried exactly as it was before sessions existed.
    Stateless,
    /// `initialize`, opening a session.
    Initialize,
    /// A message inside a session named by the session header.
    InSession,
    /// A `2024-11-05` message POSTed to the address an event stream named.
    EventStreamMessage,
}

/// Classifies a POST. The stateless revision is recognised by its own marker (`_meta` carrying the
/// protocol version) and wins over everything else, and a request with neither a session nor an
/// `initialize` keeps the stateless reading too, so the stateless path's answers are unchanged.
#[must_use]
pub fn classify_post(
    body: &Value,
    session_header: Option<&str>,
    message_session: Option<&str>,
) -> PostKind {
    if message_session.is_some() {
        return PostKind::EventStreamMessage;
    }
    let stateless_marker = body
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(META_PROTOCOL_VERSION))
        .is_some();
    if stateless_marker {
        return PostKind::Stateless;
    }
    if session_header.is_some() {
        return PostKind::InSession;
    }
    if body.get("method").and_then(Value::as_str) == Some(METHOD_INITIALIZE) {
        return PostKind::Initialize;
    }
    PostKind::Stateless
}

/// Reads the session a `2024-11-05` message address carries, from a raw query string.
#[must_use]
pub fn message_session_of(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == QUERY_SESSION_ID)
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
}

/// What a session message is, for the dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionMethod {
    /// A method the one dispatch answers, after [`raise`].
    Dispatch,
    /// `ping`, answered here with an empty result.
    Ping,
    /// A verb of the session's own state: answered from it, never dispatched.
    Session,
    /// A notification or a response from the client: accepted (202) and not answered.
    Accept,
    /// Not a method of the session revisions: `-32601`.
    NotFound,
}

/// The methods a session client reaches through the dispatch.
const SESSION_DISPATCHED: &[&str] = &[
    "tools/list",
    "tools/call",
    "prompts/list",
    "prompts/get",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "completion/complete",
];

/// The verbs a session's own state answers (subscribe stays for the old revisions).
const SESSION_STATE_VERBS: &[&str] = &[
    "resources/subscribe",
    "resources/unsubscribe",
    "logging/setLevel",
];

/// Classifies one session message. `method` is `None` for a client's response to a request.
#[must_use]
pub fn session_method(method: Option<&str>, has_id: bool) -> SessionMethod {
    match method {
        None => SessionMethod::Accept,
        Some(_) if !has_id => SessionMethod::Accept,
        Some(METHOD_PING) => SessionMethod::Ping,
        Some(m) if SESSION_DISPATCHED.contains(&m) => SessionMethod::Dispatch,
        Some(m) if SESSION_STATE_VERBS.contains(&m) => SessionMethod::Session,
        Some(_) => SessionMethod::NotFound,
    }
}

/// RAISES a session request into the stateless shape: `params._meta` gains the stateless revision
/// and an EMPTY client-capability declaration (a session client's own capabilities would read as
/// consent to an input-required answer it cannot receive). Its header mirror is then what
/// [`crate::codec::mirrored`] reads off it.
///
/// `None` when the message has no method or its `params` is present and not an object.
#[must_use]
pub fn raise(message: &mut Value) -> Option<()> {
    message.get("method")?.as_str()?;
    let params = message
        .as_object_mut()?
        .entry("params")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()?;
    let meta = params
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()?;
    meta.insert(META_PROTOCOL_VERSION.into(), PROTOCOL_VERSION.into());
    meta.insert(META_CLIENT_CAPABILITIES.into(), Value::Object(Map::new()));
    Some(())
}

/// THE CUSTOM PARAMETER MIRROR a raised `tools/call` must carry (a session client's revision has
/// none): for every `inputSchema` property naming an `x-mcp-header` suffix whose argument is a
/// string, (`mcp-param-<suffix>`, the value in the name sentinel where it needs one).
#[must_use]
pub fn param_mirror(
    input_schema: Option<&Value>,
    arguments: Option<&Value>,
) -> Vec<(String, String)> {
    let Some(props) = input_schema
        .and_then(|s| s.get("properties"))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    props
        .iter()
        .filter_map(|(property, definition)| {
            let suffix = definition.get("x-mcp-header")?.as_str()?;
            let value = arguments?.get(property)?.as_str()?;
            Some((
                format!("mcp-param-{suffix}"),
                crate::client::jsonrpc::encode_sentinel(value),
            ))
        })
        .collect()
}

/// The stateless revision's result members no session revision defines.
const STATELESS_ONLY_MEMBERS: &[&str] = &["resultType", "cacheScope", "ttlMs"];

/// LOWERS a stateless result into a session revision's shape: `false` when it is not a complete
/// one (an input-required or task answer), which no session revision can express.
pub fn lower_result(result: &mut Value) -> bool {
    let Some(obj) = result.as_object_mut() else {
        return true;
    };
    match obj.get("resultType").and_then(Value::as_str) {
        None | Some(crate::codec::RESULT_TYPE_COMPLETE) => {}
        Some(_) => return false,
    }
    for k in STATELESS_ONLY_MEMBERS {
        obj.remove(*k);
    }
    true
}

/// Builds the `initialize` result from the stateless discovery document, for `revision`: only the
/// capability groups the session revisions define and discovery declared (`tools`, `prompts`,
/// `resources` with `subscribe`, `logging`, and from `2025-06-18` `completions`); no list-changed
/// notifications are offered.
#[must_use]
pub fn initialize_result(discovery: &Value, revision: Revision) -> Value {
    let declared = discovery.get("capabilities");
    let has = |k: &str| declared.and_then(|c| c.get(k)).is_some();
    let mut caps = Map::new();
    for group in ["tools", "prompts", "resources"] {
        if has(group) {
            caps.insert(group.into(), serde_json::json!({ "listChanged": false }));
        }
    }
    if let Some(resources) = caps.get_mut("resources").and_then(Value::as_object_mut) {
        resources.insert("subscribe".into(), Value::Bool(true));
    }
    if has("logging") {
        caps.insert("logging".into(), Value::Object(Map::new()));
    }
    if has("completions") && revision != Revision::R2024_11_05 {
        caps.insert("completions".into(), Value::Object(Map::new()));
    }
    let server_info = discovery
        .get("serverInfo")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "name": "busbar", "version": "" }));
    serde_json::json!({
        "protocolVersion": revision.wire(),
        "capabilities": caps,
        "serverInfo": server_info,
    })
}

/// One event-stream event. `data` is written one `data:` line per line it holds, so a multi-line
/// payload survives framing.
#[must_use]
pub fn frame(id: Option<&str>, event: Option<&str>, data: &str) -> String {
    let mut out = String::with_capacity(data.len() + 48);
    if let Some(e) = event {
        out.push_str("event: ");
        out.push_str(e);
        out.push('\n');
    }
    if let Some(i) = id {
        out.push_str("id: ");
        out.push_str(i);
        out.push('\n');
    }
    for line in data.split('\n') {
        out.push_str("data: ");
        out.push_str(line.strip_suffix('\r').unwrap_or(line));
        out.push('\n');
    }
    out.push('\n');
    out
}

/// The `2024-11-05` stream's first event: the address, relative to the endpoint's own origin, that
/// messages for this session are POSTed to.
#[must_use]
pub fn endpoint_event(mount_path: &str, session: &str) -> String {
    frame(
        None,
        Some("endpoint"),
        &format!("{mount_path}?{QUERY_SESSION_ID}={session}"),
    )
}

/// The event name a `2024-11-05` stream carries JSON-RPC messages under.
pub const EVENT_MESSAGE: &str = "message";

#[cfg(test)]
#[path = "tests/adapt_tests.rs"]
mod tests;
