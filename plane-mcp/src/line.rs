// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINE CARRIER: one JSON-RPC message per line, each line its own request unit through the

#![cfg_attr(not(test), allow(dead_code))]

use serde_json::{json, Map, Value};

use crate::codec::PROTOCOL_VERSION;
use crate::revision::Revision;

/// The prefix of the id busbar spells its own requests on the line in.
pub const ASK_ID_PREFIX: &str = "busbar:";

/// How long busbar waits for the caller to answer ONE live ask before handing it the
pub const ASK_TIMEOUT_NS: u64 = 30 * 1_000_000_000;

/// The most live ask rounds busbar drives for one request: the carrier's own belt against a
pub const MAX_LIVE_ASK_ROUNDS: u32 = 8;

/// One success envelope.
#[must_use]
pub fn result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// One method-not-found envelope.
fn unsupported(id: &Value, message: &str) -> Value {
    busbar_contract::jsonrpc::error_body(
        id.clone(),
        crate::codec::CODE_METHOD_NOT_FOUND,
        message,
        None,
    )
}

/// The `initialize` answer to a client that names no session revision: the stateless revision,
#[must_use]
pub fn initialize_result(id: &Value) -> Value {
    result(
        id,
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": capabilities(),
            "serverInfo": server_info(),
            "instructions": format!(
                "This server speaks MCP revision {PROTOCOL_VERSION}: no handshake is required, \
                 and every request states its protocol version and client capabilities in \
                 `params._meta`."
            ),
        }),
    )
}

/// The `initialize` answer to a client that asked for a SESSION revision this plane carries: that
#[must_use]
pub fn session_initialize_result(id: &Value, revision: Revision) -> Value {
    let mut caps = capabilities();
    for group in ["tools", "prompts", "resources"] {
        caps[group]["listChanged"] = Value::Bool(false);
    }
    if revision == Revision::R2024_11_05 {
        caps.as_object_mut()
            .expect("capabilities is an object")
            .remove("completions");
    }
    result(
        id,
        json!({
            "protocolVersion": revision.wire(),
            "capabilities": caps,
            "serverInfo": server_info(),
        }),
    )
}

/// The capabilities the line carrier declares, in every revision it speaks: no `subscribe` and no
fn capabilities() -> Value {
    json!({
        "tools": { "listChanged": true },
        "prompts": { "listChanged": true },
        "resources": { "listChanged": true },
        "completions": {},
    })
}

/// The server's name and version.
fn server_info() -> Value {
    json!({
        "name": "busbar",
        "version": crate::plane_door::VERSION,
    })
}

/// What a stdio-era verb came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Era {
    /// Answered here, whole.
    Answer(Value),
    /// `initialize` asking for a session revision: the revision the carrier session now speaks,
    /// and the answer.
    Opened(Revision, Value),
    /// Not a stdio-era verb: the one dispatch's.
    Dispatch,
}

/// THE STDIO-ERA VERBS, read off a request (`method`, `id`) before the `_meta` gate, because a
#[must_use]
pub fn era(value: &Value) -> Era {
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        return Era::Dispatch;
    };
    if !matches!(
        method,
        "initialize"
            | "ping"
            | "logging/setLevel"
            | "resources/subscribe"
            | "resources/unsubscribe"
    ) {
        return Era::Dispatch;
    }
    let id = match crate::tool_arrival::request(value) {
        Ok(busbar_contract::jsonrpc::Envelope::Request { id, .. }) => id,
        Ok(busbar_contract::jsonrpc::Envelope::Notification { .. }) => return Era::Dispatch,
        Err(refusal) => {
            return Era::Answer(serde_json::from_slice(&refusal.body()).expect("a refusal is JSON"))
        }
    };
    let id = &id;
    match method {
        crate::adapt::METHOD_INITIALIZE => match value
            .pointer("/params/protocolVersion")
            .and_then(Value::as_str)
        {
            Some(requested) if requested != PROTOCOL_VERSION => {
                let revision = crate::revision::negotiate(Some(requested));
                Era::Opened(revision, session_initialize_result(id, revision))
            }
            _ => Era::Answer(initialize_result(id)),
        },
        crate::adapt::METHOD_PING => Era::Answer(result(id, json!({}))),
        "logging/setLevel" => Era::Answer(unsupported(
            id,
            "this revision has no `logging/setLevel`: there is no session to remember a floor in. A \
             request states its floor in `params._meta`.",
        )),
        "resources/subscribe" | "resources/unsubscribe" => Era::Answer(unsupported(
            id,
            "this revision has no `resources/subscribe`: open `subscriptions/listen` with \
             `notifications.resourceSubscriptions` instead.",
        )),
        _ => Era::Dispatch,
    }
}

/// What a line that is not a request is, when it answers one of busbar's own.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// The caller answered ask `n` with this result.
    Answered(u64, Value),
    /// The caller answered ask `n` with an error, or with no answer.
    Failed(u64),
}

/// The ask number busbar spelled into an id it minted.
fn ask_of(id: &Value) -> Option<u64> {
    id.as_str()?.strip_prefix(ASK_ID_PREFIX)?.parse().ok()
}

/// Whether a line answers one of busbar's own requests, and which: a JSON-RPC RESPONSE (no
#[must_use]
pub fn reply(value: &Value) -> Option<Reply> {
    let obj = value.as_object()?;
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    match obj.get("method").and_then(Value::as_str) {
        None => {
            if obj.contains_key("method") {
                return None;
            }
            let n = ask_of(obj.get("id")?)?;
            match busbar_contract::jsonrpc::read_response(value, obj.get("id")?).ok()? {
                busbar_contract::jsonrpc::Reply::Result(result) => Some(Reply::Answered(n, result)),
                busbar_contract::jsonrpc::Reply::Error { .. } => Some(Reply::Failed(n)),
            }
        }
        Some("notifications/elicitation/response") => {
            if !matches!(
                crate::tool_arrival::request(value),
                Ok(busbar_contract::jsonrpc::Envelope::Notification { .. })
            ) {
                return None;
            }
            let n = ask_of(value.pointer("/params/requestId")?)?;
            Some(Reply::Answered(
                n,
                value
                    .pointer("/params/response")
                    .cloned()
                    .unwrap_or(Value::Null),
            ))
        }
        Some(_) => None,
    }
}

/// The request id a `notifications/cancelled` names.
#[must_use]
pub fn cancelled(value: &Value) -> Option<Value> {
    (value.get("method").and_then(Value::as_str) == Some("notifications/cancelled"))
        .then(|| value.pointer("/params/requestId").cloned())
        .flatten()
        .filter(|i| i.is_string() || i.is_number())
}

/// A stable key for a JSON-RPC id: type-tagged, so the string `"1"` and the number `1` (which never
#[must_use]
pub fn id_key(id: &Value) -> String {
    match id {
        Value::String(s) => format!("s:{s}"),
        other => format!("n:{other}"),
    }
}

/// ONE LIVE ASK ROUND for one request: the request it continues, the round's asks in order, the
/// answers so far, the sealed state the retry echoes, and the unit holding the caller's answer.
#[derive(Debug, Clone)]
pub struct LiveAsk {
    /// The request as the caller sent it (its id is the caller's).
    pub original: Value,
    /// The `input_required` result itself: what the caller is handed when it does not answer.
    pub fallback: Vec<u8>,
    /// The asks not yet issued, in order: `(key, method, params)`.
    pub queued: Vec<(String, String, Option<Value>)>,
    /// The key of the ask in flight.
    pub current: String,
    /// The answers so far, by key.
    pub responses: Map<String, Value>,
    /// The sealed state the retry echoes.
    pub state: String,
    /// The live round this is (`0` = the request's first).
    pub round: u32,
    /// When the ask in flight lapses, on the host's monotonic clock.
    pub deadline_ns: u64,
}

impl LiveAsk {
    /// The round an `input_required` `result` asks of `original`; `None` when the result names no
    #[must_use]
    pub fn of(original: Value, fallback: Vec<u8>, result: &Value, round: u32) -> Option<Self> {
        let requests = result.get("inputRequests")?.as_object()?;
        let state = result.get("requestState")?.as_str()?.to_string();
        let mut queued: Vec<(String, String, Option<Value>)> = requests
            .iter()
            .filter_map(|(key, ask)| {
                Some((
                    key.clone(),
                    ask.get("method")?.as_str()?.to_string(),
                    ask.get("params").cloned(),
                ))
            })
            .collect();
        if queued.is_empty() || queued.len() != requests.len() {
            return None;
        }
        queued.reverse();
        Some(LiveAsk {
            original,
            fallback,
            queued,
            current: String::new(),
            responses: Map::new(),
            state,
            round,
            deadline_ns: 0,
        })
    }

    /// Starts the clock on the ask in flight: it lapses [`ASK_TIMEOUT_NS`] after `now_ns`.
    pub fn arm(&mut self, now_ns: u64) {
        self.deadline_ns = now_ns.saturating_add(ASK_TIMEOUT_NS);
    }

    /// Whether the ask in flight went unanswered past its deadline at `now_ns`.
    #[must_use]
    pub fn lapsed(&self, now_ns: u64) -> bool {
        self.deadline_ns != 0 && now_ns >= self.deadline_ns
    }

    /// The next ask as the request line busbar writes, under ask number `n`; `None` once every ask
    pub fn issue(&mut self, n: u64) -> Option<Vec<u8>> {
        let (key, method, params) = self.queued.pop()?;
        self.current = key;
        let params = params.as_ref().map(crate::codec::json);
        let mut line = busbar_contract::jsonrpc::request_bytes(
            &crate::codec::json(&format!("{ASK_ID_PREFIX}{n}")),
            &method,
            params.as_deref(),
        );
        line.push(b'\n');
        Some(line)
    }

    /// The caller's answer to the ask in flight.
    pub fn answered(&mut self, response: Value) {
        self.responses
            .insert(std::mem::take(&mut self.current), response);
    }

    /// THE RETRY: the request as the caller sent it, carrying the round's answers and the sealed
    #[must_use]
    pub fn retry(&self) -> Option<Value> {
        let mut retry = self.original.clone();
        let params = retry.get_mut("params")?.as_object_mut()?;
        params.insert(
            "inputResponses".to_string(),
            Value::Object(self.responses.clone()),
        );
        params.insert("requestState".to_string(), Value::from(self.state.clone()));
        Some(retry)
    }
}

#[cfg(test)]
#[path = "tests/line_tests.rs"]
mod tests;
