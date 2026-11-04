// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND WIRE for MCP revision `2026-07-28`: the JSON-RPC envelope busbar sends to an
//! upstream, and how its answer is read.
//!
//! The `_meta` keys and the mirror headers are `crate::codec`'s, the ones the ingress enforces, so
//! a request busbar sends satisfies the MUSTs busbar enforces. There is no session: every request
//! is self-describing. `params.name` is the UN-namespaced tool (busbar's `{server}_{tool}` is its
//! own). An upstream's `InputRequiredResult` is relayed to the caller only under the operator's
//! per-server grant ([`ServerRequestGrants`], deny by default), re-read every round.

use crate::codec::{
    json, H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION, META_CLIENT_CAPABILITIES,
    META_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use crate::identity::ToolKey;

/// A request busbar is about to send: everything, serialized, in one value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundRequest {
    /// The upstream endpoint the request is sent to.
    pub url: String,
    /// Header name/value pairs, lower-cased names, in the order they will be written.
    pub headers: Vec<(String, String)>,
    /// The serialized JSON-RPC body.
    pub body: Vec<u8>,
}

/// WHICH client capabilities the outbound `_meta` declares: one flag per capability busbar can
/// genuinely answer for THIS server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdvertisedCaps {
    /// Declare `roots`: the operator grants it to this server AND this caller declared it.
    pub roots: bool,
    /// Declare `sampling`: as `roots`.
    pub sampling: bool,
    /// Declare `elicitation`: as `roots`.
    pub elicitation: bool,
    /// The CALLER asked for progress, so busbar's own token rides `_meta`.
    pub progress: bool,
}

/// Build a `tools/call` for `key` against `url`.
///
/// `authorization` is the already-planned credential header value: this builder never sees the
/// caller's busbar key. `continuation` is the caller's answer to a relayed `InputRequiredResult`
/// (its `inputResponses` and the upstream's `requestState`), echoed onto the retry; `None` is every
/// first round. `advertise` declares the client capabilities in `_meta`.
/// A call whose complete stdio identity may be a JSON-RPC string instead of a legacy number.
pub fn tools_call_id(
    url: &str,
    key: &ToolKey,
    arguments: &serde_json::Value,
    request_id: &serde_json::Value,
    authorization: Option<&str>,
    advertise: AdvertisedCaps,
    continuation: Option<&serde_json::Value>,
) -> OutboundRequest {
    let name = key.tool();

    let progress_token: Option<String> = advertise.progress.then(|| progress_token(request_id));
    let mut capabilities = serde_json::Map::new();
    for (on, cap) in [
        (advertise.roots, "roots"),
        (advertise.sampling, "sampling"),
        (advertise.elicitation, "elicitation"),
    ] {
        if on {
            capabilities.insert(cap.to_string(), serde_json::json!({}));
        }
    }
    let mut meta = serde_json::json!({
        META_PROTOCOL_VERSION: PROTOCOL_VERSION,
        META_CLIENT_CAPABILITIES: capabilities,
    });
    if let (Some(meta), Some(token)) = (meta.as_object_mut(), progress_token) {
        meta.insert("progressToken".to_string(), token.into());
    }
    let mut params = serde_json::json!({
        "name": name,
        "arguments": arguments,
        "_meta": meta,
    });

    if let (Some(params), Some(continuation)) = (params.as_object_mut(), continuation) {
        for key in ["inputResponses", "requestState"] {
            if let Some(value) = continuation.get(key) {
                params.insert(key.to_string(), value.clone());
            }
        }
    }
    let body = busbar_contract::jsonrpc::request_bytes(
        &json(request_id),
        "tools/call",
        Some(&json(&params)),
    );
    envelope(url, "tools/call", Some(name), body, authorization)
}

/// The progress token corresponding to the exact typed id sent to a child.
pub fn progress_token(id: &serde_json::Value) -> String {
    match id {
        serde_json::Value::String(id) => format!("busbar-{}", id.as_str()),
        id => format!("busbar-{id}"),
    }
}

/// Build a `tools/list` for one server: the request an operator `connect` and a call's
/// verify-on-call fetch send a member over HTTP (`crate::plane_door`), and the one a stdio child is
/// asked over its pipe (`crate::plane_door`'s program leg).
pub fn tools_list(url: &str, request_id: u64, authorization: Option<&str>) -> OutboundRequest {
    tools_list_id(url, &serde_json::Value::from(request_id), authorization)
}

/// A `tools/list` whose correlation id may be a full ticket's JSON-RPC string id.
pub fn tools_list_id(
    url: &str,
    request_id: &serde_json::Value,
    authorization: Option<&str>,
) -> OutboundRequest {
    tools_list_page_id(url, request_id, authorization, None)
}

/// Build one page of a tool-list request under its exact typed correlation id.
pub fn tools_list_page_id(
    url: &str,
    request_id: &serde_json::Value,
    authorization: Option<&str>,
    cursor: Option<&str>,
) -> OutboundRequest {
    let mut params = serde_json::json!({
        "_meta": {
            META_PROTOCOL_VERSION: PROTOCOL_VERSION,
            META_CLIENT_CAPABILITIES: {},
        },
    });
    if let Some(cursor) = cursor {
        params["cursor"] = serde_json::Value::String(cursor.to_string());
    }
    let body = busbar_contract::jsonrpc::request_bytes(
        &json(request_id),
        "tools/list",
        Some(&json(&params)),
    );
    envelope(url, "tools/list", None, body, authorization)
}

/// A completed tool-list page, or the cursor needed before the list is complete.
#[derive(Debug)]
pub enum Paged {
    /// Fetch this cursor; no partial catalogue may be published yet.
    Next(String),
    /// Every page has been collected and validated.
    Done(serde_json::Value),
}

/// A logical `tools/list` reply collected across pages within the existing reply-byte bound.
#[derive(Debug, Default)]
pub struct ToolPages {
    first: Option<serde_json::Value>,
    cursors: std::collections::HashSet<String>,
    names: std::collections::HashSet<String>,
    bytes: usize,
    pages: u32,
}

impl ToolPages {
    /// The pages already accepted, used to distinguish sequential requests on a stdio stream.
    pub fn pages(&self) -> u32 {
        self.pages
    }

    /// Validate and retain one page, refusing loops, duplicate tools and malformed lists.
    pub fn take(&mut self, mut result: serde_json::Value) -> Result<Paged, String> {
        crate::trust::validate_tools(&result)?;
        let next = match result.get("nextCursor") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(cursor)) => Some(cursor.clone()),
            Some(_) => {
                return Err("the tool list has a nextCursor that is not a string".to_string());
            }
        };
        let bytes = json(&result).len();
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| "the paginated tool list exceeds the reply byte range".to_string())?;
        if self.bytes > busbar_contract::abi::sdk::exchange::REPLY_MAX {
            return Err(
                "the paginated tool list exceeds the existing reply byte bound".to_string(),
            );
        }
        self.pages = self
            .pages
            .checked_add(1)
            .ok_or_else(|| "the tool-list page identity is exhausted".to_string())?;
        let tools = result
            .get("tools")
            .and_then(serde_json::Value::as_array)
            .expect("observe checked tools");
        for tool in tools {
            let name = tool
                .get("name")
                .and_then(serde_json::Value::as_str)
                .expect("observe checked names");
            if !self.names.insert(name.to_string()) {
                return Err(format!("the tool list names `{name}` more than once"));
            }
        }
        if self.first.is_none() && next.is_none() {
            return Ok(Paged::Done(result));
        }
        let tools = result
            .get_mut("tools")
            .and_then(serde_json::Value::as_array_mut)
            .map(std::mem::take)
            .expect("observe checked tools");
        if let Some(object) = result.as_object_mut() {
            object.remove("nextCursor");
        }
        self.first
            .get_or_insert(result)
            .get_mut("tools")
            .and_then(serde_json::Value::as_array_mut)
            .expect("a validated first page")
            .extend(tools);
        match next {
            Some(cursor) if self.cursors.insert(cursor.clone()) => Ok(Paged::Next(cursor)),
            Some(_) => Err(
                "the tool list repeated a cursor, so no complete catalogue can be read".to_string(),
            ),
            None => Ok(Paged::Done(
                self.first.take().expect("a retained first page"),
            )),
        }
    }
}

/// Copy an existing list request with its next cursor, preserving routing and credential headers.
pub fn next_list_request(
    template: &OutboundRequest,
    cursor: &str,
) -> Result<OutboundRequest, String> {
    let mut body: serde_json::Value = serde_json::from_slice(&template.body)
        .map_err(|_| "the outgoing tools/list is not JSON".to_string())?;
    let params = body
        .get_mut("params")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| "the outgoing tools/list has no params object".to_string())?;
    params.insert("cursor".to_string(), cursor.into());
    Ok(OutboundRequest {
        url: template.url.clone(),
        headers: template.headers.clone(),
        body: json(&body),
    })
}

/// The shared envelope: the mirrored headers this revision REQUIRES, written from the same values
/// that went into the body so they cannot disagree. `super::verb` builds through it too.
pub fn envelope(
    url: &str,
    method: &str,
    name: Option<&str>,
    body: Vec<u8>,
    authorization: Option<&str>,
) -> OutboundRequest {
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        // An event stream is a permitted content type for the RESPONSE to a POST.
        (
            "accept".to_string(),
            "application/json, text/event-stream".to_string(),
        ),
        (H_PROTOCOL_VERSION.to_string(), PROTOCOL_VERSION.to_string()),
        (H_MCP_METHOD.to_string(), method.to_string()),
    ];
    if let Some(name) = name {
        headers.push((H_MCP_NAME.to_string(), encode_sentinel(name)));
    }
    if let Some(auth) = authorization {
        headers.push(("authorization".to_string(), format!("Bearer {auth}")));
    }
    OutboundRequest {
        url: url.to_string(),
        headers,
        body,
    }
}

/// Encode a name for a mirror header using this revision's `=?base64?…?=` sentinel when the value
/// is not plain visible ASCII (or holds `=` or `?`).
pub fn encode_sentinel(name: &str) -> String {
    use base64::Engine as _;
    if name
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'=' && b != b'?')
    {
        return name.to_string();
    }
    format!(
        "=?base64?{}?=",
        base64::engine::general_purpose::STANDARD.encode(name)
    )
}

/// The parsed shape of a JSON-RPC response, reduced to the outcomes dispatch cares about.
#[derive(Clone, Debug, PartialEq)]
pub enum RpcOutcome {
    /// A normal result.
    Result(serde_json::Value),
    /// A JSON-RPC error object with an integer `code`.
    Error {
        /// The error's `code`.
        code: i64,
        /// The error's `message`.
        message: String,
    },
    /// An `InputRequiredResult`: the upstream asks busbar's caller for something.
    InputRequired {
        /// The most privileged ask the result names.
        kind: ServerAsk,
    },
    /// The body was not a JSON-RPC response at all.
    Malformed(String),
    /// A JSON-RPC response to something else: a mismatched, `null` or absent `id`.
    Uncorrelated(String),
}

/// The three things an upstream may ask for, in ORDER OF DANGER (what answering costs the caller):
/// `roots` discloses filesystem structure, `elicitation` interrupts a human, `sampling` is an LLM
/// completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServerAsk {
    /// Disclose filesystem roots.
    Roots,
    /// Ask a human for input.
    Elicitation,
    /// `sampling/createMessage`: an LLM completion, which the caller runs if it answers.
    Sampling,
}

impl ServerAsk {
    /// The ask's grant key, as the registry and the refusal text spell it.
    pub fn key(self) -> &'static str {
        match self {
            ServerAsk::Sampling => "sampling",
            ServerAsk::Elicitation => "elicitation",
            ServerAsk::Roots => "roots",
        }
    }

    /// The ask a request's `method` makes; one that names no method, or one this plane does not
    /// know, is judged as `sampling`, so the refusal lands on a grant set deliberately.
    pub fn of_method(method: Option<&str>) -> Self {
        match method {
            Some(crate::tools_config::ASK_ELICITATION) => ServerAsk::Elicitation,
            Some(crate::tools_config::ASK_ROOTS) => ServerAsk::Roots,
            _ => ServerAsk::Sampling,
        }
    }
}

/// THE ID BUSBAR PUTS ON AN OUTBOUND DISPATCH: the round number, widened, and nothing else.
pub const fn dispatch_request_id(round: u32) -> u64 {
    round as u64
}

/// THE JSON-RPC ID BUSBAR PUTS ON ITS CHILD-PROCESS HANDSHAKE, disjoint from every dispatch id.
pub const HANDSHAKE_REQUEST_ID: u64 = u32::MAX as u64 + 1;

const _: () = assert!(HANDSHAKE_REQUEST_ID > dispatch_request_id(u32::MAX));

/// Parse an upstream response body AS THE ANSWER TO THE REQUEST `sent_id` NAMES. The envelope rules
/// (the `jsonrpc` member, the `id` cases, exactly one of `result`/`error`) are
/// [`busbar_contract::jsonrpc::read_response`]'s.
pub fn parse_response(body: &[u8], sent_id: u64) -> RpcOutcome {
    parse_response_id(body, &serde_json::Value::from(sent_id))
}

/// Parse the response under the exact JSON-RPC id sent, including its string/number type.
pub fn parse_response_id(body: &[u8], sent_id: &serde_json::Value) -> RpcOutcome {
    use busbar_contract::jsonrpc::{read_response, NotAnAnswerKind, Reply};

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return RpcOutcome::Malformed("upstream response is not valid JSON".to_string());
    };
    let reply = match read_response(&value, sent_id) {
        Ok(reply) => reply,
        Err(e) => {
            return match e.kind {
                NotAnAnswerKind::Uncorrelated => RpcOutcome::Uncorrelated(e.reason),
                NotAnAnswerKind::NotAResponse => RpcOutcome::Malformed(e.reason),
            };
        }
    };
    match reply {
        Reply::Error { code, message } => match code.as_ref().and_then(serde_json::Value::as_i64) {
            Some(code) => RpcOutcome::Error { code, message },

            None => RpcOutcome::Malformed(format!(
                "upstream error object has no integer `code` (message: {message})"
            )),
        },
        Reply::Result(result) => match input_required_kind(&result) {
            Some(ask) => RpcOutcome::InputRequired { kind: ask },
            None => RpcOutcome::Result(result),
        },
    }
}

/// Recognise an `InputRequiredResult` (MRTR: `resultType: "input_required"`, its asks a map at
/// `inputRequests`) and the MOST PRIVILEGED ask it names ([`ServerAsk::of_method`]).
fn input_required_kind(result: &serde_json::Value) -> Option<ServerAsk> {
    let obj = result.as_object()?;
    let by_spec = obj.get("resultType").and_then(|v| v.as_str()) == Some("input_required");

    let legacy = obj.get("type").and_then(|v| v.as_str()) == Some("input_required");
    if !by_spec && !legacy {
        return None;
    }
    let kind = obj
        .get("inputRequests")
        .and_then(|v| v.as_object())
        .and_then(|requests| {
            requests
                .values()
                .map(|request| ServerAsk::of_method(request.get("method").and_then(|v| v.as_str())))
                .max()
        });
    Some(kind.unwrap_or(ServerAsk::Sampling))
}

/// `tools.<server>.grants`: whether the operator lets a server put each ask to callers, consulted
/// on every relay. All false at construction; deny-by-default is a property of the type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerRequestGrants {
    /// The server may ask for `sampling/createMessage`: relayed to the caller, who runs the
    /// completion or not; busbar runs none on its behalf.
    #[serde(default)]
    pub sampling: bool,
    /// The server may ask for `elicitation/create`, relayed as `sampling`.
    #[serde(default)]
    pub elicitation: bool,
    /// The server may ask for `roots/list`, relayed as `sampling`.
    #[serde(default)]
    pub roots: bool,
}

impl ServerRequestGrants {
    /// Whether the operator lets this server put `ask` to callers.
    pub fn allows(&self, ask: ServerAsk) -> bool {
        match ask {
            ServerAsk::Sampling => self.sampling,
            ServerAsk::Elicitation => self.elicitation,
            ServerAsk::Roots => self.roots,
        }
    }
}

#[cfg(test)]
#[path = "tests/wire_tests.rs"]
mod wire_tests;

#[cfg(test)]
#[path = "tests/ask_tests.rs"]
mod ask_tests;
