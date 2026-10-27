// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND WIRE for MCP revision `2026-07-28`: the JSON-RPC envelope busbar sends to an
//! upstream, and how its answer is read.
//!
//! The `_meta` keys and the mirror headers are `crate::codec`'s, the ones the ingress enforces, so
//! a request busbar sends satisfies the MUSTs busbar enforces. There is no session: every request
//! is self-describing. `params.name` is the UN-namespaced tool (busbar's `{server}_{tool}` is its
//! own). An upstream's `InputRequiredResult` is relayed to the caller only under the operator's
//! per-server grant ([`ServerRequestGrants`], deny by default), re-read every round (Law 11).

use crate::codec::{
    H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION, META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
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
pub fn tools_call(
    url: &str,
    key: &ToolKey,
    arguments: &serde_json::Value,
    request_id: u64,
    authorization: Option<&str>,
    advertise: AdvertisedCaps,
    continuation: Option<&serde_json::Value>,
) -> OutboundRequest {
    let name = key.tool();
    // BUSBAR'S OWN TOKEN, never the caller's, and only when the caller asked for progress.
    let progress_token: Option<String> = advertise.progress.then(|| format!("busbar-{request_id}"));
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
    let mut body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
            "_meta": {
                META_PROTOCOL_VERSION: PROTOCOL_VERSION,
                "progressToken": progress_token,
                META_CLIENT_CAPABILITIES: capabilities,
            },
        },
    });
    // EXACTLY TWO members of the continuation cross, by name.
    if let (Some(params), Some(responses)) = (
        body["params"].as_object_mut(),
        continuation.and_then(|c| c.get("inputResponses")),
    ) {
        params.insert("inputResponses".to_string(), responses.clone());
        if let Some(state) = continuation.and_then(|c| c.get("requestState")) {
            params.insert("requestState".to_string(), state.clone());
        }
    }
    envelope(url, "tools/call", Some(name), body, authorization)
}

/// Build a `tools/list` for one server.
pub fn tools_list(url: &str, request_id: u64, authorization: Option<&str>) -> OutboundRequest {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/list",
        "params": {
            "_meta": {
                META_PROTOCOL_VERSION: PROTOCOL_VERSION,
                META_CLIENT_CAPABILITIES: {},
            },
        },
    });
    envelope(url, "tools/list", None, body, authorization)
}

/// The shared envelope: the mirrored headers this revision REQUIRES, written from the same values
/// that went into the body so they cannot disagree. `super::verb` builds through it too.
pub fn envelope(
    url: &str,
    method: &str,
    name: Option<&str>,
    body: serde_json::Value,
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
        body: serde_json::to_vec(&body).unwrap_or_default(),
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
}

// THE OUTBOUND ID SPACE. A dispatch's id is its round (`0..=u32::MAX` by type); the child-process
// handshake's sits above every one of them, so a spare `initialize` answer left in a child's pipe
// can never correlate as a tool's result. The `const` assertion fails the build if they meet.

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
    use busbar_contract::jsonrpc::{read_response, NotAnAnswerKind, Reply};

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return RpcOutcome::Malformed("upstream response is not valid JSON".to_string());
    };
    let reply = match read_response(&value, &serde_json::Value::from(sent_id)) {
        Ok(reply) => reply,
        Err(e) => {
            return match e.kind {
                NotAnAnswerKind::Uncorrelated => RpcOutcome::Uncorrelated(e.reason),
                NotAnAnswerKind::NotAResponse => RpcOutcome::Malformed(e.reason),
            }
        }
    };
    match reply {
        Reply::Error { code, message } => match code.as_ref().and_then(serde_json::Value::as_i64) {
            Some(code) => RpcOutcome::Error { code, message },
            // JSON-RPC 2.0 section 5.1: `code` MUST be an integer; none is never invented.
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
/// `inputRequests`) and the MOST PRIVILEGED ask it names. An ask that names no method, or one this
/// plane does not know, is judged as `sampling`, so the refusal lands on a grant set deliberately.
fn input_required_kind(result: &serde_json::Value) -> Option<ServerAsk> {
    let obj = result.as_object()?;
    let by_spec = obj.get("resultType").and_then(|v| v.as_str()) == Some("input_required");
    // The shape busbar once invented: only a non-conformant upstream sends it, and it is refused.
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
                .map(
                    |request| match request.get("method").and_then(|v| v.as_str()) {
                        Some("elicitation/create") => ServerAsk::Elicitation,
                        Some("roots/list") => ServerAsk::Roots,
                        _ => ServerAsk::Sampling,
                    },
                )
                .max()
        });
    Some(kind.unwrap_or(ServerAsk::Sampling))
}

/// The per-server grants: whether the operator lets a server put each ask to callers. All false at
/// construction; deny-by-default is a property of the type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerRequestGrants {
    /// The server may ask for `sampling/createMessage`.
    pub sampling: bool,
    /// The server may ask for `elicitation/create`.
    pub elicitation: bool,
    /// The server may ask for `roots/list`.
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
