// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT AN UPSTREAM SENDS BUSBAR UNASKED: every line a child writes (or an event stream carries)
//! classified, so a response is never confused with a notification or the server's own request.
//!
//! | class | what busbar does |
//! |---|---|
//! | the correlated response | returned to the caller; the exchange ends |
//! | a notification busbar knows | the effect in [`NotificationEffect`], then keep reading |
//! | a notification busbar does not know | dropped, then keep reading, never adopted |
//! | `ping` | answered, then keep reading |
//! | a granted authority ask | relayed to busbar's caller, who answers it (Law 11) |
//! | an ungranted authority ask | refused (`ask_ungranted`), then keep reading |
//! | a request busbar does not know | answered `-32601`, then keep reading |
//!
//! Notification payloads are never read for a routing or trust decision.

use super::jsonrpc::{ServerAsk, ServerRequestGrants};
use crate::codec::CODE_METHOD_NOT_FOUND;
use busbar_contract::jsonrpc::error_body;

/// The code an authority ask busbar will not relay is refused with: a policy answer, not `-32601`.
const ASK_REFUSED: i64 = -32001;

/// ONE MESSAGE A CHILD SENT, classified. A response is not an arm: [`classify`] answers `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerMessage {
    /// A notification busbar recognises. No reply, ever.
    Notification(ServerNotification),
    /// A notification busbar does not recognise. Still no reply.
    UnknownNotification(String),
    /// A request busbar recognises. MUST be answered.
    Request {
        /// The request's JSON-RPC id, echoed on the reply.
        id: serde_json::Value,
        /// Which of the four requests it is.
        verb: ServerRequestVerb,
    },
    /// A request busbar does not recognise. MUST STILL BE ANSWERED, with `-32601`. Dropping it
    /// leaves the child blocked on a reply that never comes.
    UnknownRequest {
        /// The request's JSON-RPC id, echoed on the `-32601` reply.
        id: serde_json::Value,
        /// The method name as the peer sent it.
        method: String,
    },
}

/// THE NINE NOTIFICATIONS A SERVER MAY SEND, closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerNotification {
    /// The peer withdrew a request it had sent busbar.
    Cancelled,
    /// A log record. RFC 5424 severity in `params.level`.
    Message,
    /// Progress on a call busbar has in flight.
    Progress,
    /// The peer's prompt list changed.
    PromptsListChanged,
    /// The peer's resource list changed.
    ResourcesListChanged,
    /// One resource's contents changed. Distinct from `ResourcesListChanged`: the LIST is the same
    /// and one member of it moved.
    ResourcesUpdated,
    /// The peer accepted a `subscriptions/listen` busbar sent.
    SubscriptionsAcknowledged,
    /// A task busbar created moved.
    Tasks,
    /// The peer's tool list changed.
    ToolsListChanged,
}

/// THE FOUR REQUESTS A SERVER MAY SEND, closed. Three of them are authority asks; one is a ping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerRequestVerb {
    /// Liveness. The only one that is not gated — see the module header.
    Ping,
    /// `roots/list`: disclose the caller's filesystem roots, if it answers.
    RootsList,
    /// `sampling/createMessage`: an LLM completion, which the caller runs if it answers.
    SamplingCreateMessage,
    /// `elicitation/create`: solicit user input.
    ElicitationCreate,
}

impl ServerRequestVerb {
    /// The grant this request asks to spend, or `None` for the one that spends nothing.
    pub fn ask(self) -> Option<ServerAsk> {
        match self {
            ServerRequestVerb::Ping => None,
            ServerRequestVerb::RootsList => Some(ServerAsk::Roots),
            ServerRequestVerb::SamplingCreateMessage => Some(ServerAsk::Sampling),
            ServerRequestVerb::ElicitationCreate => Some(ServerAsk::Elicitation),
        }
    }
}

/// WHAT BUSBAR DOES about a notification it recognises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationEffect {
    /// Bring a `tools/list` re-pull forward. The notification's contents are not read.
    BringRefreshForward,
    /// `notifications/resources/updated`: relay `params.uri` to the subscriptions watching it.
    RelayResourceUpdate,
    /// Relay to the caller's progress channel, if this dispatch has one.
    RelayProgress,
    /// Record it at the mapped log level and nothing else.
    Log,
}

impl ServerNotification {
    /// The effect, exhaustive and with no wildcard.
    pub fn effect(self) -> NotificationEffect {
        match self {
            ServerNotification::ToolsListChanged
            | ServerNotification::PromptsListChanged
            | ServerNotification::ResourcesListChanged => NotificationEffect::BringRefreshForward,
            ServerNotification::ResourcesUpdated => NotificationEffect::RelayResourceUpdate,
            ServerNotification::Progress => NotificationEffect::RelayProgress,
            // Recorded and no more: a peer's `cancelled` never aborts a call a caller paid for.
            ServerNotification::Cancelled
            | ServerNotification::Message
            | ServerNotification::SubscriptionsAcknowledged
            | ServerNotification::Tasks => NotificationEffect::Log,
        }
    }
}

/// CLASSIFY one line a child wrote. `None`: a response, or not a JSON-RPC message at all.
///
/// A known notification method is a notification whatever `id` holds; anything else is a request
/// exactly when the `id` MEMBER is present (a `null` id is still a request, and is answered).
pub fn classify(value: &serde_json::Value) -> Option<ServerMessage> {
    let obj = value.as_object()?;
    // A line carrying `result` or `error` is a response, even with a `method`.
    if obj.contains_key("result") || obj.contains_key("error") {
        return None;
    }
    let method = obj.get("method").and_then(|m| m.as_str())?;
    if let Some(n) = notification_of(method) {
        return Some(ServerMessage::Notification(n));
    }
    let Some(id) = obj.get("id").cloned() else {
        return Some(ServerMessage::UnknownNotification(method.to_string()));
    };
    Some(match request_of(method) {
        Some(verb) => ServerMessage::Request { id, verb },
        None => ServerMessage::UnknownRequest {
            id,
            method: method.to_string(),
        },
    })
}

fn notification_of(method: &str) -> Option<ServerNotification> {
    Some(match method {
        "notifications/cancelled" => ServerNotification::Cancelled,
        "notifications/message" => ServerNotification::Message,
        "notifications/progress" => ServerNotification::Progress,
        "notifications/prompts/list_changed" => ServerNotification::PromptsListChanged,
        "notifications/resources/list_changed" => ServerNotification::ResourcesListChanged,
        "notifications/resources/updated" => ServerNotification::ResourcesUpdated,
        "notifications/subscriptions/acknowledged" => ServerNotification::SubscriptionsAcknowledged,
        "notifications/tasks" => ServerNotification::Tasks,
        "notifications/tools/list_changed" => ServerNotification::ToolsListChanged,
        _ => return None,
    })
}

fn request_of(method: &str) -> Option<ServerRequestVerb> {
    Some(match method {
        "ping" => ServerRequestVerb::Ping,
        "roots/list" => ServerRequestVerb::RootsList,
        "sampling/createMessage" => ServerRequestVerb::SamplingCreateMessage,
        "elicitation/create" => ServerRequestVerb::ElicitationCreate,
        _ => return None,
    })
}

/// THE REPLY BUSBAR WRITES BACK to a child's request: `ping`'s empty result, or an ungranted ask's
/// refusal. `None` for a granted ask: it is the caller's to answer (Law 11). The grants are read
/// at the moment of the decision, so a revocation bites on the next message.
pub fn answer(
    id: &serde_json::Value,
    verb: ServerRequestVerb,
    grants: &ServerRequestGrants,
    server: &str,
) -> Option<serde_json::Value> {
    let Some(ask) = verb.ask() else {
        return Some(crate::line::result(id, serde_json::json!({})));
    };
    if grants.allows(ask) {
        return None;
    }
    let kind = ask.key();
    Some(refused(
        id,
        "ask_ungranted",
        format!(
            "server `{server}` asked for `{kind}` and its registry entry carries no `{kind}` \
             grant, so the ask is not relayed to busbar's caller. Set \
             `tools.{server}.grants.{kind}: true` if the operator intends this server to put \
             that ask to its callers."
        ),
    ))
}

/// A REFUSAL of an ask of the child's own: `-32001`, `message`, and the audit reason word in `data`.
pub fn refused(id: &serde_json::Value, reason: &str, message: String) -> serde_json::Value {
    let data = serde_json::json!({ "reason": reason });
    error_body(id.clone(), ASK_REFUSED, &message, Some(data))
}

/// The `-32601` a child gets for a request busbar does not implement: answered, never dropped (a
/// dropped request is a child blocked on a reply forever).
pub fn method_not_found(id: &serde_json::Value, method: &str) -> serde_json::Value {
    let message = format!(
        "busbar's MCP client leg does not implement `{method}`; it answers `ping` and gates \
         `roots/list`, `sampling/createMessage` and `elicitation/create` on the operator's \
         per-server grants."
    );
    error_body(id.clone(), CODE_METHOD_NOT_FOUND, &message, None)
}

#[cfg(test)]
#[path = "tests/peer_tests.rs"]
mod peer_tests;
