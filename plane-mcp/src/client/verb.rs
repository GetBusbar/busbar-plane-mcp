// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLOSED SET OF METHODS BUSBAR ISSUES TO AN UPSTREAM MCP SERVER, one enum so the column
//! `mcp × stdio × busbar-as-client × client-originated` of `tests/data/method-inventory.json` is
//! enumerable (`tests/method_inventory.rs` compares it in both directions). `initialize` is built
//! here because a stdio child demands a handshake. Params are data on the child's stdin, never argv.

use super::jsonrpc::{envelope, OutboundRequest};
use crate::codec::{META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION, PROTOCOL_VERSION};

/// ONE METHOD BUSBAR SENDS TO AN UPSTREAM, with its parameters. Only `Initialize` and
/// `NotificationsInitialized` have a production caller (the stdio handshake); the rest are the
/// inventory column's.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub enum UpstreamVerb {
    /// The handshake.
    Initialize {
        /// busbar's release, sent as `clientInfo.version`.
        client_version: &'static str,
    },
    /// The handshake's acknowledgement. A NOTIFICATION.
    NotificationsInitialized,
    /// Liveness.
    Ping,
    /// The merged capability advertisement this revision added.
    ServerDiscover,
    /// Set the upstream's log verbosity.
    LoggingSetLevel {
        /// The RFC 5424 level name.
        level: String,
    },
    /// The upstream's tool list.
    ToolsList,
    /// Invoke one tool. `name` is the UN-namespaced tool.
    ToolsCall {
        /// The un-namespaced tool name.
        name: String,
        /// The tool's arguments object.
        arguments: serde_json::Value,
    },
    /// The upstream's prompt list.
    PromptsList,
    /// One prompt, rendered with arguments.
    PromptsGet {
        /// The prompt name.
        name: String,
        /// The prompt's arguments object.
        arguments: serde_json::Value,
    },
    /// The upstream's resource list.
    ResourcesList,
    /// The upstream's resource templates.
    ResourcesTemplatesList,
    /// Read one resource.
    ResourcesRead {
        /// The resource URI.
        uri: String,
    },
    /// Subscribe to one resource's updates.
    ResourcesSubscribe {
        /// The resource URI.
        uri: String,
    },
    /// Drop one resource subscription.
    ResourcesUnsubscribe {
        /// The resource URI.
        uri: String,
    },
    /// SEP-2575's replacement for the removed GET stream. A METHOD in this revision.
    SubscriptionsListen {
        /// The notification categories asked for.
        notifications: serde_json::Value,
    },
    /// Argument completion.
    CompletionComplete {
        /// The prompt or resource template being completed.
        reference: serde_json::Value,
        /// The argument name and partial value.
        argument: serde_json::Value,
    },
    /// SEP-2663 tasks. `taskId` is the wire spelling — see the engine's `mcp::tasks`.
    TasksGet {
        /// The task id.
        task_id: String,
    },
    /// Hand a task the input it asked for.
    TasksUpdate {
        /// The task id.
        task_id: String,
        /// The answers, keyed as the task asked.
        input_responses: serde_json::Value,
    },
    /// Cancel one task.
    TasksCancel {
        /// The task id.
        task_id: String,
    },
    /// A NOTIFICATION: the caller withdrew a request busbar had already forwarded.
    NotificationsCancelled {
        /// The id of the withdrawn request.
        request_id: serde_json::Value,
        /// Why it was withdrawn.
        reason: String,
    },
    /// A NOTIFICATION: progress on a long-running call, relayed upstream.
    NotificationsProgress {
        /// The token the upstream call was issued with.
        progress_token: serde_json::Value,
        /// Progress so far.
        progress: f64,
        /// The total, when known.
        total: Option<f64>,
    },
    /// A NOTIFICATION: busbar's exposed root set changed.
    NotificationsRootsListChanged,
    /// A NOTIFICATION: the answer to an `elicitation/create` the upstream asked for.
    NotificationsElicitationResponse {
        /// The id of the upstream's `elicitation/create`.
        request_id: serde_json::Value,
        /// The user's answer.
        content: serde_json::Value,
    },
}

impl UpstreamVerb {
    /// THE WIRE METHOD NAME.
    pub fn method(&self) -> &'static str {
        match self {
            UpstreamVerb::Initialize { .. } => "initialize",
            UpstreamVerb::NotificationsInitialized => "notifications/initialized",
            UpstreamVerb::Ping => "ping",
            UpstreamVerb::ServerDiscover => "server/discover",
            UpstreamVerb::LoggingSetLevel { .. } => "logging/setLevel",
            UpstreamVerb::ToolsList => "tools/list",
            UpstreamVerb::ToolsCall { .. } => "tools/call",
            UpstreamVerb::PromptsList => "prompts/list",
            UpstreamVerb::PromptsGet { .. } => "prompts/get",
            UpstreamVerb::ResourcesList => "resources/list",
            UpstreamVerb::ResourcesTemplatesList => "resources/templates/list",
            UpstreamVerb::ResourcesRead { .. } => "resources/read",
            UpstreamVerb::ResourcesSubscribe { .. } => "resources/subscribe",
            UpstreamVerb::ResourcesUnsubscribe { .. } => "resources/unsubscribe",
            UpstreamVerb::SubscriptionsListen { .. } => "subscriptions/listen",
            UpstreamVerb::CompletionComplete { .. } => "completion/complete",
            UpstreamVerb::TasksGet { .. } => "tasks/get",
            UpstreamVerb::TasksUpdate { .. } => "tasks/update",
            UpstreamVerb::TasksCancel { .. } => "tasks/cancel",
            UpstreamVerb::NotificationsCancelled { .. } => "notifications/cancelled",
            UpstreamVerb::NotificationsProgress { .. } => "notifications/progress",
            UpstreamVerb::NotificationsRootsListChanged => "notifications/roots/list_changed",
            UpstreamVerb::NotificationsElicitationResponse { .. } => {
                "notifications/elicitation/response"
            }
        }
    }

    /// Whether this verb is a JSON-RPC NOTIFICATION: no `id`, and no reply ever.
    pub fn is_notification(&self) -> bool {
        matches!(
            self,
            UpstreamVerb::NotificationsInitialized
                | UpstreamVerb::NotificationsCancelled { .. }
                | UpstreamVerb::NotificationsProgress { .. }
                | UpstreamVerb::NotificationsRootsListChanged
                | UpstreamVerb::NotificationsElicitationResponse { .. }
        )
    }

    /// The `params` object, WITHOUT `_meta`, which [`Self::build`] adds once for every verb.
    fn params(&self) -> serde_json::Value {
        match self {
            UpstreamVerb::Initialize { client_version } => serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "busbar", "version": client_version },
            }),
            UpstreamVerb::NotificationsInitialized
            | UpstreamVerb::Ping
            | UpstreamVerb::ServerDiscover
            | UpstreamVerb::ToolsList
            | UpstreamVerb::PromptsList
            | UpstreamVerb::ResourcesList
            | UpstreamVerb::ResourcesTemplatesList
            | UpstreamVerb::NotificationsRootsListChanged => serde_json::json!({}),
            UpstreamVerb::LoggingSetLevel { level } => serde_json::json!({ "level": level }),
            UpstreamVerb::ToolsCall { name, arguments } => {
                serde_json::json!({ "name": name, "arguments": arguments })
            }
            UpstreamVerb::PromptsGet { name, arguments } => {
                serde_json::json!({ "name": name, "arguments": arguments })
            }
            UpstreamVerb::ResourcesRead { uri }
            | UpstreamVerb::ResourcesSubscribe { uri }
            | UpstreamVerb::ResourcesUnsubscribe { uri } => serde_json::json!({ "uri": uri }),
            UpstreamVerb::SubscriptionsListen { notifications } => {
                serde_json::json!({ "notifications": notifications })
            }
            UpstreamVerb::CompletionComplete {
                reference,
                argument,
            } => serde_json::json!({ "ref": reference, "argument": argument }),
            UpstreamVerb::TasksGet { task_id } | UpstreamVerb::TasksCancel { task_id } => {
                serde_json::json!({ "taskId": task_id })
            }
            UpstreamVerb::TasksUpdate {
                task_id,
                input_responses,
            } => serde_json::json!({ "taskId": task_id, "inputResponses": input_responses }),
            UpstreamVerb::NotificationsCancelled { request_id, reason } => {
                serde_json::json!({ "requestId": request_id, "reason": reason })
            }
            UpstreamVerb::NotificationsProgress {
                progress_token,
                progress,
                total,
            } => serde_json::json!({
                "progressToken": progress_token,
                "progress": progress,
                "total": total,
            }),
            UpstreamVerb::NotificationsElicitationResponse {
                request_id,
                content,
            } => serde_json::json!({ "requestId": request_id, "content": content }),
        }
    }

    /// The `Mcp-Name` header's value: the `params` member `crate::codec::name_source_of` names.
    fn target(&self) -> Option<String> {
        let source = crate::codec::name_source_of(self.method())?;
        self.params()
            .get(source)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }

    /// BUILD the request through the shared envelope. `request_id` is ignored for a notification.
    pub fn build(
        &self,
        url: &str,
        request_id: u64,
        authorization: Option<&str>,
    ) -> OutboundRequest {
        let mut params = self.params();
        if let Some(obj) = params.as_object_mut() {
            obj.insert(
                "_meta".to_string(),
                serde_json::json!({
                    META_PROTOCOL_VERSION: PROTOCOL_VERSION,
                    META_CLIENT_CAPABILITIES: {},
                }),
            );
        }
        let method = self.method();
        let body = if self.is_notification() {
            serde_json::json!({ "jsonrpc": "2.0", "method": method, "params": params })
        } else {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            })
        };
        envelope(url, method, self.target().as_deref(), body, authorization)
    }
}

#[cfg(test)]
#[path = "tests/verb_tests.rs"]
mod verb_tests;
