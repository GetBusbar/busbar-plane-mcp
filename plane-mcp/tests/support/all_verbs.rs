// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// ONE INSTANCE OF EVERY `UpstreamVerb` VARIANT, for the tests that enumerate the surface; included
// (`include!`) where `UpstreamVerb` is in scope. A new variant is added here by hand: the inventory
// test counts these against the generated matrix.
fn all_verbs() -> Vec<UpstreamVerb> {
    vec![
        UpstreamVerb::Initialize {
            client_version: "0.0.0",
        },
        UpstreamVerb::NotificationsInitialized,
        UpstreamVerb::Ping,
        UpstreamVerb::ServerDiscover,
        UpstreamVerb::LoggingSetLevel {
            level: "info".to_string(),
        },
        UpstreamVerb::ToolsList,
        UpstreamVerb::ToolsCall {
            name: "read".to_string(),
            arguments: serde_json::json!({}),
        },
        UpstreamVerb::PromptsList,
        UpstreamVerb::PromptsGet {
            name: "greet".to_string(),
            arguments: serde_json::json!({}),
        },
        UpstreamVerb::ResourcesList,
        UpstreamVerb::ResourcesTemplatesList,
        UpstreamVerb::ResourcesRead {
            uri: "file:///a".to_string(),
        },
        UpstreamVerb::ResourcesSubscribe {
            uri: "file:///a".to_string(),
        },
        UpstreamVerb::ResourcesUnsubscribe {
            uri: "file:///a".to_string(),
        },
        UpstreamVerb::SubscriptionsListen {
            notifications: serde_json::json!({ "toolsListChanged": true }),
        },
        UpstreamVerb::CompletionComplete {
            reference: serde_json::json!({ "type": "ref/prompt", "name": "greet" }),
            argument: serde_json::json!({ "name": "who", "value": "b" }),
        },
        UpstreamVerb::TasksGet {
            task_id: "t1".to_string(),
        },
        UpstreamVerb::TasksUpdate {
            task_id: "t1".to_string(),
            input_responses: serde_json::json!([]),
        },
        UpstreamVerb::TasksCancel {
            task_id: "t1".to_string(),
        },
        UpstreamVerb::NotificationsCancelled {
            request_id: serde_json::json!(7),
            reason: "the caller withdrew".to_string(),
        },
        UpstreamVerb::NotificationsProgress {
            progress_token: serde_json::json!("busbar-7"),
            progress: 0.5,
            total: Some(1.0),
        },
        UpstreamVerb::NotificationsRootsListChanged,
        UpstreamVerb::NotificationsElicitationResponse {
            request_id: serde_json::json!(9),
            content: serde_json::json!({ "answer": "yes" }),
        },
    ]
}
