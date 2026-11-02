// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A CHILD SENDS BUSBAR — classification, the deny-by-default gate on the three authority

use super::super::jsonrpc::ServerAsk;
use super::super::peer::{
    answer, classify, method_not_found, NotificationEffect, ServerMessage, ServerNotification,
    ServerRequestVerb,
};
use crate::client::jsonrpc::ServerRequestGrants;

fn line(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).expect("the fixture is JSON")
}

/// A RESPONSE IS NOT A SERVER MESSAGE, and this is the assertion that keeps the stream in sync.
#[test]
fn a_response_is_never_a_server_message() {
    for raw in [
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{},"method":"sampling/createMessage"}"#,
    ] {
        assert_eq!(
            classify(&line(raw)),
            None,
            "a response must never classify as a server-originated message: {raw}"
        );
    }
}

/// A NOTIFICATION METHOD IS A NOTIFICATION REGARDLESS OF WHAT `id` CARRIES.
#[test]
fn a_notification_method_is_a_notification_even_with_a_null_id() {
    assert_eq!(
        classify(&line(
            r#"{"jsonrpc":"2.0","id":null,"method":"notifications/message","params":{}}"#
        )),
        Some(ServerMessage::Notification(ServerNotification::Message))
    );
}

/// THE HANG THIS MODULE USED TO PRODUCE: A PRESENT-BUT-NULL `id` ON A REQUEST METHOD MUST STILL BE
#[test]
fn a_present_but_null_id_on_a_request_method_is_still_a_request() {
    assert_eq!(
        classify(&line(
            r#"{"jsonrpc":"2.0","id":null,"method":"roots/list","params":{}}"#
        )),
        Some(ServerMessage::Request {
            id: serde_json::Value::Null,
            verb: ServerRequestVerb::RootsList,
        }),
        "an explicit null id on a REQUEST method must still be answered, not silently dropped"
    );
}

/// A TRUE NOTIFICATION — `id` ABSENT ENTIRELY — STILL GETS NO REPLY.
#[test]
fn a_true_notification_with_id_absent_is_still_unanswered() {
    assert_eq!(
        classify(&line(
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#
        )),
        Some(ServerMessage::Notification(ServerNotification::Message))
    );
}

/// AN UNKNOWN REQUEST IS ANSWERED `-32601`. AN UNKNOWN NOTIFICATION IS NOT ANSWERED AT ALL.
#[test]
fn an_unknown_request_is_answered_and_an_unknown_notification_is_not() {
    let Some(ServerMessage::UnknownRequest { id, method }) = classify(&line(
        r#"{"jsonrpc":"2.0","id":5,"method":"totally/unknown","params":{}}"#,
    )) else {
        panic!("an unrecognised request must be classified as one");
    };
    assert_eq!(method, "totally/unknown");
    let reply = method_not_found(&id, &method);
    assert_eq!(reply["id"], 5);
    assert_eq!(reply["error"]["code"], -32601);

    assert_eq!(
        classify(&line(
            r#"{"jsonrpc":"2.0","method":"totally/unknown","params":{}}"#
        )),
        Some(ServerMessage::UnknownNotification("totally/unknown".into())),
        "an unrecognised notification is counted and dropped, never answered"
    );
}

/// `ping` IS ANSWERED UNCONDITIONALLY, and it is the ONLY request that is.
#[test]
fn ping_is_answered_with_an_empty_result_under_no_grants() {
    let id = serde_json::json!(9);
    let reply = answer(
        &id,
        ServerRequestVerb::Ping,
        &ServerRequestGrants::default(),
        "fs",
    )
    .expect("busbar answers a ping itself: it is keepalive, not an ask");
    assert_eq!(reply["id"], 9);
    assert_eq!(reply["result"], serde_json::json!({}));
    assert!(
        reply.get("error").is_none(),
        "a ping is never refused: {reply}"
    );
    assert_eq!(
        ServerRequestVerb::Ping.ask(),
        None,
        "a ping spends no authority, so it must name no grant"
    );
}

/// THE THREE AUTHORITY ASKS ARE DENY-BY-DEFAULT, and the refusal NAMES THE GRANT TO SET.
#[test]
fn the_three_authority_asks_are_denied_by_default_and_name_their_grant() {
    let none = ServerRequestGrants::default();
    for (verb, kind) in [
        (ServerRequestVerb::RootsList, "roots"),
        (ServerRequestVerb::SamplingCreateMessage, "sampling"),
        (ServerRequestVerb::ElicitationCreate, "elicitation"),
    ] {
        let ask = verb.ask().expect("an authority ask names a grant");
        assert_eq!(ask.key(), kind);
        assert!(
            !none.allows(ask),
            "{kind} must be denied when the operator granted nothing"
        );
        let reply = answer(&serde_json::json!(3), verb, &none, "fs")
            .expect("an ungranted ask is refused on the child's input");
        let message = reply["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(&format!("tools.fs.grants.{kind}: true")),
            "the refusal must name the exact key an operator sets: {message}"
        );
        assert_eq!(reply["error"]["code"], -32001, "{reply}");
        assert_eq!(reply["error"]["data"]["reason"], "ask_ungranted", "{reply}");
        assert!(
            reply.get("result").is_none(),
            "a refused ask carries no result: {reply}"
        );
    }
}

/// LAW 11: A GRANTED ASK IS THE CALLER'S, AND BUSBAR WRITES NOTHING IN ITS PLACE. The grant is a
#[test]
fn a_granted_ask_is_relayed_and_never_answered_by_busbar() {
    let all = ServerRequestGrants {
        sampling: true,
        elicitation: true,
        roots: true,
    };
    for (verb, ask) in [
        (
            ServerRequestVerb::SamplingCreateMessage,
            ServerAsk::Sampling,
        ),
        (ServerRequestVerb::ElicitationCreate, ServerAsk::Elicitation),
        (ServerRequestVerb::RootsList, ServerAsk::Roots),
    ] {
        assert!(all.allows(ask), "{}", ask.key());
        assert!(!ServerRequestGrants::default().allows(ask));
        assert_eq!(
            answer(&serde_json::json!(1), verb, &all, "fs"),
            None,
            "busbar answers a granted `{}` ask with nothing: the caller does",
            ask.key()
        );
        assert!(
            answer(
                &serde_json::json!(1),
                verb,
                &ServerRequestGrants::default(),
                "fs"
            )
            .is_some(),
            "an ungranted ask is still refused"
        );
    }
}

/// ONE GRANT DOES NOT OPEN THE OTHER TWO. The three are independent authorities and a table that
#[test]
fn each_grant_opens_only_its_own_ask() {
    let roots_only = ServerRequestGrants {
        roots: true,
        ..ServerRequestGrants::default()
    };
    assert!(roots_only.allows(ServerAsk::Roots));
    assert!(!roots_only.allows(ServerAsk::Sampling));
    assert!(!roots_only.allows(ServerAsk::Elicitation));
}

/// THE FOUR "SOMETHING CHANGED" NOTIFICATIONS CAN ONLY BRING A REFRESH FORWARD, and no others can.
#[test]
fn only_the_change_notifications_trigger_a_refresh() {
    let expected = [
        (ServerNotification::ToolsListChanged, true),
        (ServerNotification::PromptsListChanged, true),
        (ServerNotification::ResourcesListChanged, true),
        (ServerNotification::ResourcesUpdated, true),
        (ServerNotification::Cancelled, false),
        (ServerNotification::Message, false),
        (ServerNotification::SubscriptionsAcknowledged, false),
        (ServerNotification::Tasks, false),
        (ServerNotification::Progress, false),
    ];
    assert_eq!(
        expected.len(),
        9,
        "all nine server notifications must be covered; a shrinking denominator is the failure mode"
    );
    for (n, triggers) in expected {
        assert_eq!(
            matches!(
                n.effect(),
                NotificationEffect::BringRefreshForward | NotificationEffect::RelayResourceUpdate
            ),
            triggers,
            "{n:?} maps to the wrong effect"
        );
    }

    for n in expected.map(|(n, _)| n) {
        assert_eq!(
            n.effect() == NotificationEffect::RelayResourceUpdate,
            n == ServerNotification::ResourcesUpdated,
            "{n:?}: only `resources/updated` records an announcement"
        );
    }
    assert_eq!(
        ServerNotification::Progress.effect(),
        NotificationEffect::RelayProgress,
        "progress is the one notification a caller is entitled to see relayed"
    );
}
