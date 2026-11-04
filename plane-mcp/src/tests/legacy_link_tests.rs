// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The held `2024-11-05` link's reading of its stream: the message address named once and
//! only on the endpoint's origin, answers handed only to the call waiting for their id,
//! once, and the waiting calls bounded.

use super::*;

#[path = "legacy_retention_regressions.rs"]
mod retention;

fn link() -> Link {
    let template = crate::client::jsonrpc::envelope(
        "https://up.example/events",
        "tools/call",
        None,
        crate::codec::json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"})),
        None,
    );
    Link::new(1, "https://up.example/events", "fs", &template)
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

/// Feeds `raw` (whole events) and answers the calls it woke.
fn feed(l: &mut Link, raw: &str) -> Vec<Ticket> {
    let (mut woken, mut announced) = (Vec::new(), Announced::new());
    l.events(
        raw.as_bytes(),
        ServerRequestGrants::default(),
        &mut woken,
        &mut announced,
    );
    woken
}

#[test]
fn a_link_is_ready_once_and_answers_only_what_it_waits_for() {
    let mut l = link();
    assert_eq!(l.address, None);
    l.parked.push(ticket(1));
    let woken = feed(&mut l, "event: endpoint\ndata: /messages?sessionId=a\n\n");
    assert_eq!(
        l.address.as_deref(),
        Some("https://up.example/messages?sessionId=a")
    );
    assert_eq!(woken, vec![ticket(1)], "the parked call is woken");
    feed(&mut l, "event: endpoint\ndata: /elsewhere\n\n");
    assert_eq!(
        l.address.as_deref(),
        Some("https://up.example/messages?sessionId=a"),
        "the address is named once"
    );
    assert!(l.wait(7, ticket(2)));
    let answer = r#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
    let woken = feed(&mut l, &format!("event: message\ndata: {answer}\n\n"));
    assert_eq!(woken, vec![ticket(2)]);
    assert_eq!(
        l.answers.get("7").map(|(t, b)| (*t, b.as_slice())),
        Some((ticket(2), answer.as_bytes()))
    );
    l.answers.clear();
    feed(&mut l, &format!("event: message\ndata: {answer}\n\n"));
    assert!(l.answers.is_empty(), "answered once");
    assert_eq!(l.dropped, 1, "a second answer is a reply no call waits for");
    let note = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
    feed(&mut l, &format!("data: {note}\n\n"));
    assert!(l.answers.is_empty() && l.outbox.is_empty() && l.dead.is_none());
}

#[test]
fn the_waiting_calls_are_bounded() {
    let mut l = link();
    for id in 0..MAX_WAITING as u64 {
        assert!(l.wait(id, ticket(1)));
    }
    assert!(!l.wait(u64::MAX, ticket(1)), "bounded");
    l.waiters.remove("0");
    assert!(l.wait(u64::MAX, ticket(1)));
}

#[test]
fn red_a_link_refuses_a_cross_origin_endpoint() {
    let mut l = link();
    l.parked.push(ticket(3));
    let woken = feed(&mut l, "event: endpoint\ndata: https://evil.example/m\n\n");
    assert_eq!(l.address, None);
    assert!(
        l.dead.is_some(),
        "a stream naming another origin is unusable"
    );
    assert_eq!(woken, vec![ticket(3)], "and its parked calls learn why");
}

#[test]
fn retired_generations_are_never_reused() {
    let first = next_generation().unwrap();
    let second = next_generation().unwrap();
    assert!(second > first);
}

#[test]
fn death_keeps_woken_call_ownership_until_failure_is_consumed() {
    let mut l = link();
    l.wait(7, ticket(1));
    l.parked.push(ticket(2));
    let mut woken = Vec::new();
    l.die("launch refused", &mut woken);
    assert_eq!(l.failed, vec![ticket(1), ticket(2)]);
    assert_eq!(woken, l.failed);
    assert_eq!(l.dead.as_deref(), Some("launch refused"));
}

#[test]
fn malformed_event_json_fails_waiting_calls() {
    let mut l = link();
    l.wait(7, ticket(1));
    let woken = feed(&mut l, "event: message\ndata: {broken\n\n");
    assert!(l.dead.as_deref().unwrap().contains("malformed JSON"));
    assert!(woken.contains(&ticket(1)));
}

#[test]
fn reply_queue_overflow_fails_the_link_loudly() {
    let mut l = link();
    for _ in 0..MAX_OUTBOX {
        l.outbox.push_back(Vec::new());
    }
    feed(
        &mut l,
        "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n\n",
    );
    assert!(l.dead.as_deref().unwrap().contains("reply queue limit"));
    assert_eq!(l.outbox.len(), MAX_OUTBOX);
}

#[test]
fn failed_call_post_releases_retained_progress_bytes() {
    let plane = McpDoor::default();
    let mut l = link();
    l.init = Init::Done;
    l.address = Some("https://up.example/messages".into());
    l.wait(7, ticket(1));
    l.notes
        .insert("7".into(), vec![serde_json::json!({"progress":1})]);
    l.notes_bytes.insert("7".into(), 14);
    plane.legacy.insert("key".into(), l);
    let request = crate::client::jsonrpc::envelope(
        "https://up.example/events",
        "tools/call",
        None,
        crate::codec::json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call"})),
        None,
    );
    let mut state = Some(Calling {
        generation: 1,
        id: Some(7),
        posted: false,
        init: CallInit::Done,
    });
    let answer = call_using(
        ticket(1),
        &plane,
        ("key", "fs"),
        &request,
        &mut state,
        (0, 1000),
        |_, _, _| Poll::Ready(Err("POST failed".into())),
    );
    assert!(matches!(answer, Poll::Ready(Err(_))));
    plane.legacy.with(&"key".to_string(), |l| {
        let l = l.unwrap();
        assert!(l.notes.is_empty());
        assert!(l.notes_bytes.is_empty());
        assert!(l.waiters.is_empty());
    });
}

#[test]
fn peer_reply_post_requires_a_successful_final_head() {
    for code in [200, 202, 204, 299] {
        assert_eq!(
            reply_step(&ReplyPiece {
                kind: REPLY_HEAD,
                code,
                ..ReplyPiece::default()
            }),
            Some(ReplyStep::Close)
        );
    }
    for code in [101, 300, 400, 500, 503] {
        assert_eq!(
            reply_step(&ReplyPiece {
                kind: REPLY_HEAD,
                code,
                ..ReplyPiece::default()
            }),
            None
        );
    }
    for kind in [REPLY_END, REPLY_ACK] {
        assert_eq!(
            reply_step(&ReplyPiece {
                kind,
                ..ReplyPiece::default()
            }),
            None
        );
    }
    assert_eq!(
        reply_step(&ReplyPiece {
            kind: REPLY_HEAD,
            code: 100,
            ..ReplyPiece::default()
        }),
        Some(ReplyStep::Read)
    );
}
