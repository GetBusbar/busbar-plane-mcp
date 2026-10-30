// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The held `2024-11-05` link's reading of its stream: the message address named once and only on
//! the endpoint's origin, answers handed only to the call waiting for their id, once, and the
//! waiting calls bounded.

use super::*;

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
