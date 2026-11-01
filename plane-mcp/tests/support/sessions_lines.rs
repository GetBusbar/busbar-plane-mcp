// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_session_refuses_non_objects_batches_and_malformed_rpc_envelopes() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let door = open();
    let session = open_session(&door, 20_000, ALICE);
    for (offset, body) in [
        b"[]".as_slice(),
        b"[{}]",
        b"5",
        b"null",
        b"{}",
        br#"{"jsonrpc":"1.0","method":"ping","id":1}"#,
        br#"{"jsonrpc":"2.0","method":3,"id":1}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let answer = session_post(&door, 20_010 + offset as u64, &session, ALICE, body);
        assert_eq!(
            answer.status,
            400,
            "malformed session input was accepted: {}",
            answer.text()
        );
        assert_eq!(answer.json()["error"]["code"], -32600);
    }
    assert_eq!(
        session_post(&door, 20_030, &session, ALICE, INITIALIZED).status,
        202
    );
}

#[test]
fn a_wrong_version_get_or_delete_does_not_open_or_end_the_session() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let door = open();
    let session = open_session(&door, 20_100, ALICE);
    for (unit, method) in [(20_101, "GET"), (20_102, "DELETE")] {
        let fields = [
            ("accept", "text/event-stream"),
            ("mcp-session-id", session.as_str()),
            ("mcp-protocol-version", "2025-11-25"),
        ];
        assert_eq!(
            door.arrive(unit, method, "/mcp", b"", &fields).outcome,
            Outcome::Ready
        );
        let given = if method == "GET" {
            Given::stream_open(ALICE, unit)
        } else {
            Given::caller(ALICE, b"")
        };
        let answer = door.piece(unit, &given);
        assert_eq!(answer.status, 400, "{method}: {}", answer.text());
        assert_eq!(answer.json()["error"]["code"], -32600);
    }
    assert_eq!(listed(&door, 20_103, &session, ALICE).status, 200);
    let fields = [
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    assert_eq!(
        door.arrive(20_104, "DELETE", "/mcp", b"", &fields).outcome,
        Outcome::Ready
    );
    assert_eq!(door.piece(20_104, &Given::caller(ALICE, b"")).status, 200);
    assert_eq!(listed(&door, 20_105, &session, ALICE).status, 404);
}

fn emit_update(door: &Door, unit: u64, multiline: bool) {
    assert_eq!(
        door.arrive(unit, "POST", "/mcp", ST_CALL, ST_FIELDS)
            .outcome,
        Outcome::Ready
    );
    door.piece(unit, &Given::attempt(BOB, "st"));
    assert!(door.piece(unit, &Given::caller(BOB, ST_CALL)).far);
    let note = if multiline {
        "data: {\"jsonrpc\":\"2.0\",\ndata: \"method\":\"notifications/resources/updated\",\ndata: \"params\":{\"uri\":\"file:///readme\"}}\n\n"
    } else {
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\",\"params\":{\"uri\":\"file:///readme\"}}\n\n"
    };
    let far = format!(
        "event: message\n{note}event: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{{\"content\":[],\"resultType\":\"complete\"}}}}\n\n"
    );
    let answer = door.piece(
        unit,
        &Given::far(
            BOB,
            200,
            vec![("content-type", "text/event-stream")],
            far.as_bytes(),
        ),
    );
    assert_eq!(answer.status, 200, "{}", answer.text());
}

fn subscribed_stream(door: &Door, base: u64) -> String {
    let session = open_session(door, base, ALICE);
    let request = br#"{"jsonrpc":"2.0","id":3,"method":"resources/subscribe","params":{"uri":"file:///readme"}}"#;
    assert_eq!(
        session_post(door, base + 1, &session, ALICE, request).status,
        200
    );
    let fields = [
        ("accept", "text/event-stream"),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    assert_eq!(
        door.arrive(base + 2, "GET", "/mcp", b"", &fields).outcome,
        Outcome::Ready
    );
    assert_eq!(
        door.piece(base + 2, &Given::stream_open(ALICE, base + 2))
            .status,
        200
    );
    session
}

#[test]
fn multiline_upstream_resource_notifications_reach_the_subscriber() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let door = open();
    let _session = subscribed_stream(&door, 20_200);
    emit_update(&door, 20_203, true);
    let got = door.piece(20_202, &Given::collect(ALICE, 20_202));
    assert!(
        got.text().contains("notifications/resources/updated"),
        "{}",
        got.text()
    );
}

#[test]
fn a_quiet_resumed_stream_does_not_replay_already_acknowledged_events() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let door = open();
    let session = subscribed_stream(&door, 20_300);
    emit_update(&door, 20_303, false);
    let event = door.piece(20_302, &Given::collect(ALICE, 20_302)).text();
    assert!(event.contains("notifications/resources/updated"), "{event}");
    let cursor = event
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .expect("an event id")
        .to_string();
    door.cancel(20_302);
    let fields = [
        ("accept", "text/event-stream"),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
        ("last-event-id", cursor.as_str()),
    ];
    assert_eq!(
        door.arrive(20_304, "GET", "/mcp", b"", &fields).outcome,
        Outcome::Ready
    );
    let resumed = door.piece(20_304, &Given::stream_open(ALICE, 20_304));
    assert_eq!(resumed.status, 200);
    assert!(!resumed.text().contains("notifications/resources/updated"));
    let again = door.piece(20_304, &Given::collect(ALICE, 20_304));
    assert!(
        !again.text().contains("notifications/resources/updated"),
        "the cursor was reset: {}",
        again.text()
    );
}

#[test]
fn a_refused_extra_stream_leaves_the_old_stream_delivering_real_updates() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let door = open();
    let session = subscribed_stream(&door, 20_400);
    let fields = [
        ("accept", "text/event-stream"),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    let mut unit = 20_403;
    loop {
        assert_eq!(
            door.arrive(unit, "GET", "/mcp", b"", &fields).outcome,
            Outcome::Ready
        );
        let opened = door.piece(unit, &Given::stream_open(ALICE, unit));
        if opened.status != 200 {
            assert_eq!(opened.status, 429, "{}", opened.text());
            break;
        }
        unit += 1;
    }
    emit_update(&door, unit + 1, false);
    let delivered = door.piece(20_402, &Given::collect(ALICE, 20_402));
    assert!(!delivered.done, "the original stream is still open");
    assert!(
        delivered.text().contains("notifications/resources/updated"),
        "the original stream still delivers after the refusal: {}",
        delivered.text()
    );
}
