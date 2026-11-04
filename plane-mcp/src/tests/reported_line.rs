use super::*;

#[test]
fn a_line_answer_preserves_json_bytes_without_physical_line_breaks() {
    let plane = McpDoor::default();
    let mut unit = host_check_unit();
    unit.line = Some(LineUnit {
        session: 1,
        ..LineUnit::default()
    });
    let raw = b"{\r\n\"jsonrpc\":\"2.0\",\n\"id\":7,\n\"result\":{\"n\":1.00,\"text\":\"line\\nquote\\\"\",\"content\":[]}}";
    unit.pending = Some(Pending::answer(200, raw.to_vec(), None, &[]));
    liven(&plane, Ticket::NONE, &mut unit);
    let bytes = &unit.pending.as_ref().unwrap().bytes;
    assert!(!bytes.contains(&b'\n') && !bytes.contains(&b'\r'));
    assert!(
        bytes.windows(4).any(|part| part == b"1.00"),
        "number spelling is retained"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(bytes).unwrap(),
        serde_json::from_slice::<Value>(raw).unwrap()
    );
}

#[test]
fn a_duplicate_line_reply_cannot_answer_a_queued_key_or_extend_the_deadline() {
    let plane = McpDoor::default();
    let original = json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fs_read_file","arguments":{}}});
    let result = json!({"resultType":"input_required","inputRequests":{"a":{"method":"roots/list"},"b":{"method":"roots/list"}},"requestState":"sealed"});
    let mut live = LiveAsk::of(original, b"{}".to_vec(), &result, 0).unwrap();
    live.arm(1);
    let original_deadline = live.deadline_ns;
    live.issue(7).unwrap();
    plane.live_asks.insert((1, 7), live);
    let reply = br#"{"jsonrpc":"2.0","id":"busbar:7","result":{"roots":[]}}"#;
    let first = arrive(&plane, 1, reply);
    assert!(first.dispatch.is_none());
    assert!(first.unit.next_ask.is_some());
    assert!(
        plane.live_asks.get(&(1, 7)).is_none(),
        "the answered id is retired before the next emit"
    );
    let second = arrive(&plane, 1, reply);
    assert!(second.dispatch.is_none() && second.unit.next_ask.is_none());
    plane.live_asks.with_all(|asks| {
        assert_eq!(asks.len(), 1);
        let live = asks.values().next().unwrap();
        assert_eq!(live.responses.len(), 1);
        assert!(!live.responses.contains_key(""));
        assert_eq!(live.deadline_ns, original_deadline);
        assert!(!live.lapsed(original_deadline - 1));
        assert!(
            live.lapsed(original_deadline),
            "the queued ask retains the old expiry until emitted"
        );
    });
}
