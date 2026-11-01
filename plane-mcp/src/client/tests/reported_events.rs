use super::*;

#[test]
fn an_endpoint_address_rejects_controls_and_backslash_before_the_connector() {
    for address in [
        "/mcp\0tail",
        "/mcp\u{1b}tail",
        "/mcp\u{7f}tail",
        "/mcp\u{85}tail",
        "/mcp\\tail",
    ] {
        assert_eq!(
            message_address("https://up.example/sse", address),
            Err(AddressRefused::Malformed)
        );
    }
    assert_eq!(
        message_address("https://up.example/sse", "/messages?sessionId=a").unwrap(),
        "https://up.example/messages?sessionId=a"
    );
}

#[test]
fn the_first_sse_line_strips_a_bom_across_chunk_boundaries() {
    let mut reader = EventReader::new(1024);
    assert!(reader.feed(&[0xef]).is_empty());
    assert!(reader.feed(&[0xbb, 0xbf]).is_empty());
    let events = reader.feed(b"event: endpoint\r\ndata: /messages\r\n\r\n");
    assert_eq!(
        events,
        vec![StreamEvent {
            event: Some("endpoint".into()),
            data: "/messages".into()
        }]
    );
}

#[test]
fn an_oversized_event_cannot_dispatch_after_crossing_the_existing_bound() {
    let mut reader = EventReader::new(32);
    let events = reader.feed(b"data: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\n");
    assert!(reader.overflowed());
    assert!(
        events.is_empty(),
        "an oversized event is refused even if its terminator is in the same chunk"
    );
}
