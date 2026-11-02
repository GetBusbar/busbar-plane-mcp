//! What reading a stdio child's message is allowed to allocate. Moved in from `tests/` when the

use busbar_test_kit::alloc_counter::allocations_of;

#[test]
fn a_childs_message_read_in_small_pieces_is_parsed_once() {
    use crate::tool_program::{Frames, Message};
    use serde_json::{json, Value};
    const ITEMS: u64 = 2000;
    let content: Vec<Value> = (0..ITEMS)
        .map(|i| json!({"type": "text", "text": format!("t{i}")}))
        .collect();
    let message =
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 7, "result": {"content": content}}))
            .unwrap();
    let mut frames = Frames::default();
    let mut read = Vec::with_capacity(4);
    let count = allocations_of(|| {
        for piece in message.chunks(64) {
            read.extend(frames.push(piece));
        }
    });
    println!(
        "{} bytes in {} pieces: {count} allocations",
        message.len(),
        message.len().div_ceil(64)
    );
    assert_eq!(
        read,
        vec![Message::Value(serde_json::from_slice(&message).unwrap())],
        "the message is read whole, once"
    );
    assert!(
        count < 20 * ITEMS,
        "reading one {}-byte message in 64-byte pieces allocated {count} times: what is held is \
         re-parsed on every piece",
        message.len()
    );
}
