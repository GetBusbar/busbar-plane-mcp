//! What reading a stdio child's message is allowed to allocate. Moved in from `tests/` when the
//! crate's only public item became `door`.
//!
//! NOT WIRED: this module is not declared in `src/tests/mod.rs`, so it does not compile or run. It
//! counts allocations through `busbar_contract::alloc_counter::Counting` (busbar-contract's
//! `alloc-counter` dev-dependency feature, ARCHITECT addendum 2026-10-21 08:30Z), installed as this
//! crate's test build's one `#[global_allocator]`; no plugin crate holds `unsafe` for an allocator.
//! The busbar pin (#1399's line) does not carry that feature yet: the gate is wired, with its budget
//! unchanged, at the repin that carries it.
//!
//! An allocation COUNT is the same number on every machine, so work that grows with the input
//! where it should not is seen here where a stopwatch on a shared runner would miss it. (The
//! decode-allocation pin that lived here drove the unserved `Plane` impl, deleted with it under
//! plane-mcp finding 12.)

// Wired at the repin that carries `alloc-counter`:
// #[global_allocator]
// static A: busbar_contract::alloc_counter::Counting = busbar_contract::alloc_counter::Counting::new();
// and `allocations_of` reads its count.

/// RED (finding 14, the design's no-blocking rule: bounded work): a stdio child's message arriving
/// in many small pieces is read ONCE. Re-parsing everything held on every piece builds and drops
/// the message's completed part once per piece: quadratic in its size (a multi-megabyte tool result
/// costs seconds of worker CPU per lease). Scanning only the new bytes and parsing only a whole
/// message keeps the count linear: one parse's worth of allocations and the buffer's growth.
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
