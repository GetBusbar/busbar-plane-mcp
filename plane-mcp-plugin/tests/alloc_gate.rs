// SPDX-License-Identifier: Apache-2.0
//! The stdio message parser's allocation bound, measured on the actual production source.
#[allow(dead_code)]
#[path = "../../plane-mcp/src/program_frames.rs"]
mod program_frames;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
thread_local! { static ALLOCATIONS: Cell<u64> = const { Cell::new(0) }; }
struct MessageParserAllocator;
fn note_allocation() {
    let _ = ALLOCATIONS.try_with(|count| count.set(count.get().saturating_add(1)));
}
// SAFETY: all allocation operations forward their arguments unchanged to System; the
// thread-local integer counts alloc, zeroed alloc and realloc calls without allocating.
unsafe impl GlobalAlloc for MessageParserAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        note_allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static PARSER_ALLOCATOR: MessageParserAllocator = MessageParserAllocator;
#[test]
fn a_childs_message_read_in_small_pieces_is_parsed_once() {
    use program_frames::{Frames, Message};
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
    let before = ALLOCATIONS.with(Cell::get);
    {
        for piece in message.chunks(64) {
            read.extend(frames.push(piece));
        }
    }
    let count = ALLOCATIONS.with(Cell::get) - before;
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
