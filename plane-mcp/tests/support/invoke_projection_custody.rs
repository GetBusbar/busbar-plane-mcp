use super::*;
use busbar_contract::abi::hook::{MessageView, SignalEntry};
use busbar_contract::abi::plane::{ProjectIn, ProjectOut};

fn project(
    d: &Door,
    body: &[u8],
    rewrite: &[u8],
    capacity: usize,
) -> (Outcome, ProjectOut, Vec<u8>) {
    let mut arena = vec![0u8; capacity];
    let mut messages = [z::<MessageView>(); 4];
    let mut signals = [z::<SignalEntry>(); 4];
    let mut input = z::<ProjectIn>();
    input.head = head::<ProjectIn>(slot::PROJECT, Ticket::NONE);
    input.body = octets(body);
    input.rewrite = octets(rewrite);
    input.arena_buf = arena.as_mut_ptr();
    input.arena_cap = arena.len();
    input.messages_buf = messages.as_mut_ptr();
    input.messages_cap = messages.len();
    input.signals_buf = signals.as_mut_ptr();
    input.signals_cap = signals.len();
    let mut output = z::<ProjectOut>();
    output.head = out_head::<ProjectOut>();
    // SAFETY: The fixture owns this live door instance; the exact input/output frames and every borrowed buffer remain live throughout the synchronous call.
    let answer = unsafe {
        ops().project.unwrap()(
            d.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    (answer.outcome(), output, arena)
}

fn body(arena: &[u8], output: &ProjectOut) -> Vec<u8> {
    let start = output.body.offset as usize;
    arena[start..start + output.body.len as usize].to_vec()
}

#[test]
fn invocation_projection_keeps_exact_wire_shape_on_success_short_retry_and_rewrite() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open();
    let request = br#"{"method":"tools/call","params":{"name":"fs_read_file","arguments":{"nested":{"private-key":"private-value"},"n":9007199254740993}},"unused":"not projected"}"#;
    let expected = br#"{"arguments":{"n":9007199254740993,"nested":{"private-key":"private-value"}},"tool":"fs_read_file"}"#;
    let (outcome, short, _) = project(&d, request, &[], 0);
    assert_eq!(outcome, Outcome::Failed);
    assert!(short.arena_needed > 0);
    let (outcome, output, arena) = project(&d, request, &[], short.arena_needed as usize);
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(body(&arena, &output), expected);
    let rewrite = br#"{"messages":[{"content":{"replacement":"after"}}]}"#;
    let (outcome, output, arena) = project(&d, request, rewrite, 4096);
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(
        body(&arena, &output),
        br#"{"arguments":{"replacement":"after"},"tool":"fs_read_file"}"#
    );
    let start = output.rewritten.offset as usize;
    let rewritten: Value =
        serde_json::from_slice(&arena[start..start + output.rewritten.len as usize]).unwrap();
    assert_eq!(
        rewritten["params"]["arguments"],
        json!({"replacement":"after"})
    );
    let (outcome, output, _) = project(
        &d,
        br#"{"method":"ping","params":{"unused":"private-value"}}"#,
        &[],
        64,
    );
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(output.body.offset, busbar_contract::abi::plane::SPAN_ABSENT);
}
