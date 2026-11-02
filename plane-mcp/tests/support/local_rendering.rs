// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Existing door API regressions for local repeated-placeholder answers. The allocation witness

use super::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static LARGEST: Cell<Option<usize>> = const { Cell::new(None) };
}

struct AllocationWitness;

fn allocated(size: usize) {
    let _ = LARGEST.try_with(|largest| {
        if let Some(old) = largest.get() {
            largest.set(Some(old.max(size)));
        }
    });
}

// SAFETY: every allocation is forwarded unchanged to the system allocator. The const-initialized
// thread-local Cell neither allocates nor owns a destructor, so observation cannot re-enter it.
unsafe impl GlobalAlloc for AllocationWitness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocated(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocated(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocated(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATION_WITNESS: AllocationWitness = AllocationWitness;

struct Crossing {
    outcome: Outcome,
    output: OnPieceOut,
    bytes: Vec<u8>,
    fields: Vec<(String, String)>,
    largest: usize,
}

fn crossing(
    d: &Door,
    unit: u64,
    body: &[u8],
    capacity: usize,
    arena_cap: usize,
    resume: bool,
) -> Crossing {
    let mut reply = vec![0u8; capacity];
    let mut arena = vec![0u8; arena_cap];
    let mut fields = [z::<OutField>(); 16];
    let mut units = [z::<UnitCount>(); 8];
    let mut records = [z::<RecordWrite>(); 16];
    let mut input = z::<OnPieceIn>();
    input.head = head::<OnPieceIn>(
        slot::ON_PIECE,
        Ticket {
            slot: unit.try_into().unwrap(),
            generation: 1,
        },
    );
    if resume {
        input.head.flags |= FLAG_RESUME;
    }
    input.unit = unit;
    input.from = FROM_CALLER;
    input.flags = if resume { 0 } else { PIECE_LAST };
    input.caller_ref = str_of(ALICE);
    input.bytes = octets(body);
    input.reply_buf = reply.as_mut_ptr();
    input.reply_cap = reply.len();
    input.arena_buf = arena.as_mut_ptr();
    input.arena_cap = arena.len();
    input.fields_buf = fields.as_mut_ptr();
    input.fields_cap = fields.len();
    input.units_buf = units.as_mut_ptr();
    input.units_cap = units.len();
    input.records_buf = records.as_mut_ptr();
    input.records_cap = records.len();
    let mut output = z::<OnPieceOut>();
    output.head = out_head::<OnPieceOut>();
    LARGEST.with(|largest| largest.set(Some(0)));
    // SAFETY: these are the actual slot's live, correctly sized input, output and loan buffers.
    let answer = unsafe {
        ops().on_piece.unwrap()(
            d.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    let largest = LARGEST.with(|largest| largest.take().unwrap());
    reply.truncate(output.emitted.try_into().unwrap());
    let span = |s: busbar_contract::abi::mechanism::call::Span| {
        let start = s.offset as usize;
        String::from_utf8(arena[start..start + s.len as usize].to_vec()).unwrap()
    };
    let fields = fields[..output.fields_written as usize]
        .iter()
        .map(|field| (span(field.name), span(field.value)))
        .collect();
    Crossing {
        outcome: answer.outcome(),
        output,
        bytes: reply,
        fields,
        largest,
    }
}

fn request(method: &str, params: Value) -> Vec<u8> {
    let mut params = params;
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":60000,"method":method,"params":params}))
        .unwrap()
}

fn section(template: &str) -> String {
    json!({"fs":{"url":"https://up.example/st","pin":{"mechanism":"unpinned"},
        "prompts_allow":{"repeat":{"template":template}},
        "resource_templates_allow":{"file:///logs/{value}":{"text":template}}
    }})
    .to_string()
}

fn begin(d: &Door, unit: u64, method: &str, body: &[u8], accept: &str) {
    let value: Value = serde_json::from_slice(body).unwrap();
    let name = value["params"][if method == "resources/read" {
        "uri"
    } else {
        "name"
    }]
    .as_str()
    .unwrap();
    let fields = [
        ("accept", accept),
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", method),
        ("mcp-name", name),
    ];
    assert_eq!(
        d.arrive(unit, "POST", "/mcp", body, &fields).outcome,
        Outcome::Ready
    );
}

#[test]
fn repeated_prompt_and_resource_answers_stream_past_an_upstream_reply_limit_without_expanded_allocations(
) {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);

    let argument = "x".repeat(65536);
    let copies = 257;
    let expanded = argument.len() * copies;
    let template = "{value}".repeat(copies);
    let d = open_with(&section(&template));
    for (unit, method) in [(60000, "prompts/get"), (60001, "resources/read")] {
        let uri = format!("file:///logs/{argument}");
        let (params, prefix, suffix) = if method == "prompts/get" {
            (json!({"name":"fs_repeat","arguments":{"value":argument}}),
             "{\"id\":60000,\"jsonrpc\":\"2.0\",\"result\":{\"messages\":[{\"content\":{\"text\":\"".to_string(),
             "\",\"type\":\"text\"},\"role\":\"user\"}],\"resultType\":\"complete\"}}".to_string())
        } else {
            (json!({"uri":uri}),
             "{\"id\":60000,\"jsonrpc\":\"2.0\",\"result\":{\"cacheScope\":\"private\",\"contents\":[{\"text\":\"".to_string(),
             format!("\",\"uri\":{}}}],\"resultType\":\"complete\",\"ttlMs\":0}}}}",serde_json::to_string(&uri).unwrap()))
        };
        let body = request(method, params);
        begin(&d, unit, method, &body, "application/json");
        let short = crossing(&d, unit, &body, 1, 0, false);
        assert_eq!(short.outcome, Outcome::Failed);
        assert!(short.output.arena_needed > 0);
        assert_eq!(short.output.emitted, 0);
        assert!(
            short.largest < expanded,
            "the crossing allocated the expanded answer: {} bytes",
            short.largest
        );
        let expected_len = prefix.len() + expanded + suffix.len();
        let mut expected = prefix
            .bytes()
            .chain((0..copies).flat_map(|_| argument.bytes()))
            .chain(suffix.bytes());
        let mut first = true;
        let mut total = 0;
        let mut reported_units = 0;
        loop {
            let part = crossing(&d, unit, b"", if first { 1 } else { 8192 }, 4096, true);
            assert_eq!(part.outcome, Outcome::Ready);
            assert!(
                part.largest < expanded,
                "a resumption allocated the expanded answer"
            );
            reported_units += part.output.units_written;
            if first {
                assert_eq!(part.output.reply_status, 200);
                assert_eq!(
                    field_of(&part.fields, "content-length"),
                    Some(expected_len.to_string().as_str())
                );
            } else {
                assert_eq!(part.output.fields_written, 0);
                assert_eq!(part.output.units_written, 0);
            }
            for byte in &part.bytes {
                assert_eq!(Some(*byte), expected.next(), "wire byte {total}");
                total += 1;
            }
            if part.output.more == 0 {
                assert_ne!(part.output.flags & EMIT_DONE, 0);
                break;
            }
            assert!(!part.bytes.is_empty());
            first = false;
        }
        assert_eq!(total, expected_len);
        assert_eq!(expected.next(), None);
        assert_eq!(
            reported_units, 1,
            "the completed answer earns its one existing fee unit"
        );
    }
}

#[test]
fn a_partial_local_answer_can_be_cancelled_before_a_new_answer_is_served() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open_with(&section("before {value} after"));
    let body = request(
        "prompts/get",
        json!({"name":"fs_repeat","arguments":{"value":"<a>one</a>"}}),
    );
    begin(&d, 60010, "prompts/get", &body, "application/json");
    let first = crossing(&d, 60010, &body, 1, 4096, false);
    assert_eq!(first.outcome, Outcome::Ready);
    assert_eq!(first.output.more, 1);
    assert_eq!(d.cancel(60010).0, Outcome::Ready);
    begin(&d, 60011, "prompts/get", &body, "application/json");
    let next = d.piece(60011, &Given::caller(ALICE, &body));
    assert_eq!(
        next.json()["result"]["messages"][0]["content"]["text"],
        json!("before one after")
    );
}

#[test]
fn a_slash_reconstituted_with_an_earlier_opener_stays_retractable_across_substitution() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for (index, (template, argument)) in [("{value}", "<<a>/<a>b>"), ("<<a>/{value}b>", "<a>")]
        .into_iter()
        .enumerate()
    {
        let d = open_with(&section(template));
        let body = request(
            "prompts/get",
            json!({"name":"fs_repeat","arguments":{"value":argument}}),
        );
        let unit = 60050 + index as u64;
        begin(&d, unit, "prompts/get", &body, "application/json");
        let answer = d.piece(unit, &Given::caller(ALICE, &body));
        assert_eq!(
            answer.json()["result"]["messages"][0]["content"]["text"],
            json!("")
        );
    }
}

#[test]
fn a_local_result_keeps_its_json_when_framed_as_an_event_stream() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open_with(&section("prefix {value} suffix"));
    let body = request(
        "prompts/get",
        json!({"name":"fs_repeat","arguments":{"value":"<a>one</a>\n\"é"}}),
    );
    begin(&d, 60020, "prompts/get", &body, "application/json");
    let plain = d.piece(60020, &Given::caller(ALICE, &body));
    begin(
        &d,
        60021,
        "prompts/get",
        &body,
        "text/event-stream, application/json",
    );
    let streamed = d.piece(60021, &Given::caller(ALICE, &body));
    assert_eq!(streamed.field("content-type"), Some("text/event-stream"));
    assert_eq!(streamed.field("content-length"), None);
    let text = streamed.text();
    let results: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value.get("result").is_some())
        .collect();
    assert_eq!(results, vec![plain.json()]);
    assert!(text.ends_with("\n\n"));
}

#[test]
fn the_line_carrier_writes_a_local_result_as_one_compact_document() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open_with(&section("before {value} after"));
    let body = request(
        "prompts/get",
        json!({"name":"fs_repeat","arguments":{"value":"one\n\"é"}}),
    );
    assert_eq!(d.line(60025, 900, &body).outcome, Outcome::Ready);
    let answer = d.piece(60025, &Given::caller(ALICE, &body));
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.json()["result"]["messages"][0]["content"]["text"],
        json!("before one\n\"é after")
    );
    assert!(!answer.bytes.contains(&b'\n'));
    assert!(!answer.bytes.contains(&b'\r'));
}

#[test]
fn a_legacy_message_transfers_local_content_to_its_held_stream_in_revision_shape() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open_with(&section("prefix {value} suffix"));
    assert_eq!(
        d.arrive(
            60030,
            "GET",
            "/mcp",
            b"",
            &[("accept", "text/event-stream")]
        )
        .outcome,
        Outcome::Ready
    );
    let opened = d.piece(60030, &Given::stream_open(ALICE, 60030));
    let text = opened.text();
    let endpoint = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    assert!(endpoint.starts_with("/mcp?"));
    let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":32,"method":"prompts/get",
        "params":{"name":"fs_repeat","arguments":{"value":"<a>one</a>"}}}))
    .unwrap();
    assert_eq!(
        d.arrive(
            60031,
            "POST",
            endpoint,
            &body,
            &[("accept", "application/json, text/event-stream")]
        )
        .outcome,
        Outcome::Ready
    );
    let accepted = d.piece(60031, &Given::caller(ALICE, &body));
    assert_eq!(accepted.status, 202);
    assert!(accepted.bytes.is_empty());
    let delivered = d.piece(60030, &Given::collect(ALICE, 60030));
    let text = delivered.text();
    let result: Value = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .map(|line| serde_json::from_str(line).unwrap())
        .unwrap();
    assert_eq!(result["id"], json!(32));
    assert_eq!(
        result["result"],
        json!({"messages":[{"role":"user","content":{"type":"text","text":"prefix one suffix"}}]})
    );
    assert!(!text.lines().any(|line| line.starts_with("id: ")));
    assert_eq!(d.cancel(60030).0, Outcome::Ready);
}
