// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const URL: &str = "https://pages.example/mcp";
static MODE: AtomicU64 = AtomicU64::new(0);

fn page(body: &Value) -> Value {
    let cursor = body.pointer("/params/cursor").and_then(Value::as_str);
    match (MODE.load(Ordering::SeqCst), cursor) {
        (1, None) => json!({"tools":[{"name":"first"}],"nextCursor":"again"}),
        (1, Some(_)) => json!({"tools":[{"name":"second"}],"nextCursor":"again"}),
        (5, None) => json!({"tools":[{"name":"duplicate"}],"nextCursor":"again"}),
        (5, Some(_)) => json!({"tools":[{"name":"duplicate"}]}),
        (2, Some(_)) => json!({"tools": false}),
        (3, _) => json!({"tools":[{"name":"single"}]}),
        (6, _) => json!({"tools":[{"name":"single"}],"nextCursor":null}),
        (4, Some(cursor)) => {
            let Ok(n) = cursor.parse::<usize>() else {
                return json!({"tools":false});
            };
            json!({"tools":[{"name":format!("tool{n}")}],"nextCursor":(n+1).to_string()})
        }
        (4, None) => json!({"tools":[{"name":"tool0"}],"nextCursor":"1"}),
        (_, None) => json!({"tools":[{"name":"first"}],"nextCursor":"second"}),
        (_, Some("second")) => json!({"tools":[{"name":"second"}],"nextCursor":"third"}),
        (_, Some("third")) => json!({"tools":[{"name":"third"}]}),
        _ => json!({"tools":false}),
    }
}

pub(super) fn http_reply(url: &str, body: &Value) -> Option<Reply> {
    url.starts_with(URL).then(|| {
        if body["method"] != "tools/list" {
            return (503, json_head(), Vec::new());
        }
        let status = if body.pointer("/params/cursor").is_some() {
            match MODE.load(Ordering::SeqCst) {
                7 => 500,
                8 => 401,
                9 => 429,
                _ => 200,
            }
        } else {
            200
        };
        (status, json_head(), rpc_result(&body["id"], page(body)))
    })
}

fn http_section() -> String {
    json!({"pg":{"url":URL,"pin":{"mechanism":"unpinned"},"tools_allow":{"first":{},"second":{},"third":{}}}}).to_string()
}

#[test]
fn operator_connect_observes_every_tool_list_page_before_publishing() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    MODE.store(0, Ordering::SeqCst);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(&http_section());
    let served = d.connect(930, "pg");
    assert_eq!(view_of(&served), (Value::Null, json!(3)));
    let requests = seen();
    let lists: Vec<_> = requests.iter().filter(|s| s.url.starts_with(URL)).collect();
    assert_eq!(lists.len(), 3);
    assert!(lists[0].body["params"].get("cursor").is_none());
    assert_eq!(lists[1].body["params"]["cursor"], "second");
    assert_eq!(lists[2].body["params"]["cursor"], "third");
}

#[test]
fn incomplete_or_looping_lists_never_publish_a_partial_catalogue() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for mode in [1, 2, 4, 5] {
        MODE.store(mode, Ordering::SeqCst);
        *upstreams() = Some(Upstreams::default());
        let d = open_with(&http_section());
        let served = d.connect(931 + mode, "pg");
        let (failure, count) = view_of(&served);
        assert!(failure.is_string(), "{mode}: {served:?}");
        if mode == 4 {
            assert!(failure.as_str().unwrap().contains("service-handle range"));
        }
        assert_eq!(count, 0, "no partial observation is published");
        assert!(lists_to(URL) > 1, "the next page was actually requested");
    }
}

#[test]
fn verify_on_call_fetches_the_complete_list_before_forwarding() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    MODE.store(0, Ordering::SeqCst);
    *upstreams() = Some(Upstreams::default());
    *book() = None;
    let d = open_with(&http_section());
    let call = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"pg_second","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let fields = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "pg_second"),
    ];
    assert_eq!(
        d.arrive(944, "POST", "/mcp", call, &fields).outcome,
        Outcome::Ready
    );
    d.piece(944, &Given::attempt(ALICE, "pg"));
    let sent = d.piece(944, &Given::caller(ALICE, call));
    assert!(sent.far, "{}", sent.text());
    assert_eq!(lists_to(URL), 3);
}

#[derive(Default)]
struct ProgramState {
    next: u64,
    streams: HashMap<u64, (bool, bool, VecDeque<Vec<u8>>)>,
    requests: Vec<Value>,
    handles: Vec<busbar_contract::abi::mechanism::ticket::CompletionHandle>,
    reused_handle: bool,
}

impl ProgramState {
    fn completed(&mut self, handle: busbar_contract::abi::mechanism::ticket::CompletionHandle) {
        if !handle.ticket.is_none() && self.handles.contains(&handle) {
            self.reused_handle = true;
        }
        self.handles.push(handle);
    }
}

static PROGRAM: Mutex<Option<ProgramState>> = Mutex::new(None);

extern "C" fn program_open(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends EstablishIn for this call.
    let input = unsafe { input.cast::<EstablishIn>().read() };
    let mut state = PROGRAM.lock().unwrap_or_else(PoisonError::into_inner);
    let state = state.get_or_insert_with(ProgramState::default);
    state.completed(input.head.handle);
    state.next += 1;
    let stream = state.next;
    state.streams.insert(stream, (true, false, VecDeque::new()));
    answer(out, Outcome::Ready, stream, 0)
}

extern "C" fn program_write(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    use busbar_contract::abi::host::conn::connector::IoIn;
    // SAFETY: the connector lends IoIn and its initialized bytes for this call.
    let input = unsafe { input.cast::<IoIn>().read() };
    // SAFETY: these are the initialized bytes the SDK lends for the write.
    let bytes = unsafe { std::slice::from_raw_parts(input.buf, input.len) };
    let Ok(request) = serde_json::from_slice::<Value>(bytes) else {
        return answer(out, Outcome::Failed, 0, 0);
    };
    let result = match request["method"].as_str() {
        Some("initialize") => Some(json!({"protocolVersion":"2025-06-18","capabilities":{}})),
        Some("tools/list") => Some(page(&request)),
        _ => None,
    };
    let mut state = PROGRAM.lock().unwrap_or_else(PoisonError::into_inner);
    let state = state.as_mut().unwrap();
    state.completed(input.head.handle);
    state.requests.push(request.clone());
    if let Some(result) = result {
        let (_, pending, inbox) = state.streams.get_mut(&input.stream).unwrap();
        inbox.push_back(rpc_result(&request["id"], result));
        *pending = true;
    }
    answer(out, Outcome::Ready, 0, input.len as u64)
}

extern "C" fn program_read(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends ReplyIn and its writable buffer/descriptor for this call.
    let input = unsafe { input.cast::<ReplyIn>().read() };
    let mut state = PROGRAM.lock().unwrap_or_else(PoisonError::into_inner);
    let state = state.as_mut().unwrap();
    let (head, pending, inbox) = state.streams.get_mut(&input.stream).unwrap();
    let (kind, bytes) = if std::mem::take(head) {
        (
            REPLY_HEAD,
            format!("{}: 1\r\n", busbar_contract::conn::PROGRAM_GENERATION_FIELD).into_bytes(),
        )
    } else if std::mem::take(pending) {
        return answer(out, Outcome::Pending, 0, 0);
    } else if let Some(bytes) = inbox.pop_front() {
        (REPLY_BODY, bytes)
    } else {
        return answer(out, Outcome::Pending, 0, 0);
    };
    if bytes.len() > input.len {
        return answer(out, Outcome::Failed, 0, 0);
    }
    state.completed(input.head.handle);
    // SAFETY: ReplyIn lends this writable buffer with the stated capacity.
    let buffer = unsafe { std::slice::from_raw_parts_mut(input.buf, input.len) };
    buffer[..bytes.len()].copy_from_slice(&bytes);
    let fields = if kind == REPLY_HEAD {
        FrameSpan {
            offset: 0,
            len: bytes.len() as u64,
        }
    } else {
        FrameSpan::default()
    };
    // SAFETY: ReplyIn lends its descriptor output slot for this call.
    unsafe {
        input.piece.write(ReplyPiece {
            kind,
            fields,
            ..ReplyPiece::default()
        })
    };
    answer(out, Outcome::Ready, 0, bytes.len() as u64)
}

extern "C" fn program_close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the connector lends StreamIn for the duration of this call.
    let input = unsafe { input.cast::<StreamIn>().read() };
    let mut state = PROGRAM.lock().unwrap_or_else(PoisonError::into_inner);
    let state = state.as_mut().unwrap();
    state.completed(input.head.handle);
    state.streams.remove(&input.stream);
    answer(out, Outcome::Ready, 0, 0)
}

static PROGRAM_CONNS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: CONN_SERVICES,
    establish: Some(program_open),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: Some(program_write),
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: Some(program_close),
    random: None,
    identity: None,
    read_reply: Some(program_read),
    write_request: None,
};

static PROGRAM_TABLES: Tables = Tables(HostTables {
    size: std::mem::size_of::<HostTables>() as u32,
    _reserved: 0,
    ctx: HostCtx::NONE,
    wake: None,
    conns: &PROGRAM_CONNS,
    io: std::ptr::null(),
    services: &HOST_SLOTS,
});

fn program_door() -> Door {
    let section = br#"{"pg":{"transport":"stdio","command":"/usr/bin/true","pin":{"mechanism":"unpinned"},"tools_allow":{"first":{},"second":{},"third":{}}}}"#;
    let mut input: PlaneOpenIn = z();
    input.open = OpenIn {
        head: head::<PlaneOpenIn>(life::OPEN, Ticket::NONE),
        host: &PROGRAM_TABLES.0,
        settings: octets(section),
        generation: 1,
        ..z()
    };
    input.public_url = str_of("https://busbar.example");
    let mut output: PlaneOpenOut = z();
    output.open.head = out_head::<PlaneOpenOut>();
    // SAFETY: both records have the layout and lifetime required by the door's own OPEN slot.
    #[allow(unused_unsafe)]
    let result = unsafe {
        lifecycle().open.unwrap()(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(result.outcome(), Outcome::Ready);
    Door {
        instance: output.open.instance,
        retirement: std::cell::RefCell::new(completion_retirement_host::Host::new(
            HostCtx { handle: 71 },
            DRIVER,
        )),
    }
}

#[test]
fn a_completed_stdio_response_obeys_the_reply_bound_on_its_final_piece() {
    use busbar_contract::abi::sdk::exchange::REPLY_MAX;
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    MODE.store(0, Ordering::SeqCst);
    *PROGRAM.lock().unwrap_or_else(PoisonError::into_inner) = Some(ProgramState::default());
    *book() = None;
    let door = program_door();
    let call = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"pg_first","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let fields = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "pg_first"),
    ];
    for (unit, size) in [(30_401, REPLY_MAX + 1)] {
        assert_eq!(
            door.arrive(unit, "POST", "/mcp", call, &fields).outcome,
            Outcome::Ready
        );
        door.piece(unit, &Given::attempt(ALICE, "pg"));
        let sent = door.pump(unit, &Given::caller(ALICE, call));
        assert!(sent.far, "{}", sent.text());
        let prefix = format!(
            r#"{{"jsonrpc":"2.0","id":{},"result":{{"content":[{{"type":"text","text":""#,
            sent.json()["id"]
        );
        let suffix = br#""}]}}"#;
        let mut body = prefix.into_bytes();
        body.resize(size - suffix.len(), b'x');
        body.extend_from_slice(suffix);
        assert_eq!(body.len(), size);
        let mut final_answer = Answered::default();
        let pieces = body.chunks(16 * 1024);
        let count = pieces.len();
        for (at, bytes) in pieces.enumerate() {
            let mut given = Given::far(ALICE, 200, Vec::new(), bytes);
            if at + 1 != count {
                given.flags &= !PIECE_LAST;
            }
            if at != 0 {
                given.flags &= !PIECE_HAS_STATUS;
            }
            final_answer = door.piece(unit, &given);
        }
        assert_eq!(final_answer.json()["result"]["isError"], true);
        assert!(final_answer.text().contains(&REPLY_MAX.to_string()));
    }
}

#[test]
fn stdio_connect_retains_pages_and_unique_ids_across_pending_reads() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    MODE.store(0, Ordering::SeqCst);
    *PROGRAM.lock().unwrap_or_else(PoisonError::into_inner) = Some(ProgramState::default());
    let d = program_door();
    assert_eq!(view_of(&d.connect(955, "pg")), (Value::Null, json!(3)));
    let state = PROGRAM.lock().unwrap_or_else(PoisonError::into_inner);
    let requests = &state.as_ref().unwrap().requests;
    let ids: Vec<_> = requests
        .iter()
        .filter(|request| request["method"] == "tools/list")
        .map(|request| request["id"].clone())
        .collect();
    assert_eq!(ids.len(), 3);
    assert!(ids.iter().enumerate().all(|(i, id)| !ids[..i].contains(id)));
    assert!(
        state.as_ref().unwrap().streams.is_empty(),
        "all page leases closed"
    );
    assert!(
        !state.as_ref().unwrap().reused_handle,
        "completed service handles are never reused across pages"
    );
}

#[test]
fn stdio_does_not_publish_a_looping_or_malformed_partial_list() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for mode in [1, 2, 5] {
        MODE.store(mode, Ordering::SeqCst);
        *PROGRAM.lock().unwrap_or_else(PoisonError::into_inner) = Some(ProgramState::default());
        let d = program_door();
        let (failure, count) = view_of(&d.connect(960 + mode, "pg"));
        assert!(failure.is_string());
        assert_eq!(count, 0);
        let state = PROGRAM.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(
            state
                .as_ref()
                .unwrap()
                .requests
                .iter()
                .filter(|request| request["method"] == "tools/list")
                .count()
                > 1
        );
        assert!(!state.as_ref().unwrap().reused_handle);
        assert!(state.as_ref().unwrap().streams.is_empty());
    }
}

#[test]
fn stdio_verify_on_call_retains_all_pages_across_pending_reads() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    MODE.store(0, Ordering::SeqCst);
    *PROGRAM.lock().unwrap_or_else(PoisonError::into_inner) = Some(ProgramState::default());
    *book() = None;
    let d = program_door();
    let call = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"pg_second","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let fields = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "pg_second"),
    ];
    assert_eq!(
        d.arrive(970, "POST", "/mcp", call, &fields).outcome,
        Outcome::Ready
    );
    d.piece(970, &Given::attempt(ALICE, "pg"));
    let mut sent = d.piece(970, &Given::caller(ALICE, call));
    for _ in 0..16 {
        if sent.outcome != Some(Outcome::Pending) {
            break;
        }
        d.turn();
        sent = d.piece(970, &Given::caller(ALICE, call));
    }
    assert!(sent.far, "{}", sent.text());
    let state = PROGRAM.lock().unwrap_or_else(PoisonError::into_inner);
    let state = state.as_ref().unwrap();
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|request| request["method"] == "tools/list")
            .count(),
        3
    );
    assert!(!state.reused_handle);
    assert!(state.streams.is_empty());
}

#[test]
fn a_single_page_needs_no_spurious_cursor_request() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for mode in [3, 6] {
        MODE.store(mode, Ordering::SeqCst);
        *upstreams() = Some(Upstreams::default());
        let d = open_with(&http_section());
        assert_eq!(view_of(&d.connect(939, "pg")), (Value::Null, json!(1)));
        assert_eq!(lists_to(URL), 1);
    }
}

#[test]
fn an_adverse_second_page_status_cannot_publish_its_plausible_tool_body() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for mode in [7, 8, 9] {
        MODE.store(mode, Ordering::SeqCst);
        *upstreams() = Some(Upstreams::default());
        let d = open_with(&http_section());
        let (failure, count) = view_of(&d.connect(980 + mode, "pg"));
        assert!(failure.is_string());
        assert_eq!(
            count, 0,
            "a plausible error page never becomes a partial sighting"
        );
        assert_eq!(lists_to(URL), 2);
    }
}

#[test]
fn served_discovery_asks_the_same_trust_book_as_the_served_tool_list() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let _book = BookOn::on();
    let d = open_with(TWO_SECTION);
    assert_eq!(view_of(&d.connect(990, "tw")), (Value::Null, json!(2)));
    assert_eq!(
        listed(&d, 991).len(),
        2,
        "both approved tools are actually listed"
    );
    for digest in book().as_mut().unwrap().approved.values_mut() {
        *digest = "sha256:an-earlier-approval".to_string();
    }
    assert!(
        listed(&d, 992).is_empty(),
        "the served list observes changed trust"
    );
    let request = br#"{"jsonrpc":"2.0","id":9,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let fields = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "server/discover"),
    ];
    assert_eq!(
        d.arrive(993, "POST", "/mcp", request, &fields).outcome,
        Outcome::Ready
    );
    let answer = d.piece(993, &Given::caller(ALICE, request));
    assert_eq!(answer.json()["result"]["counts"]["tools"], 0);
    assert_eq!(answer.json()["result"]["servers"], json!([]));
}
