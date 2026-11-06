// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_stdio_task_completes_under_the_actual_child_call_id() {
    for unit in [2, (1_u64 << 32) | 2] {
        let _serial = fresh();
        let d = open_on(&UNCONNECTED, &program_section(false));
        let task = create(&d, 1, "io", "io_read_file");
        let body = last_nested();
        assert_eq!(d.arrive_run(unit, &body).outcome, Outcome::Ready);
        let ticket = Ticket {
            slot: 2,
            generation: 1,
        };
        d.piece_on_ticket(unit, ticket, &Given::attempt(ALICE, "io"));
        let sent = d.piece_on_ticket(unit, ticket, &Given::caller(ALICE, &body));
        assert!(sent.far, "{}", sent.text());
        let expected = if unit == 2 {
            json!((1_u64 << 40) | (unit << 7))
        } else {
            json!(format!("busbar-call:unit:{unit}:0"))
        };
        assert_eq!(
            sent.json()["id"],
            expected,
            "the task carries its actual child call id"
        );
        let mut answered = Given::far(ALICE, 200, &[]);
        let result = result_of(&sent, "stdio task complete");
        answered.bytes = &result;
        answered.head.push(("generation", "1"));
        d.piece_on_ticket(unit, ticket, &answered);
        assert_completed(&get(&d, 3, &task), "stdio task complete");
    }
}

#[test]
fn a_task_never_inlines_a_redirect_body_the_synchronous_call_refused() {
    let _serial = fresh();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let sent = run(&d, 2, "st", &last_nested());
    assert!(sent.far, "{}", sent.text());
    d.piece(
        2,
        &Given::far(
            ALICE,
            302,
            &result_of(&sent, "redirect result must never be delivered"),
        ),
    );
    assert_failed(&get(&d, 3, &task), "redirect");
}

#[test]
fn a_task_never_inlines_complete_results_still_carrying_an_upstream_ask() {
    for field in ["requestState", "inputRequests"] {
        let _serial = fresh();
        let d = open(&section());
        let task = create(&d, 1, "st", "st_read_file");
        let sent = run(&d, 2, "st", &last_nested());
        assert!(sent.far, "{}", sent.text());
        let mut result = json!({"resultType":"complete","content":[]});
        result[field] = json!({"unrelayed":"authority"});
        d.piece(
            2,
            &Given::far(ALICE, 200, &rpc_result(&sent.json()["id"], result)),
        );
        assert_failed(&get(&d, 3, &task), field);
    }
}

#[test]
fn a_task_keeps_an_accepted_tool_execution_error_result_unchanged() {
    let _serial = fresh();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let sent = run(&d, 2, "st", &last_nested());
    assert!(sent.far, "{}", sent.text());
    let result = json!({
        "content":[{"type":"text","text":"<script>the tool's own error</script>\u{001b}[31m\n"}],
        "structuredContent":{"values":["<b>raw</b>","\u{0000}opaque"],"nested":{"keep":"&<>"}},
        "isError":true
    });
    d.piece(
        2,
        &Given::far(ALICE, 200, &rpc_result(&sent.json()["id"], result.clone())),
    );
    let read = get(&d, 3, &task).json();
    assert_eq!(read["result"]["status"], json!("completed"));
    assert_eq!(read["result"]["result"], result);
}

fn program_section(serialised: bool) -> Value {
    json!({"io": {
        "transport":"stdio", "command":"/usr/bin/true", "pin":pin(),
        "grants":{"elicitation":serialised},
        "tools_allow":{"read_file":{"task_support":"required"}},
    }})
}

#[test]
fn a_queued_task_rechecks_its_grant_and_trust_when_the_child_becomes_free() {
    for quarantine in [false, true] {
        let _serial = fresh();
        let d = open_on(&UNCONNECTED, &program_section(true));
        let first = create(&d, 1, "io", "io_read_file");
        let first_body = last_nested();
        let second = create(&d, 3, "io", "io_read_file");
        let second_body = last_nested();
        let sent = run(&d, 2, "io", &first_body);
        assert!(sent.far, "{}", sent.text());
        let queued = run(&d, 4, "io", &second_body);
        assert!(
            !queued.far,
            "the second call must wait for its child's turn"
        );
        assert_eq!(
            get(&d, 5, &second).json()["result"]["status"],
            json!("working")
        );
        if quarantine {
            VERDICT.store(
                busbar_contract::abi::host::service::DISTRUST_QUARANTINED,
                Ordering::SeqCst,
            );
        } else {
            revoked().push("mcp_tool:io_read_file".to_string());
        }
        d.piece(
            2,
            &Given::far(ALICE, 200, &result_of(&sent, "first finished")),
        );
        let woke = d.piece(4, &Given::caller(ALICE, b""));
        assert!(
            !woke.far,
            "a revoked queued task must not reach its child: {}",
            woke.text()
        );
        assert_completed(&get(&d, 6, &first), "first finished");
        assert_failed(
            &get(&d, 7, &second),
            if quarantine {
                "quarantined"
            } else {
                "not a tool this server exposes"
            },
        );
    }
}

#[derive(Default)]
struct GreetingChild {
    next: u64,
    leases: HashMap<u64, (bool, std::collections::VecDeque<Vec<u8>>)>,
}

static GREETING_CHILD: Mutex<Option<GreetingChild>> = Mutex::new(None);
static PEND_GREETING: AtomicBool = AtomicBool::new(false);

fn with_child<R>(f: impl FnOnce(&mut GreetingChild) -> R) -> R {
    let mut child = GREETING_CHILD
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    f(child.get_or_insert_with(GreetingChild::default))
}

extern "C" fn program_establish(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    if PEND_GREETING.swap(false, Ordering::SeqCst) {
        return answer(out, Outcome::Pending, 0, 0, 0);
    }
    let stream = with_child(|c| {
        c.next += 1;
        c.leases
            .insert(c.next, (true, std::collections::VecDeque::new()));
        c.next
    });
    ready(out, stream, 0, 0)
}

extern "C" fn program_write(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    use busbar_contract::abi::host::conn::connector::IoIn;
    // SAFETY: the connector lends its IoIn and bytes for this crossing only.
    let i = unsafe { input.cast::<IoIn>().read() };
    let bytes = unsafe { std::slice::from_raw_parts(i.buf, i.len) };
    let message: Value = serde_json::from_slice(bytes).expect("one child JSON message");
    if let Some(id) = message.get("id") {
        let result = match message["method"].as_str() {
            Some("initialize") => {
                json!({"protocolVersion":message["params"]["protocolVersion"],"capabilities":{"tools":{}}})
            }
            Some("tools/list") => {
                json!({"tools":[{"name":"read_file","inputSchema":{"type":"object"}}]})
            }
            _ => json!({}),
        };
        let reply = rpc_result(id, result);
        with_child(|c| {
            for (_, inbox) in c.leases.values_mut() {
                inbox.push_back(reply.clone());
            }
        });
    }
    ready(out, 0, i.len as u64, 0)
}

extern "C" fn program_read(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the connector lends a ReplyIn and its buffer and descriptor for this crossing.
    let i = unsafe { input.cast::<ReplyIn>().read() };
    let got = with_child(|c| {
        let (head, inbox) = c.leases.get_mut(&i.stream)?;
        if *head {
            *head = false;
            // The HostTables stand-in supplies a canonical host-owned launch
            // receipt. Process success has no numeric status, so code stays zero.
            Some((
                REPLY_HEAD,
                b"generation: 1\r\nprogram-instance: 1\r\nprogram-identity: L3Vzci9iaW4vdHJ1ZQ==\r\n"
                    .to_vec(),
            ))
        } else {
            inbox.pop_front().map(|bytes| (REPLY_BODY, bytes))
        }
    });
    let Some((kind, bytes)) = got else {
        return answer(out, Outcome::Pending, 0, 0, 0);
    };
    let fields = if kind == REPLY_HEAD {
        FrameSpan {
            offset: 0,
            len: bytes.len() as u64,
        }
    } else {
        FrameSpan::default()
    };
    assert!(bytes.len() <= i.len);
    // SAFETY: the ABI buffer has the asserted capacity and the descriptor belongs to the caller.
    unsafe {
        std::slice::from_raw_parts_mut(i.buf, i.len)[..bytes.len()].copy_from_slice(&bytes);
        i.piece.write(ReplyPiece {
            kind,
            fields,
            ..ReplyPiece::default()
        });
    }
    ready(out, 0, bytes.len() as u64, 0)
}

extern "C" fn program_close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the connector hands the close service its StreamIn.
    let i = unsafe { input.cast::<StreamIn>().read() };
    with_child(|c| c.leases.remove(&i.stream));
    ready(out, 0, 0, 0)
}

static PROGRAM_CONN: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: CONN_SERVICES,
    establish: Some(program_establish),
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
    conns: &PROGRAM_CONN,
    io: std::ptr::null(),
    services: &HOST_SLOTS,
});

fn greeting_section() -> Value {
    let mut section = program_section(false);
    section["io"]["cwd"] = json!("/");
    section["io"]["pin"] = json!({"mechanism":"local_program","key":"/usr/bin/true"});
    section
}

#[test]
fn a_task_rechecks_grant_and_trust_after_its_child_greeting_pends() {
    for quarantine in [false, true] {
        let _serial = fresh();
        with_child(|c| *c = GreetingChild::default());
        PEND_GREETING.store(false, Ordering::SeqCst);
        let d = open_on(&PROGRAM_TABLES, &greeting_section());
        let task = create(&d, 1, "io", "io_read_file");
        let body = last_nested();
        PEND_GREETING.store(true, Ordering::SeqCst);
        let waiting = run(&d, 2, "io", &body);
        assert!(
            !PEND_GREETING.load(Ordering::SeqCst),
            "the task reached its child's greeting"
        );
        assert!(!waiting.far, "a pending greeting cannot send the call");
        if quarantine {
            VERDICT.store(
                busbar_contract::abi::host::service::DISTRUST_QUARANTINED,
                Ordering::SeqCst,
            );
        } else {
            revoked().push("mcp_tool:io_read_file".to_string());
        }
        let woke = d.piece(2, &Given::caller(ALICE, b""));
        assert!(
            !woke.far,
            "a task revoked during its greeting must not be sent: {}",
            woke.text()
        );
        assert_failed(
            &get(&d, 3, &task),
            if quarantine {
                "quarantined"
            } else {
                "not a tool this server exposes"
            },
        );
    }
}

#[test]
fn a_task_resumes_a_pending_child_greeting_and_preserves_its_result() {
    let _serial = fresh();
    with_child(|c| *c = GreetingChild::default());
    PEND_GREETING.store(false, Ordering::SeqCst);
    let d = open_on(&PROGRAM_TABLES, &greeting_section());
    let task = create(&d, 1, "io", "io_read_file");
    let body = last_nested();
    PEND_GREETING.store(true, Ordering::SeqCst);
    assert!(!run(&d, 2, "io", &body).far);
    assert!(!PEND_GREETING.load(Ordering::SeqCst));
    let sent = d.piece(2, &Given::caller(ALICE, b""));
    assert!(
        sent.far,
        "an unchanged grant can finish the greeting and send: {}",
        sent.text()
    );
    let result = result_of(&sent, "greeted task complete");
    let mut answered = Given::far(ALICE, 0, &result);
    answered.head.extend([
        ("generation", "1"),
        ("program-instance", "1"),
        ("program-identity", "L3Vzci9iaW4vdHJ1ZQ=="),
    ]);
    d.piece(2, &answered);
    assert_completed(&get(&d, 3, &task), "greeted task complete");
}
