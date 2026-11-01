use super::*;

#[test]
fn a_short_session_buffer_retains_completed_legacy_results_until_a_successful_retry() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let mut section: Value = serde_json::from_str(SECTION).unwrap();
    let legacy: Value = serde_json::from_str(LEGACY_SECTION).unwrap();
    section["lg"] = legacy["lg"].clone();
    let d = open_with(&section.to_string());
    assert_eq!(view_of(&d.connect(906, "lg")), (Value::Null, json!(1)));
    let listen = br#"{"jsonrpc":"2.0","id":905,"method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":["file:///readme"]},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let fields = [
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "subscriptions/listen"),
    ];
    assert_eq!(
        d.arrive(905, "POST", "/mcp", listen, &fields).outcome,
        Outcome::Ready
    );
    let opened = d.piece(905, &Given::stream_open(ALICE, 905));
    assert!(opened.text().contains("acknowledged"), "{}", opened.text());
    let ping = sse_event("message", r#"{"jsonrpc":"2.0","id":907,"method":"ping"}"#);
    upstreams()
        .as_mut()
        .unwrap()
        .open
        .values_mut()
        .find_map(|wire| wire.sse.as_mut())
        .unwrap()
        .events
        .push_back(ping);
    d.tick();
    let extensions = d.retirement.borrow().input();
    let mut input = PlaneDriveIn {
        drive: DriveIn {
            head: head::<PlaneDriveIn>(life::DRIVE, DRIVER),
            driver: DRIVER,
        },
        sessions_buf: std::ptr::null_mut(),
        sessions_cap: 0,
    };
    input.drive.head.extensions = octets(&extensions);
    let mut short: PlaneDriveOut = z();
    short.head = out_head::<PlaneDriveOut>();
    let f = lifecycle().drive.unwrap();
    let answer = f(
        d.instance,
        std::ptr::from_ref(&input).cast(),
        std::ptr::from_mut(&mut short).cast(),
    );
    assert_eq!(answer.outcome(), Outcome::Failed);
    busbar_contract::abi::plane::check::check_drive(answer.outcome(), &short, 0).unwrap();
    assert!(short.sessions_needed > 0);
    assert_eq!(short.sessions_written, 0);
    let bytes = if short.head.extensions.len == 0 {
        &[][..]
    } else {
        // SAFETY: the output lease remains live throughout this observation.
        unsafe { std::slice::from_raw_parts(short.head.extensions.ptr, short.head.extensions.len) }
    };
    assert!(
        busbar_contract::abi::sdk::completion_retirement::read_ack(bytes)
            .unwrap()
            .is_none(),
        "a legitimate short answer cannot acknowledge completion results"
    );
    assert!(
        seen()
            .iter()
            .any(|request| request.body["id"] == json!(907) && request.body["result"].is_object()),
        "the legacy reply POST completed before session-buffer validation failed"
    );
    completion_retirement_host::release(d.instance, &short.head, lifecycle());
    let mut sessions = [0u64; 16];
    input.sessions_buf = sessions.as_mut_ptr();
    input.sessions_cap = sessions.len();
    input.drive.head.flags |= busbar_contract::abi::mechanism::call::FLAG_RESUME;
    let mut full: PlaneDriveOut = z();
    full.head = out_head::<PlaneDriveOut>();
    let answer = f(
        d.instance,
        std::ptr::from_ref(&input).cast(),
        std::ptr::from_mut(&mut full).cast(),
    );
    assert_eq!(answer.outcome(), Outcome::Pending);
    assert!(sessions[..full.sessions_written as usize].contains(&905));
    assert!(
        !d.retirement.borrow_mut().acknowledge(&full.head).is_empty(),
        "the successful retry acknowledges the retained completed results"
    );
    completion_retirement_host::release(d.instance, &full.head, lifecycle());
    d.drive();
    assert_eq!(seen().iter().filter(|request| request.body["id"] == json!(907) && request.body["result"].is_object()).count(), 1,
        "confirmation and retry never send the same server reply twice");
}

#[test]
fn a_legacy_pending_read_keeps_the_driver_pending_across_later_ticks() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open_with(LEGACY_SECTION);
    assert_eq!(view_of(&d.connect(904, "lg")), (Value::Null, json!(1)));
    for _ in 0..2 {
        d.tick();
        let mut sessions = [0_u64; 16];
        let extensions = d.retirement.borrow().input();
        let mut input = PlaneDriveIn {
            drive: DriveIn {
                head: head::<PlaneDriveIn>(life::DRIVE, DRIVER),
                driver: DRIVER,
            },
            sessions_buf: sessions.as_mut_ptr(),
            sessions_cap: sessions.len(),
        };
        input.drive.head.extensions = octets(&extensions);
        let mut output: PlaneDriveOut = z();
        output.head = out_head::<PlaneDriveOut>();
        let f = lifecycle().drive.unwrap();
        let answer = f(
            d.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        );
        assert_eq!(
            answer.outcome(),
            Outcome::Pending,
            "the held GET has not ended, so its completion handles stay held"
        );
        busbar_contract::abi::plane::check::check_drive(
            answer.outcome(),
            &output,
            sessions.len() as u64,
        )
        .unwrap();
        d.retirement.borrow_mut().acknowledge(&output.head);
        completion_retirement_host::release(d.instance, &output.head, lifecycle());
    }
}
