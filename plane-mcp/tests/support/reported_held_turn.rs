use super::*;

static WOKEN: Mutex<Vec<Ticket>> = Mutex::new(Vec::new());
extern "C" fn wake(_: HostCtx, ticket: Ticket) {
    WOKEN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(ticket);
}
static WAKING: Tables = Tables(HostTables {
    size: std::mem::size_of::<HostTables>() as u32,
    _reserved: 0,
    ctx: HostCtx::NONE,
    wake: Some(wake),
    conns: std::ptr::null(),
    io: std::ptr::null(),
    services: &HOST_SLOTS,
});

#[test]
fn a_held_stdio_place_wakes_queued_work_at_its_existing_ask_deadline() {
    for queued_before_ask in [false, true] {
        let _serial = fresh();
        let _clock = Clock;
        WOKEN.lock().unwrap_or_else(PoisonError::into_inner).clear();
        let start = 100_000_000_000;
        FIXED_NS.store(start, Ordering::SeqCst);
        let d = open_on(
            &WAKING,
            &json!({"io":{"transport":"stdio","command":"/usr/bin/true","pin":pin(),"timeout":"600s","grants":{"elicitation":true},"tools_allow":{"read_file":{"task_support":"required"}}}}),
        );
        create(&d, 1, "io", "io_read_file");
        let first = last_nested();
        create(&d, 3, "io", "io_read_file");
        let second = last_nested();
        let sent = run(&d, 2, "io", &first);
        assert!(sent.far, "{}", sent.text());
        if queued_before_ask {
            let queued = run(&d, 4, "io", &second);
            assert!(!queued.far);
            assert_eq!(
                queued.wake_at_ns,
                start + 600_000_000_000,
                "before a hold exists, only the request deadline is known"
            );
        }
        let ask=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":900,"method":"elicitation/create","params":{"message":"sure?"}})).unwrap();
        let mut far = Given::far(ALICE, 200, &ask);
        far.head.push(("generation", "1"));
        d.piece(2, &far);
        if queued_before_ask {
            assert!(WOKEN.lock().unwrap_or_else(PoisonError::into_inner).contains(&Ticket {slot:4,generation:1}),"a call already queued before the hold was installed is woken to learn its earlier timer");
        }
        let queued = if queued_before_ask {
            d.piece(4, &Given::caller(ALICE, b""))
        } else {
            run(&d, 4, "io", &second)
        };
        assert!(!queued.far);
        // The existing ask hold is300s; this does not shorten the caller's600s request deadline.
        assert_eq!(
            queued.wake_at_ns,
            start + 300_000_000_000,
            "the host is actually told when the held place becomes eligible"
        );
        FIXED_NS.store(start + 299_999_000_000, Ordering::SeqCst);
        let early = d.piece(4, &Given::caller(ALICE, b""));
        assert!(!early.far, "the child remains held before expiry");
        assert_eq!(early.wake_at_ns, start + 300_000_000_000);
        FIXED_NS.store(start + 300_000_000_000, Ordering::SeqCst);
        let expired = d.piece(4, &Given::caller(ALICE, b""));
        assert!(
            expired.far,
            "at the existing hold's expiry the queued request is still within its own deadline: {}",
            expired.text()
        );
    }
}
