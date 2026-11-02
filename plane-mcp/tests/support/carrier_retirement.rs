// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::collections::BTreeSet;

static CLOSED: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
static EMIT_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static EMIT_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static PRESSURE: AtomicU64 = AtomicU64::new(0);

fn extensions(epoch: u64, receipt: Option<&[u8]>) -> Vec<u8> {
    let mut ext = inspection_wire::input(epoch, receipt);
    let padding = PRESSURE.load(Ordering::SeqCst) as usize;
    if padding != 0 {
        ext.extend(busbar_contract::abi::mechanism::extensions::encode(&[(
            "carrier-test-padding",
            &vec![0; padding],
        )]));
    }
    ext
}

pub(super) extern "C" fn emit(
    _: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    use busbar_contract::abi::host::service::SessionEmitIn;
    // SAFETY: session.emit receives its declared input from the SDK.
    let input = unsafe { input.cast::<SessionEmitIn>().read() };
    EMIT_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
    if CLOSED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&input.session)
    {
        return answer(out, Outcome::Refused, 0, 0);
    }
    EMIT_ACCEPTED.fetch_add(1, Ordering::SeqCst);
    answer(out, Outcome::Ready, 0, 0)
}

struct Controls;
impl Controls {
    fn new() -> Self {
        EMIT_ATTEMPTS.store(0, Ordering::SeqCst);
        EMIT_ACCEPTED.store(0, Ordering::SeqCst);
        PRESSURE.store(0, Ordering::SeqCst);
        CLOSED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        Controls
    }
}
impl Drop for Controls {
    fn drop(&mut self) {
        PRESSURE.store(0, Ordering::SeqCst);
        CLOSED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

pub(super) struct Crossing {
    outcome: Outcome,
    request: Option<Vec<u8>>,
    needed: u32,
    error: String,
}

fn crossed(door: &Door, outcome: RawOutcome, head: &OutHead, needed: u32) -> Crossing {
    let request = inspection_wire::request(head);
    let error = if head.error.ptr.is_null() {
        String::new()
    } else {
        // SAFETY: output error text remains valid while the output's crossing or lease is live.
        unsafe {
            String::from_utf8_lossy(std::slice::from_raw_parts(head.error.ptr, head.error.len))
                .into_owned()
        }
    };
    inspection_wire::release(door.instance, head, lifecycle());
    Crossing {
        outcome: outcome.outcome(),
        request,
        needed,
        error,
    }
}

fn start(door: &Door, epoch: Option<u64>) -> Crossing {
    let ext = epoch
        .map(|epoch| extensions(epoch, None))
        .unwrap_or_default();
    let mut i = TickIn {
        head: head::<TickIn>(life::TICK, DRIVER),
        now_ns: TICKS.fetch_add(1, Ordering::SeqCst),
    };
    i.head.extensions = octets(&ext);
    let mut o: TickOut = z();
    o.head = out_head::<TickOut>();
    // SAFETY: lifecycle TICK with its declared types and the test's live instance.
    // SAFETY: The fixture owns this live door instance; the exact input/output frames and every borrowed buffer remain live throughout the synchronous call.
    let ret = unsafe {
        lifecycle().tick.unwrap()(
            door.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    crossed(door, ret, &o.head, 0)
}

fn resume(door: &Door, epoch: u64, receipt: Option<&[u8]>, cap: usize) -> Crossing {
    let ext = extensions(epoch, receipt);
    let mut sessions = vec![0_u64; cap];
    let mut i: PlaneDriveIn = z();
    i.drive = DriveIn {
        head: head::<PlaneDriveIn>(life::DRIVE, DRIVER),
        driver: DRIVER,
    };
    i.drive.head.flags |= inspection_wire::RESUME;
    i.drive.head.extensions = octets(&ext);
    i.sessions_buf = sessions.as_mut_ptr();
    i.sessions_cap = sessions.len();
    let mut o: PlaneDriveOut = z();
    o.head = out_head::<PlaneDriveOut>();
    // SAFETY: lifecycle DRIVE with its declared buffers/types and the test's live instance.
    // SAFETY: The fixture owns this live door instance; the exact input/output frames and every borrowed buffer remain live throughout the synchronous call.
    let ret = unsafe {
        lifecycle().drive.unwrap()(
            door.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    crossed(door, ret, &o.head, o.sessions_needed)
}

pub(super) fn finish(door: &Door, mut request: Vec<u8>) {
    loop {
        let receipt = inspection_wire::carriers(&request, |id| {
            !CLOSED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&id)
        });
        let done = resume(door, 1, Some(&receipt), 16);
        match done.request {
            Some(next) => request = next,
            None => {
                assert_eq!(done.outcome, Outcome::Ready, "{}", done.error);
                assert_eq!(done.needed, 0, "the supplied driver buffer fits");
                break;
            }
        }
    }
}

fn line(door: &Door, unit: u64, session: u64, caller: &str, body: &Value) -> Answered {
    let body = serde_json::to_vec(body).unwrap();
    let session = session.to_string();
    let fields = [Field {
        name: str_of(busbar_contract::abi::host::service::CARRIER_SESSION_FIELD),
        value: str_of(&session),
    }];
    let mut i: ArriveIn = z();
    i.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
    i.unit = unit;
    i.claim = door_facts::LINE_ROUTE as u32;
    i.target = str_of("/mcp");
    i.method = str_of("POST");
    i.body = octets(&body);
    i.fields = fields.as_ptr();
    i.fields_len = fields.len();
    let mut units = [z::<UnitCount>(); 8];
    i.units_buf = units.as_mut_ptr();
    i.units_cap = units.len();
    let mut o: ArriveOut = z();
    o.head = out_head::<ArriveOut>();
    // SAFETY: ARRIVE with the exact live input/output buffers above.
    // SAFETY: The fixture owns this live door instance; the exact input/output frames and every borrowed buffer remain live throughout the synchronous call.
    let ret = unsafe {
        ops().arrive.unwrap()(
            door.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    assert_eq!(ret.outcome(), Outcome::Ready);
    door.piece(unit, &Given::caller(caller, &body))
}

fn initialize(door: &Door, unit: u64, session: u64, caller: &str) -> Answered {
    line(
        door,
        unit,
        session,
        caller,
        &json!({"jsonrpc":"2.0","id":unit,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
    )
}

#[test]
fn carrier_negotiation_capacity_is_reclaimed_only_for_host_closed_ids() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _controls = Controls::new();
    let door = open();
    for session in 1..=4096 {
        assert_eq!(
            initialize(&door, 30_000 + session, session, ALICE).json()["result"]["protocolVersion"],
            "2025-06-18"
        );
    }
    CLOSED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(1);
    let checked = start(&door, Some(1));
    if let Some(request) = checked.request {
        finish(&door, request);
    } else {
        assert_eq!(checked.outcome, Outcome::Ready);
    }
    assert_eq!(
        initialize(&door, 40_000, 5000, BOB).json()["result"]["protocolVersion"],
        "2025-06-18"
    );
    assert_ne!(
        initialize(&door, 40_001, 5001, ALICE).json()["result"]["protocolVersion"],
        "2025-06-18",
        "host-live sessions are never evicted to make room"
    );
}

#[path = "inspection_carrier_controls.rs"]
mod inspection_controls;
