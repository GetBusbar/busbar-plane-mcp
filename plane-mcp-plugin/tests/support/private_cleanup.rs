// SPDX-License-Identifier: Apache-2.0
// Actual private maintenance/cancellation/refresh assertions, without a test-only door.
use super::*;
use busbar_contract::abi::host::service::{
    ClockNowIn, ClockReading, HostSlots, ItemSpan, ServiceOut, WorkOpenIn, WorkSettleIn, SERVICES,
};
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome, Span};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use busbar_contract::abi::sdk::completion_retirement::{self as wire, Capability};
use busbar_contract::abi::sdk::plane_life::PlaneLife;
use std::cell::RefCell;
use std::ffi::c_void;
const DRIVER: Ticket = Ticket {
    slot: 87,
    generation: 4,
};
const WORK: u64 = 42;
struct State {
    cap: Capability,
    confirm: bool,
    now_ms: u64,
    clock_fails: bool,
    mode: Outcome,
    calls: Vec<CompletionHandle>,
    records: Vec<Vec<u8>>,
    applied: usize,
    remaining: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            cap: Capability {
                owner: HostCtx { handle: 71 },
                ticket: DRIVER,
                epoch: 1,
                nonce: 1,
                acknowledged: [0; 32],
            },
            confirm: true,
            now_ms: 500,
            clock_fails: false,
            mode: Outcome::Pending,
            calls: Vec::new(),
            records: Vec::new(),
            applied: 0,
            remaining: 0,
        }
    }
}

thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

fn finish(out: *mut ServiceOut, outcome: Outcome, value: u64, len: u64, items: u64) -> RawOutcome {
    let raw = RawOutcome::of(outcome);
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            value,
            len,
            items,
            needed_bytes: 0,
            needed_items: 0,
            ..ServiceOut::ZERO
        });
    }
    raw
}
extern "C" fn clock(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<ClockNowIn>().read_unaligned() };
    let failed = STATE.with(|state| {
        let state = state.borrow();
        if state.clock_fails {
            return true;
        }
        unsafe {
            input.reading.write(ClockReading {
                size: std::mem::size_of::<ClockReading>() as u32,
                _reserved: 0,
                wall_ns: state.now_ms * 1_000_000,
                mono_ns: state.now_ms * 1_000_000,
            });
        }
        false
    });
    finish(
        out,
        if failed {
            Outcome::Failed
        } else {
            Outcome::Ready
        },
        0,
        0,
        0,
    )
}
extern "C" fn open_work(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<WorkOpenIn>().read_unaligned() };
    let reference = b"0123456789abcdef0123456789abcdef";
    let span = ItemSpan {
        key: Span {
            offset: 0,
            len: reference.len() as u32,
        },
        value: Span {
            offset: busbar_contract::abi::plane::SPAN_ABSENT,
            len: 0,
        },
    };
    assert!(input.into.cap >= reference.len() && input.into.spans_cap >= 1);
    unsafe {
        std::ptr::copy_nonoverlapping(reference.as_ptr(), input.into.buf, reference.len());
        input.into.spans.write(span);
    }
    finish(out, Outcome::Ready, WORK, reference.len() as u64, 1)
}
extern "C" fn settle(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<WorkSettleIn>().read_unaligned() };
    let record = unsafe { std::slice::from_raw_parts(input.record.ptr, input.record.len) };
    let outcome = STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert_eq!(input.handle, WORK);
        state.calls.push(input.head.handle);
        state.records.push(record.to_vec());
        if state.mode == Outcome::Ready {
            state.applied += 1;
            assert_eq!(state.applied, 1, "confirmed cleanup was issued twice");
        }
        state.mode
    });
    finish(out, outcome, 0, 0, 0)
}
struct CleanupHost {
    tables: Box<HostTables>,
    _slots: Box<HostSlots>,
}
fn cleanup_host() -> CleanupHost {
    let mut slots: Box<HostSlots> = Box::new(unsafe { std::mem::zeroed() });
    slots.size = std::mem::size_of::<HostSlots>() as u32;
    slots.slots = SERVICES;
    slots.clock_now = Some(clock);
    slots.work_open = Some(open_work);
    slots.work_settle = Some(settle);
    let tables = Box::new(HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx { handle: 71 },
        wake: None,
        conns: std::ptr::null(),
        services: &*slots,
        io: std::ptr::null(),
    });
    CleanupHost {
        tables,
        _slots: slots,
    }
}
struct MaintenanceCase<'host> {
    plane: McpDoor,
    _host: std::marker::PhantomData<&'host CleanupHost>,
}
impl<'host> MaintenanceCase<'host> {
    fn new(host: &'host CleanupHost, clock_fails: bool) -> Self {
        STATE.with(|state| {
            *state.borrow_mut() = State {
                clock_fails,
                ..State::default()
            }
        });
        let plane = McpDoor {
            services: unsafe { Services::from_raw(&host.tables) },
            host: Some(unsafe { busbar_contract::abi::sdk::conn::Host::from_raw(&host.tables) }),
            ..McpDoor::default()
        };
        if clock_fails {
            let child = crate::ask::ChildLeg {
                launch: None,
                generation: 1,
                wait: serde_json::json!(7),
                asks: Vec::new(),
                work: None,
            };
            let opened = open_child_work(
                &plane,
                (
                    plane.services.unwrap(),
                    Ticket {
                        slot: 1,
                        generation: 1,
                    },
                    &mut 0,
                ),
                (&mut None, &mut None),
                ("fs", "fs"),
                (&serde_json::json!({}), 0, child),
            );
            assert!(matches!(opened, ChildOpened::Refused(..)));
        } else {
            door_relay_cleanup::hold(&plane, WORK, 1000);
        }
        Self {
            plane,
            _host: std::marker::PhantomData,
        }
    }
    fn drive(&self) {
        let extensions =
            STATE.with(|state| wire::append_capability(&[], state.borrow().cap).unwrap());
        self.plane.legacy_seq.with_all(|states| {
            let driver = states.entry(()).or_default();
            driver
                .begin(HostCtx { handle: 71 }, DRIVER, &extensions)
                .unwrap();
            let pending = door_relay_cleanup::drive(&self.plane, DRIVER, driver);
            assert!(
                driver.failure.is_none(),
                "maintenance retirement remains valid"
            );
            let ack = driver.retirement.acknowledgement(0).unwrap();
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.remaining = self.plane.relays.with_all(|works| works.len());
                if state.confirm {
                    if let Some(ack) = ack {
                        assert_eq!(ack.capability, state.cap);
                        state.cap.nonce += 1;
                        state.cap.acknowledged = wire::ack_digest(&ack).unwrap();
                    }
                }
            });
            let _ = pending;
        });
    }
    fn reload_and_retire(&self) {
        let published = <McpDoor as PlaneLife>::refresh(&self.plane, b"{}", 2)
            .expect("real refresh accepts empty section");
        let snapshot = self
            .plane
            .generations
            .publish_with(2, &published.spec, published.held);
        assert!(!snapshot.is_null());
        <McpDoor as PlaneLife>::published(&self.plane, 2);
        <McpDoor as PlaneLife>::retire(&self.plane, 1);
        self.plane.generations.retire(1);
    }
    fn cancel_caller(&self) {
        let (stopped, records, answered) = cancel_unit_state(
            &self.plane,
            UnitCancel {
                ticket: Ticket {
                    slot: 1,
                    generation: 1,
                },
                unit: 1,
            },
        );
        assert!(stopped.is_empty() && records.is_empty() && !answered);
    }
}
#[test]
fn expiry_is_maintained_without_another_ask_and_pending_keeps_the_full_handle() {
    let host = cleanup_host();
    let fixture = MaintenanceCase::new(&host, false);
    fixture.drive();
    STATE.with(|state| assert!(state.borrow().calls.is_empty()));
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.now_ms = 1500;
        state.confirm = false;
    });
    fixture.drive();
    fixture.cancel_caller();
    fixture.drive();
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.calls.len(), 2);
        assert_eq!(state.calls[0], state.calls[1]);
        assert_eq!(state.calls[0].ticket, DRIVER);
        assert_eq!(state.remaining, 1);
    });
    STATE.with(|state| state.borrow_mut().mode = Outcome::Failed);
    fixture.drive();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert_eq!(state.remaining, 1);
        state.confirm = true;
        state.mode = Outcome::Refused;
    });
    fixture.drive();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert_ne!(
            state.calls[2], state.calls[3],
            "terminal failure must use a fresh completion handle"
        );
        assert_eq!(state.remaining, 1);
        state.mode = Outcome::Ready;
    });
    fixture.drive();
    fixture.drive();
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.remaining, 0);
        assert_eq!(state.applied, 1);
        assert!(state
            .records
            .iter()
            .all(|record| record.as_slice() == super::CHILD_LAPSED));
    });
}

#[test]
fn clock_refusal_after_open_keeps_immediate_cleanup_even_while_clock_stays_unavailable() {
    let host = cleanup_host();
    let fixture = MaintenanceCase::new(&host, true);
    fixture.drive();
    fixture.drive();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert_eq!(state.remaining, 1);
        assert_eq!(state.calls[0], state.calls[1]);
        state.mode = Outcome::Ready;
    });
    fixture.drive();
    fixture.drive();
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.remaining, 0);
        assert_eq!(state.applied, 1);
    });
}

#[test]
fn pending_cleanup_survives_config_reload_and_old_generation_retirement() {
    let host = cleanup_host();
    let fixture = MaintenanceCase::new(&host, false);
    STATE.with(|state| state.borrow_mut().now_ms = 1500);
    fixture.drive();
    fixture.reload_and_retire();
    fixture.drive();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert_eq!(state.remaining, 1);
        assert_eq!(state.calls.len(), 2);
        assert_eq!(state.calls[0], state.calls[1]);
        state.mode = Outcome::Ready;
    });
    fixture.drive();
    fixture.drive();
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.remaining, 0);
        assert_eq!(state.applied, 1);
    });
}
