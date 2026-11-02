// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real safe slots drive the production maintenance loop over controlled host completions.

use super::*;
use busbar_contract::abi::host::service::{
    ClockNowIn, ClockReading, ItemSpan, WorkOpenIn, WorkSettleIn,
};
use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, Outcome, Span};
use busbar_contract::abi::mechanism::lifecycle::{
    slot, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn,
};
use busbar_contract::abi::plane::{PlaneCancelIn, PlaneCancelOut, PlaneLifecycle, PlaneRefreshOut};
use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureRetention, CaptureSlot};
use busbar_contract::abi::sdk::completion_retirement::{self as wire, Capability};
use busbar_contract::abi::sdk::door::{blank_in, blank_out, kind_op, Lifecycle};
use busbar_contract::abi::sdk::plane_life::{PlaneLife, Refresh, Retire};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot, Services};
use busbar_test_kit::test_support::{
    fake::{self, FakeHost, FakeService, ServiceCall},
    reply,
};
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

struct Clock;
impl FakeService for Clock {
    type In = ClockNowIn;
    fn serve(call: &mut ServiceCall<ClockNowIn>) -> Outcome {
        STATE.with(|state| {
            let state = state.borrow();
            if state.clock_fails {
                return Outcome::Failed;
            }
            call.put(
                |i| &i.reading,
                ClockReading {
                    size: std::mem::size_of::<ClockReading>() as u32,
                    _reserved: 0,
                    wall_ns: state.now_ms * 1_000_000,
                    mono_ns: state.now_ms * 1_000_000,
                },
            );
            Outcome::Ready
        })
    }
}

struct OpenWork;
impl FakeService for OpenWork {
    type In = WorkOpenIn;
    fn serve(call: &mut ServiceCall<WorkOpenIn>) -> Outcome {
        let reference = b"0123456789abcdef0123456789abcdef";
        assert!(call.fill(
            |i| &i.into,
            reference,
            &[ItemSpan {
                key: Span {
                    offset: 0,
                    len: reference.len() as u64
                },
                value: Span {
                    offset: busbar_contract::abi::plane::SPAN_ABSENT,
                    len: 0
                }
            }]
        ));
        call.set_value(WORK);
        Outcome::Ready
    }
}

struct Settle;
impl FakeService for Settle {
    type In = WorkSettleIn;
    fn serve(call: &mut ServiceCall<WorkSettleIn>) -> Outcome {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert_eq!(call.input().handle, WORK);
            state.calls.push(call.input().head.handle);
            state.records.push(call.blob(|i| &i.record).to_vec());
            if state.mode == Outcome::Ready {
                state.applied += 1;
                assert_eq!(state.applied, 1, "confirmed cleanup was issued twice");
            }
            state.mode
        })
    }
}

struct Capture;
impl CaptureHome for Capture {
    fn retention() -> &'static CaptureRetention {
        static RETENTION: std::sync::OnceLock<CaptureRetention> = std::sync::OnceLock::new();
        RETENTION.get_or_init(Default::default)
    }
    fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R {
        thread_local! { static SLOT: RefCell<CaptureSlot> = RefCell::new(CaptureSlot::default()); }
        SLOT.with(|slot| f(&mut slot.borrow_mut()))
    }
}

struct Open;
impl SafeSlot for Open {
    type State = McpDoor;
    type In = OpenIn;
    type Out = OpenOut;
    fn call(
        instance: Instance<'_, McpDoor>,
        input: Lent<'_, OpenIn>,
        _: Out<'_, OpenOut>,
    ) -> Outcome {
        let host = input.host().unwrap();
        let plane = McpDoor {
            services: Services::of(host),
            host: Some(Host::of(host)),
            ..McpDoor::default()
        };
        if input.generation() == 0 {
            // Exercise the actual post-open clock-refusal path, not a hand-built cleanup entry.
            let child = crate::ask::ChildLeg {
                generation: 1,
                wait: serde_json::json!(7),
                asks: Vec::new(),
                work: None,
            };
            let opened = super::super::open_child_work(
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
            assert!(matches!(opened, super::super::ChildOpened::Refused(..)));
        } else {
            super::super::door_relay_cleanup::hold(&plane, WORK, 1000);
        }
        instance.open(plane);
        Outcome::Ready
    }
}

struct PollDriver;
impl SafeSlot for PollDriver {
    type State = McpDoor;
    type In = DriveIn;
    type Out = OutHead;
    fn call(
        instance: Instance<'_, McpDoor>,
        input: Lent<'_, DriveIn>,
        _: Out<'_, OutHead>,
    ) -> Outcome {
        let plane = instance.get().unwrap();
        let pending = super::drive(
            &instance,
            plane,
            input.head().host(),
            input.head().extensions().bytes(),
        )
        .unwrap();
        let ack = plane.legacy_seq.with_all(|states| {
            states
                .get_mut(&())
                .and_then(|driver| driver.retirement.acknowledgement(0).unwrap())
        });
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.remaining = plane.relays.with_all(|works| works.len());
            if state.confirm {
                if let Some(ack) = ack {
                    assert_eq!(ack.capability, state.cap);
                    state.cap.nonce += 1;
                    state.cap.acknowledged = wire::ack_digest(&ack).unwrap();
                }
            }
        });
        if pending {
            Outcome::Pending
        } else {
            Outcome::Ready
        }
    }
}

struct Close;
impl SafeSlot for Close {
    type State = McpDoor;
    type In = InHead;
    type Out = OutHead;
    fn call(_: Instance<'_, McpDoor>, _: Lent<'_, InHead>, _: Out<'_, OutHead>) -> Outcome {
        Outcome::Ready
    }
}

struct Cancel;
impl SafeSlot for Cancel {
    type State = McpDoor;
    type In = PlaneCancelIn;
    type Out = PlaneCancelOut;
    fn call(
        instance: Instance<'_, McpDoor>,
        input: Lent<'_, PlaneCancelIn>,
        out: Out<'_, PlaneCancelOut>,
    ) -> Outcome {
        <McpDoor as PlaneLife>::cancel(instance, input, out)
    }
}

struct Fixture {
    instance: *mut c_void,
    _host: FakeHost,
}
impl Fixture {
    fn new(clock_fails: bool) -> Self {
        STATE.with(|state| {
            *state.borrow_mut() = State {
                clock_fails,
                ..State::default()
            }
        });
        let host = FakeHost::new()
            .ctx(HostCtx { handle: 71 })
            .serve(fake::host::CLOCK_NOW, Clock)
            .serve(fake::host::WORK_OPEN, OpenWork)
            .serve(fake::host::WORK_SETTLE, Settle);
        let mut input = blank_in::<OpenIn>();
        input.head.op = slot::OPEN;
        input.generation = u64::from(!clock_fails);
        let opened = reply::call_hosted(
            kind_op::<Lifecycle, Safe<Open>, Capture, { slot::OPEN }>().unwrap(),
            std::ptr::null_mut(),
            &host.lend_to(input),
            blank_out::<OpenOut>(),
        );
        assert_eq!(opened.outcome, Outcome::Ready, "{opened:?}");
        Self {
            instance: opened.out.instance,
            _host: host,
        }
    }
    fn drive(&self) {
        let extensions =
            STATE.with(|state| wire::append_capability(&[], state.borrow().cap).unwrap());
        let mut input = blank_in::<DriveIn>();
        input.head.op = slot::DRIVE;
        input.head.ticket = DRIVER;
        input.head.host = HostCtx { handle: 71 };
        input.driver = DRIVER;
        input.head.extensions = busbar_contract::abi::mechanism::call::Blob {
            ptr: extensions.as_ptr(),
            len: extensions.len(),
            ..busbar_contract::abi::mechanism::call::Blob::ZERO
        };
        let answer = reply::call(
            kind_op::<Lifecycle, Safe<PollDriver>, Capture, { slot::DRIVE }>().unwrap(),
            self.instance,
            &input,
            blank_out::<OutHead>(),
        );
        assert!(
            matches!(answer.outcome, Outcome::Ready | Outcome::Pending),
            "{answer:?}"
        );
    }
    fn reload_and_retire(&self) {
        let settings = b"{}";
        let mut input = blank_in::<RefreshIn>();
        input.head.op = slot::REFRESH;
        input.generation = 2;
        input.settings = Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            ..Blob::ZERO
        };
        let refreshed = reply::call(
            kind_op::<PlaneLifecycle, Safe<Refresh<McpDoor>>, Capture, { slot::REFRESH }>()
                .unwrap(),
            self.instance,
            &input,
            blank_out::<PlaneRefreshOut>(),
        );
        assert_eq!(refreshed.outcome, Outcome::Ready, "{refreshed:?}");
        let mut input = blank_in::<GenIn>();
        input.head.op = slot::RETIRE;
        input.generation = 1;
        let retired = reply::call(
            kind_op::<Lifecycle, Safe<Retire<McpDoor>>, Capture, { slot::RETIRE }>().unwrap(),
            self.instance,
            &input,
            blank_out::<OutHead>(),
        );
        assert_eq!(retired.outcome, Outcome::Ready, "{retired:?}");
    }
    fn cancel_caller(&self) {
        let mut input = blank_in::<PlaneCancelIn>();
        input.cancel.head.op = slot::CANCEL;
        input.cancel.ticket = Ticket {
            slot: 1,
            generation: 1,
        };
        input.unit = 1;
        let cancelled = reply::call(
            kind_op::<PlaneLifecycle, Safe<Cancel>, Capture, { slot::CANCEL }>().unwrap(),
            self.instance,
            &input,
            blank_out::<PlaneCancelOut>(),
        );
        assert_eq!(cancelled.outcome, Outcome::Ready);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let mut input = blank_in::<InHead>();
        input.op = slot::CLOSE;
        let closed = reply::call(
            kind_op::<Lifecycle, Safe<Close>, Capture, { slot::CLOSE }>().unwrap(),
            self.instance,
            &input,
            blank_out::<OutHead>(),
        );
        assert_eq!(closed.outcome, Outcome::Ready);
    }
}

#[test]
fn expiry_is_maintained_without_another_ask_and_pending_keeps_the_full_handle() {
    let fixture = Fixture::new(false);
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
            .all(|record| record.as_slice() == super::super::CHILD_LAPSED));
    });
}

#[test]
fn clock_refusal_after_open_keeps_immediate_cleanup_even_while_clock_stays_unavailable() {
    let fixture = Fixture::new(true);
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
    let fixture = Fixture::new(false);
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
