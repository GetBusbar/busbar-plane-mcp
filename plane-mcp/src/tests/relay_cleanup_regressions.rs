// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real safe slots drive the production maintenance loop over controlled host completions.

use super::*;
use busbar_contract::abi::host::service::{
    ClockNowIn, ClockReading, ItemSpan, WorkOpenIn, WorkSettleIn,
};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome, Span, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot, GenIn, RefreshIn};
use busbar_contract::abi::plane::{
    PlaneCancelIn, PlaneCancelOut, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut,
};
use busbar_contract::abi::sdk::completion_retirement::{self as wire, Capability};
use busbar_contract::abi::sdk::door::blank_out;
use busbar_contract::abi::sdk::plane_life::{PlaneLife, Refresh, Retire};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot, Services};
use busbar_test_kit::test_support::{
    fake::{self, FakeHost, FakeService, ServiceCall},
    reply,
    test_in::TestIn,
    DoorView,
};
use std::cell::RefCell;

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
                    len: reference.len() as u32
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

struct Open;
impl SafeSlot for Open {
    type State = McpDoor;
    type In = PlaneOpenIn;
    type Out = PlaneOpenOut;
    fn call(
        instance: Instance<'_, McpDoor>,
        input: Lent<'_, PlaneOpenIn>,
        _: Out<'_, PlaneOpenOut>,
    ) -> Outcome {
        let host = input.open().host().unwrap();
        let plane = McpDoor {
            services: Services::of(host),
            host: Some(Host::of(host)),
            ..McpDoor::default()
        };
        if input.open().generation() == 0 {
            // Exercise the actual post-open clock-refusal path, not a hand-built cleanup entry.
            let child = crate::ask::ChildLeg {
                launch: None,
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
    type In = PlaneDriveIn;
    type Out = PlaneDriveOut;
    fn call(
        instance: Instance<'_, McpDoor>,
        input: Lent<'_, PlaneDriveIn>,
        _: Out<'_, PlaneDriveOut>,
    ) -> Outcome {
        let plane = instance.get().unwrap();
        let pending = super::drive(
            &instance,
            plane,
            input.drive().head().host(),
            input.drive().head().extensions().bytes(),
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

mod fixture_door {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::plane::Ops,
        statement: busbar_contract::abi::sdk::door::statement("mcp-fixture", "1.6.0", 4),
        lifecycle: {
            validate: busbar_contract::abi::sdk::Safe<crate::tests::fixture::Idle<busbar_contract::abi::mechanism::lifecycle::ValidateIn, busbar_contract::abi::mechanism::call::OutHead>>,
            open: busbar_contract::abi::sdk::Safe<super::Open>,
            refresh: busbar_contract::abi::sdk::Safe<super::Refresh<super::McpDoor>>,
            retire: busbar_contract::abi::sdk::Safe<super::Retire<super::McpDoor>>,
            tick: busbar_contract::abi::sdk::Safe<crate::tests::fixture::Idle<busbar_contract::abi::mechanism::lifecycle::TickIn, busbar_contract::abi::mechanism::lifecycle::TickOut>>,
            drive: busbar_contract::abi::sdk::Safe<super::PollDriver>,
            cancel: busbar_contract::abi::sdk::Safe<super::Cancel>,
            release: busbar_contract::abi::sdk::Safe<crate::tests::fixture::Idle<busbar_contract::abi::mechanism::lifecycle::ReleaseIn, busbar_contract::abi::mechanism::call::OutHead>>,
            close: busbar_contract::abi::sdk::Safe<super::Close>,
        },
    }
}

fn view() -> DoorView {
    DoorView::of(fixture_door::MACRO_DOOR)
}

fn fixture_host() -> FakeHost {
    FakeHost::new()
        .ctx(HostCtx { handle: 71 })
        .serve(fake::host::CLOCK_NOW, Clock)
        .serve(fake::host::WORK_OPEN, OpenWork)
        .serve(fake::host::WORK_SETTLE, Settle)
}
struct Fixture<'h> {
    instance: Option<reply::Instance<'h>>,
}
impl<'h> Fixture<'h> {
    fn new(host: &'h FakeHost, clock_fails: bool) -> Self {
        STATE.with(|state| {
            *state.borrow_mut() = State {
                clock_fails,
                ..State::default()
            }
        });
        let input = host.lend_in(
            TestIn::<PlaneOpenIn>::new()
                .set(|i| &i.open.head.op, slot::OPEN)
                .set(|i| &i.open.generation, u64::from(!clock_fails)),
        );
        // The hosted OPEN retains the externally owned tables until this fixture closes.
        let mut opened = reply::call_hosted_in(
            view()
                .op::<busbar_contract::abi::plane::Ops>(|o| &o.head.open)
                .unwrap(),
            None,
            &input,
            blank_out::<PlaneOpenOut>(),
        );
        assert_eq!(opened.outcome, Outcome::Ready, "{opened:?}");
        Self {
            instance: Some(
                opened
                    .take_instance()
                    .expect("the hosted open owns an instance"),
            ),
        }
    }
    fn drive(&self) {
        let extensions =
            STATE.with(|state| wire::append_capability(&[], state.borrow().cap).unwrap());
        let input = TestIn::<PlaneDriveIn>::new()
            .set(|i| &i.drive.head.op, slot::DRIVE)
            .set(|i| &i.drive.head.ticket, DRIVER)
            .set(|i| &i.drive.head.host.handle, 71)
            .set(|i| &i.drive.driver, DRIVER)
            .blob(|i| &i.drive.head.extensions, &extensions, BLOB_OCTETS);
        // TestIn borrows the capability bytes for this call; the instance retains its host loan.
        let answer = reply::call_in(
            view()
                .op::<busbar_contract::abi::plane::Ops>(|o| &o.head.drive)
                .unwrap(),
            self.instance.as_ref(),
            &input,
            blank_out::<PlaneDriveOut>(),
        );
        assert!(
            matches!(answer.outcome, Outcome::Ready | Outcome::Pending),
            "{answer:?}"
        );
    }
    fn reload_and_retire(&self) {
        let input = TestIn::<RefreshIn>::new()
            .set(|i| &i.head.op, slot::REFRESH)
            .set(|i| &i.generation, 2)
            .settings(b"{}");
        // The real plane REFRESH copies its settings while the instance proof stays borrowed.
        let refreshed = reply::call_in(
            view()
                .op::<busbar_contract::abi::plane::Ops>(|o| &o.head.refresh)
                .unwrap(),
            self.instance.as_ref(),
            &input,
            blank_out::<PlaneRefreshOut>(),
        );
        assert_eq!(refreshed.outcome, Outcome::Ready, "{refreshed:?}");
        let input = TestIn::<GenIn>::new()
            .set(|i| &i.head.op, slot::RETIRE)
            .set(|i| &i.generation, 1);
        // Old-generation retirement cannot consume or replace the instance proof.
        let retired = reply::call_in(
            view()
                .op::<busbar_contract::abi::plane::Ops>(|o| &o.head.retire)
                .unwrap(),
            self.instance.as_ref(),
            &input,
            blank_out::<OutHead>(),
        );
        assert_eq!(retired.outcome, Outcome::Ready, "{retired:?}");
    }
    fn cancel_caller(&self) {
        let input = TestIn::<PlaneCancelIn>::new()
            .set(|i| &i.cancel.head.op, slot::CANCEL)
            .set(
                |i| &i.cancel.ticket,
                Ticket {
                    slot: 1,
                    generation: 1,
                },
            )
            .set(|i| &i.unit, 1);
        // Caller cancellation is on this same live plane; no output buffer is borrowed past return.
        let cancelled = reply::call_in(
            view()
                .op::<busbar_contract::abi::plane::Ops>(|o| &o.head.cancel)
                .unwrap(),
            self.instance.as_ref(),
            &input,
            blank_out::<PlaneCancelOut>(),
        );
        assert_eq!(cancelled.outcome, Outcome::Ready);
    }
}
impl Drop for Fixture<'_> {
    fn drop(&mut self) {
        let input = TestIn::<InHead>::new().set(|i| &i.op, slot::CLOSE);
        // Consume the instance before the external FakeHost goes out of scope.
        let closed = reply::close_in(
            view()
                .op::<busbar_contract::abi::plane::Ops>(|o| &o.head.close)
                .unwrap(),
            self.instance.take().unwrap(),
            &input,
            blank_out::<OutHead>(),
        );
        assert_eq!(closed.outcome, Outcome::Ready);
    }
}

#[test]
fn expiry_is_maintained_without_another_ask_and_pending_keeps_the_full_handle() {
    let host = fixture_host();
    let fixture = Fixture::new(&host, false);
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
    let host = fixture_host();
    let fixture = Fixture::new(&host, true);
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
    let host = fixture_host();
    let fixture = Fixture::new(&host, false);
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
