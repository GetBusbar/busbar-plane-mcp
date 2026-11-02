// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Rooted child-work retries require custody in this live plane, even when durable work and the
//! child's internal stamp would otherwise agree after a restart. Real safe slots call the
//! production binder over typed host services; the host deliberately retains the same record.
//! A raw launch pair records correlation within host custody; it grants no restart authority.

use super::*;
use busbar_contract::abi::host::service::{
    ItemSpan, WorkFindIn, WorkResumeIn, WorkSettleIn, WORK_LIVE,
};
use busbar_contract::abi::mechanism::call::{InHead, Span};
use busbar_contract::abi::mechanism::lifecycle::slot;
use busbar_contract::abi::plane::PlaneOpenOut;
use busbar_contract::abi::sdk::door::blank_out;
use busbar_test_kit::test_support::{
    fake::{self, FakeHost, FakeService, ServiceCall},
    reply,
    test_in::TestIn,
    DoorView,
};
use std::cell::RefCell;

const WORK: u64 = 42;
const REFERENCE: &str = "0123456789abcdef0123456789abcdef";
const MEMBER: &str = "fs";
const TICKET: Ticket = Ticket {
    slot: 17,
    generation: 3,
};

// Independently stated durable wire records: sha256("fs") is the final field. The rooted record
// binds host launch (37, 1), internal stamp 1 and call id 7; a new door can reuse internal stamp 1.
const ROOTED_RECORD: &[u8] =
    b"a2|37|1|1|7|dce7cce055566bed799f788cd0048e209a27a473c0f48b956fa1f1780e80d2c1";
const OTHER_LAUNCH_RECORD: &[u8] =
    b"a2|37|2|1|7|dce7cce055566bed799f788cd0048e209a27a473c0f48b956fa1f1780e80d2c1";
const LEGACY_RECORD: &[u8] =
    b"a1|1|7|dce7cce055566bed799f788cd0048e209a27a473c0f48b956fa1f1780e80d2c1";

#[derive(Clone)]
struct Case {
    owned_here: bool,
    require_local: bool,
    launch: Option<(u64, u64)>,
    record: &'static [u8],
    resume_pending_once: bool,
}

#[derive(Clone, Debug, Default)]
struct Calls {
    find: usize,
    resume: usize,
    settle: usize,
    result: Option<bool>,
    done: bool,
    held_after: bool,
    resume_handles: Vec<CompletionHandle>,
    pending_seen: bool,
    done_replay: Option<bool>,
    done_replay_issued_nothing: bool,
}

thread_local! {
    static CASE: RefCell<Option<Case>> = const { RefCell::new(None) };
    static CALLS: RefCell<Calls> = RefCell::new(Calls::default());
}

fn found_bytes() -> Vec<u8> {
    CASE.with(|case| {
        let case = case.borrow();
        let mut bytes = vec![WORK_LIVE];
        bytes.extend_from_slice(case.as_ref().expect("a configured case").record);
        bytes
    })
}

fn found_spans(len: usize) -> [ItemSpan; 1] {
    [ItemSpan {
        key: Span { offset: 0, len: 1 },
        value: Span {
            offset: 1,
            len: (len - 1) as u32,
        },
    }]
}

struct Find;
impl FakeService for Find {
    type In = WorkFindIn;
    fn serve(call: &mut ServiceCall<WorkFindIn>) -> Outcome {
        assert_eq!(call.text(|i| &i.reference), REFERENCE);
        CALLS.with(|calls| calls.borrow_mut().find += 1);
        let bytes = found_bytes();
        assert!(call.fill(|i| &i.into, &bytes, &found_spans(bytes.len())));
        call.set_value(WORK);
        Outcome::Ready
    }
}

struct Resume;
impl FakeService for Resume {
    type In = WorkResumeIn;
    fn serve(call: &mut ServiceCall<WorkResumeIn>) -> Outcome {
        assert_eq!(call.input().handle, WORK);
        let first = CALLS.with(|calls| {
            let mut calls = calls.borrow_mut();
            calls.resume += 1;
            calls.resume_handles.push(call.input().head.handle);
            calls.resume == 1
        });
        if first && CASE.with(|case| case.borrow().as_ref().unwrap().resume_pending_once) {
            return Outcome::Pending;
        }
        let bytes = found_bytes();
        assert!(call.fill(|i| &i.into, &bytes, &found_spans(bytes.len())));
        Outcome::Ready
    }
}

struct Settle;
impl FakeService for Settle {
    type In = WorkSettleIn;
    fn serve(call: &mut ServiceCall<WorkSettleIn>) -> Outcome {
        assert_eq!(call.input().handle, WORK);
        assert_eq!(call.blob(|i| &i.record), b"a1|answered");
        CALLS.with(|calls| calls.borrow_mut().settle += 1);
        Outcome::Ready
    }
}

/// Only the binder's child_work/issued fields are relevant; the other unit state is inert.
fn unit() -> CallUnit {
    CallUnit {
        key: 7,
        held: None,
        disposition: Disposition::Notice {
            method: "notifications/initialized".to_owned(),
        },
        params: None,
        framing: None,
        param_fields: Vec::new(),
        ticket: Some(TICKET),
        issued: 0,
        entitled: BTreeMap::new(),
        member: Some(MEMBER.to_owned()),
        attempt: 0,
        relay: None,
        pending: None,
        claim: None,
        verified: None,
        joined_fetch: None,
        program: None,
        program_list: None,
        readied: None,
        program_ready: None,
        task: None,
        line: None,
        child_work: ChildWork::default(),
        session: None,
        negotiating: None,
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
        let host = input.open().host().expect("the fixture lends its host");
        let plane = McpDoor {
            services: Services::of(host),
            ..McpDoor::default()
        };
        let case = CASE.with(|case| case.borrow().as_ref().unwrap().clone());
        if case.owned_here {
            door_relay_cleanup::hold(&plane, WORK, 1000);
        }
        let child = crate::ask::ChildLeg {
            launch: case.launch,
            generation: 1,
            wait: serde_json::json!(7),
            asks: vec![("answer".to_owned(), serde_json::json!(11))],
            work: Some(REFERENCE.to_owned()),
        };
        let mut unit = unit();
        let mut bound = bind_child_work(
            &plane,
            TICKET,
            &mut unit,
            MEMBER,
            &child,
            case.require_local,
        );
        if case.resume_pending_once {
            // The exact unit and plane survive this PENDING result. No successful service is
            // replayed, and the custody entry remains present while resume awaits completion.
            assert!(bound.is_pending());
            assert!(!unit.child_work.resumed);
            assert!(!unit.child_work.done);
            assert!(plane.relays.with_all(|works| works.contains_key(&WORK)));
            CALLS.with(|calls| {
                let mut calls = calls.borrow_mut();
                assert_eq!((calls.find, calls.resume, calls.settle), (1, 1, 0));
                calls.pending_seen = true;
            });
            bound = bind_child_work(
                &plane,
                TICKET,
                &mut unit,
                MEMBER,
                &child,
                case.require_local,
            );
            assert_eq!(bound, std::task::Poll::Ready(true));
            assert!(unit.child_work.done);
            assert!(!plane.relays.with_all(|works| works.contains_key(&WORK)));
            let before = CALLS.with(|calls| {
                let calls = calls.borrow();
                (calls.find, calls.resume, calls.settle)
            });
            // Only this same unit's completed bind may bypass the now-removed custody entry.
            let repeated = bind_child_work(
                &plane,
                TICKET,
                &mut unit,
                MEMBER,
                &child,
                case.require_local,
            );
            CALLS.with(|calls| {
                let mut calls = calls.borrow_mut();
                calls.done_replay = match repeated {
                    std::task::Poll::Ready(bound) => Some(bound),
                    std::task::Poll::Pending => None,
                };
                calls.done_replay_issued_nothing =
                    before == (calls.find, calls.resume, calls.settle);
            });
        }
        CALLS.with(|calls| {
            let mut calls = calls.borrow_mut();
            calls.result = match bound {
                std::task::Poll::Ready(bound) => Some(bound),
                std::task::Poll::Pending => None,
            };
            calls.done = unit.child_work.done;
            calls.held_after = plane.relays.with_all(|works| works.contains_key(&WORK));
        });
        instance.open(plane);
        Outcome::Ready
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

mod fixture_door {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::plane::Ops,
        statement: busbar_contract::abi::sdk::door::statement("mcp-work-custody-fixture", "1.6.0", 4),
        lifecycle: {
            validate: busbar_contract::abi::sdk::Safe<crate::tests::fixture::Idle<busbar_contract::abi::mechanism::lifecycle::ValidateIn, busbar_contract::abi::mechanism::call::OutHead>>,
            open: busbar_contract::abi::sdk::Safe<super::Open>,
            refresh: busbar_contract::abi::sdk::Safe<crate::tests::fixture::Idle<busbar_contract::abi::mechanism::lifecycle::RefreshIn, busbar_contract::abi::plane::PlaneRefreshOut>>,
            retire: busbar_contract::abi::sdk::Safe<crate::tests::fixture::Idle<busbar_contract::abi::mechanism::lifecycle::GenIn, busbar_contract::abi::mechanism::call::OutHead>>,
            tick: busbar_contract::abi::sdk::Safe<crate::tests::fixture::Idle<busbar_contract::abi::mechanism::lifecycle::TickIn, busbar_contract::abi::mechanism::lifecycle::TickOut>>,
            drive: busbar_contract::abi::sdk::Safe<crate::tests::fixture::Idle<busbar_contract::abi::plane::PlaneDriveIn, busbar_contract::abi::plane::PlaneDriveOut>>,
            cancel: busbar_contract::abi::sdk::Safe<crate::tests::fixture::Idle<busbar_contract::abi::plane::PlaneCancelIn, busbar_contract::abi::plane::PlaneCancelOut>>,
            release: busbar_contract::abi::sdk::Safe<crate::tests::fixture::Idle<busbar_contract::abi::mechanism::lifecycle::ReleaseIn, busbar_contract::abi::mechanism::call::OutHead>>,
            close: busbar_contract::abi::sdk::Safe<super::Close>,
        },
    }
}

fn run(case: Case) -> Calls {
    CASE.with(|configured| *configured.borrow_mut() = Some(case));
    CALLS.with(|calls| *calls.borrow_mut() = Calls::default());
    let host = FakeHost::new()
        .ctx(busbar_contract::abi::mechanism::ticket::HostCtx { handle: 71 })
        .serve(fake::host::WORK_FIND, Find)
        .serve(fake::host::WORK_RESUME, Resume)
        .serve(fake::host::WORK_SETTLE, Settle);
    let view = DoorView::of(fixture_door::MACRO_DOOR);
    let input = host.lend_in(
        TestIn::<PlaneOpenIn>::new()
            .set(|i| &i.open.head.op, slot::OPEN)
            .set(|i| &i.open.generation, 1),
    );
    let mut opened = reply::call_hosted_in(
        view.op::<busbar_contract::abi::plane::Ops>(|o| &o.head.open)
            .unwrap(),
        None,
        &input,
        blank_out::<PlaneOpenOut>(),
    );
    assert_eq!(opened.outcome, Outcome::Ready, "{opened:?}");
    let instance = opened
        .take_instance()
        .expect("the fixture opened an instance");
    let input = TestIn::<InHead>::new().set(|i| &i.op, slot::CLOSE);
    let closed = reply::close_in(
        view.op::<busbar_contract::abi::plane::Ops>(|o| &o.head.close)
            .unwrap(),
        instance,
        &input,
        blank_out::<OutHead>(),
    );
    assert_eq!(closed.outcome, Outcome::Ready, "{closed:?}");
    CALLS.with(|calls| calls.borrow().clone())
}

fn rooted(owned_here: bool, record: &'static [u8]) -> Case {
    Case {
        owned_here,
        require_local: true,
        launch: Some((37, 1)),
        record,
        resume_pending_once: false,
    }
}

fn positive_control() {
    let calls = run(rooted(true, ROOTED_RECORD));
    assert_eq!(calls.result, Some(true), "{calls:?}");
    assert_eq!((calls.find, calls.resume, calls.settle), (1, 1, 1));
    assert!(calls.done);
    assert!(!calls.held_after, "successful settlement releases custody");
}

#[test]
fn rooted_child_work_owned_by_the_current_plane_resumes_and_settles() {
    positive_control();
}

#[test]
fn same_plane_pending_resume_replays_its_handle_and_completed_unit_needs_no_custody() {
    positive_control();
    let mut case = rooted(true, ROOTED_RECORD);
    case.resume_pending_once = true;
    let calls = run(case);
    assert!(calls.pending_seen, "{calls:?}");
    assert_eq!(calls.result, Some(true), "{calls:?}");
    assert_eq!((calls.find, calls.resume, calls.settle), (1, 2, 1));
    assert_eq!(calls.resume_handles.len(), 2);
    assert_eq!(calls.resume_handles[0], calls.resume_handles[1]);
    assert_eq!(calls.resume_handles[0].ticket, TICKET);
    assert!(calls.done);
    assert!(!calls.held_after);
    assert_eq!(calls.done_replay, Some(true));
    assert!(calls.done_replay_issued_nothing);
}

#[test]
fn a_fresh_plane_refuses_identical_durable_child_work_before_resume_or_settle() {
    positive_control();
    let calls = run(rooted(false, ROOTED_RECORD));
    assert_eq!(calls.result, Some(false), "{calls:?}");
    assert_eq!((calls.find, calls.resume, calls.settle), (1, 0, 0));
    assert!(!calls.done);
    assert!(!calls.held_after);
}

#[test]
fn current_custody_cannot_authorize_a_changed_child_launch_record() {
    positive_control();
    let calls = run(rooted(true, OTHER_LAUNCH_RECORD));
    assert_eq!(calls.result, Some(false), "{calls:?}");
    assert_eq!((calls.find, calls.resume, calls.settle), (1, 0, 0));
    assert!(!calls.done);
    assert!(
        calls.held_after,
        "a refused record does not consume custody"
    );
}

#[test]
fn legacy_unrooted_child_work_keeps_its_existing_durable_binding() {
    positive_control();
    let calls = run(Case {
        owned_here: false,
        require_local: false,
        launch: None,
        record: LEGACY_RECORD,
        resume_pending_once: false,
    });
    assert_eq!(calls.result, Some(true), "{calls:?}");
    assert_eq!((calls.find, calls.resume, calls.settle), (1, 1, 1));
    assert!(calls.done);
}
