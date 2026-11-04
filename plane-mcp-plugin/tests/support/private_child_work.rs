// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// Rooted child-work retry assertions over the actual private binder, without a test-only product.

use super::*;
use busbar_contract::abi::host::service::{
    ItemSpan, WorkFindIn, WorkResumeIn, WorkSettleIn, WORK_LIVE,
};
use busbar_contract::abi::mechanism::call::Span;
use std::cell::RefCell;

const WORK: u64 = 42;
const REFERENCE: &str = "0123456789abcdef0123456789abcdef";
const MEMBER: &str = "fs";
const TICKET: Ticket = Ticket {
    slot: 17,
    generation: 3,
};

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
    violations: Vec<&'static str>,
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

use busbar_contract::abi::host::service::{HostSlots, ServiceBufs, ServiceOut, SERVICES};
use busbar_contract::abi::mechanism::call::RawOutcome;
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use std::ffi::c_void;
fn finish(
    out: *mut ServiceOut,
    outcome: Outcome,
    value: u64,
    len: usize,
    items: usize,
) -> RawOutcome {
    let raw = RawOutcome::of(outcome);
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            value,
            len: len as u64,
            items: items as u64,
            needed_bytes: 0,
            needed_items: 0,
            ..ServiceOut::ZERO
        });
    }
    raw
}
fn fill_child_record(into: ServiceBufs) -> usize {
    let bytes = found_bytes();
    let spans = found_spans(bytes.len());
    if into.cap < bytes.len() || into.spans_cap < spans.len() {
        CALLS.with(|calls| calls.borrow_mut().violations.push("short output buffers"));
        return 0;
    }
    // SAFETY: these are the exact live output slices lent by the actual binder's service call.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), into.buf, bytes.len());
        std::ptr::copy_nonoverlapping(spans.as_ptr(), into.spans, spans.len());
    }
    bytes.len()
}
extern "C" fn find_work(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<WorkFindIn>().read_unaligned() };
    let reference = unsafe { std::slice::from_raw_parts(input.reference.ptr, input.reference.len) };
    if reference != REFERENCE.as_bytes() {
        CALLS.with(|calls| calls.borrow_mut().violations.push("wrong reference"));
    }
    CALLS.with(|calls| calls.borrow_mut().find += 1);
    let len = fill_child_record(input.into);
    finish(out, Outcome::Ready, WORK, len, 1)
}
extern "C" fn resume_work(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<WorkResumeIn>().read_unaligned() };
    if input.handle != WORK {
        CALLS.with(|calls| calls.borrow_mut().violations.push("wrong work handle"));
    }
    let first = CALLS.with(|calls| {
        let mut calls = calls.borrow_mut();
        calls.resume += 1;
        calls.resume_handles.push(input.head.handle);
        calls.resume == 1
    });
    if first && CASE.with(|case| case.borrow().as_ref().unwrap().resume_pending_once) {
        return finish(out, Outcome::Pending, 0, 0, 0);
    }
    let len = fill_child_record(input.into);
    finish(out, Outcome::Ready, 0, len, 1)
}
extern "C" fn settle_work(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<WorkSettleIn>().read_unaligned() };
    if input.handle != WORK {
        CALLS.with(|calls| calls.borrow_mut().violations.push("wrong work handle"));
    }
    let record = unsafe { std::slice::from_raw_parts(input.record.ptr, input.record.len) };
    if record != b"a1|answered" {
        CALLS.with(|calls| {
            calls
                .borrow_mut()
                .violations
                .push("wrong settlement record")
        });
    }
    CALLS.with(|calls| calls.borrow_mut().settle += 1);
    finish(out, Outcome::Ready, 0, 0, 0)
}
/// Only the binder's child_work/issued fields are relevant; the other unit state is inert.
pub(super) fn unit() -> CallUnit {
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

fn run(case: Case) -> Calls {
    CASE.with(|configured| *configured.borrow_mut() = Some(case));
    CALLS.with(|calls| *calls.borrow_mut() = Calls::default());
    let mut slots: HostSlots = unsafe { std::mem::zeroed() };
    slots.size = std::mem::size_of::<HostSlots>() as u32;
    slots.slots = SERVICES;
    slots.work_find = Some(find_work);
    slots.work_resume = Some(resume_work);
    slots.work_settle = Some(settle_work);
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx { handle: 71 },
        wake: None,
        conns: std::ptr::null(),
        services: &slots,
        io: std::ptr::null(),
    };
    let plane = McpDoor {
        services: unsafe { Services::from_raw(&tables) },
        ..McpDoor::default()
    };
    let case = CASE.with(|case| case.borrow().as_ref().unwrap().clone());
    if case.owned_here {
        door_relay_cleanup::hold(&plane, WORK, REFERENCE, 1000);
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
        assert!(bound.is_pending());
        assert!(!unit.child_work.resumed);
        assert!(!unit.child_work.done);
        assert!(plane.relays.with_all(|works| works.contains_key(&WORK)));
        CALLS.with(|calls| {
            let calls = calls.borrow();
            assert_eq!((calls.find, calls.resume, calls.settle), (1, 1, 0));
        });
        bound = bind_child_work(
            &plane,
            TICKET,
            &mut unit,
            MEMBER,
            &child,
            case.require_local,
        );
        assert!(matches!(bound, std::task::Poll::Ready(Ok(true))));
        assert!(unit.child_work.done);
        assert!(!plane.relays.with_all(|works| works.contains_key(&WORK)));
        let before = CALLS.with(|calls| {
            let calls = calls.borrow();
            (calls.find, calls.resume, calls.settle)
        });

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
                std::task::Poll::Ready(bound) => Some(bound.expect("child-work service succeeds")),
                std::task::Poll::Pending => None,
            };
            calls.done_replay_issued_nothing = before == (calls.find, calls.resume, calls.settle);
        });
    }
    CALLS.with(|calls| {
        let mut calls = calls.borrow_mut();
        calls.result = match bound {
            std::task::Poll::Ready(bound) => Some(bound.expect("child-work service succeeds")),
            std::task::Poll::Pending => None,
        };
        calls.done = unit.child_work.done;
        calls.held_after = plane.relays.with_all(|works| works.contains_key(&WORK));
    });
    let calls = CALLS.with(|calls| calls.borrow().clone());
    assert!(calls.violations.is_empty(), "{calls:?}");
    calls
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
