// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::conn::connector::{EstablishIn, ReplyIn, RequestIn, StreamIn};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::lifecycle::{
    slot, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx};
use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureSlot};
use busbar_contract::abi::sdk::door::{blank_in, blank_out, kind_op, Lifecycle};
use busbar_contract::abi::sdk::test_support::{
    fake::{self, FakeHost, FakeService, ServiceCall},
    reply,
};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use std::cell::RefCell;
use std::ffi::c_void;

const BINDING: &str = "binding";
const MEMBER: &str = "fs";
const ENDPOINT: &str = "https://up.example/messages";
const OWNER: Ticket = Ticket {
    slot: 9,
    generation: 1,
};
const FOLLOWER: Ticket = Ticket {
    slot: 10,
    generation: 1,
};
const INITIALIZE_STREAM: u64 = 1;
const NOTIFICATION_STREAM: u64 = 2;
const CALL_ID: u64 = 1;
const TIMEOUT_MS: u64 = 1000;
// RFC 9110: the POST is accepted while its RPC answer arrives over SSE.
const HTTP_ACCEPTED: u32 = 202;
const HTTP_UNAUTHORIZED: u32 = 401;

#[derive(Default)]
struct State {
    pause_stream: u64,
    resumed: bool,
    address_missing: bool,
    status: u32,
    streams: u64,
    dials: Vec<CompletionHandle>,
    bodies: Vec<Value>,
    closed: Vec<u64>,
    woken: Vec<Ticket>,
    answers: Vec<Value>,
    failures: Vec<String>,
    snapshot: Option<Snapshot>,
}

struct Snapshot {
    init: Init,
    init_by: Option<Ticket>,
    parked: Vec<Ticket>,
    waiters: usize,
    answers: usize,
    continuations: usize,
    dead: bool,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
    // The real caller keeps Calling in Conversation. The probe keeps that same continuation
    // separately from the SDK's Exchange, which stays on the real instance across ABI entries.
    static CALLS: RefCell<Vec<(Ticket, Option<Calling>)>> = const { RefCell::new(Vec::new()) };
}

extern "C" fn wake(_: HostCtx, ticket: Ticket) {
    STATE.with(|state| state.borrow_mut().woken.push(ticket));
}

struct Establish;
impl FakeService for Establish {
    type In = EstablishIn;
    fn serve(call: &mut ServiceCall<EstablishIn>) -> Outcome {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.dials.push(call.input().head.handle);
            let stream = state.streams + 1;
            if stream == state.pause_stream && !state.resumed {
                return Outcome::Pending;
            }
            state.streams = stream;
            call.set_value(stream);
            Outcome::Ready
        })
    }
}

struct Write;
impl FakeService for Write {
    type In = RequestIn;
    fn serve(call: &mut ServiceCall<RequestIn>) -> Outcome {
        if call.lent(|i| &i.piece)[0].kind == REQUEST_BODY {
            let body = serde_json::from_slice(call.lent(|i| &i.bytes)).unwrap();
            STATE.with(|state| state.borrow_mut().bodies.push(body));
        }
        call.set_len(call.input().len as u64);
        Outcome::Ready
    }
}

struct Read;
impl FakeService for Read {
    type In = ReplyIn;
    fn serve(call: &mut ServiceCall<ReplyIn>) -> Outcome {
        let code = STATE.with(|state| state.borrow().status);
        call.put(
            |i| &i.piece,
            ReplyPiece {
                kind: REPLY_ACK,
                code,
                ..ReplyPiece::default()
            },
        );
        Outcome::Ready
    }
}

struct CloseStream;
impl FakeService for CloseStream {
    type In = StreamIn;
    fn serve(call: &mut ServiceCall<StreamIn>) -> Outcome {
        STATE.with(|state| state.borrow_mut().closed.push(call.input().stream));
        Outcome::Ready
    }
}

struct Capture;
impl CaptureHome for Capture {
    fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R {
        thread_local! {static SLOT: RefCell<CaptureSlot> = RefCell::new(CaptureSlot::default());}
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
        let mut plane = McpDoor::default();
        plane.host = Some(Host::of(&host));
        plane.wake = busbar_contract::abi::sdk::services::Wake::of(&host);
        let mut link = link();
        if !STATE.with(|state| state.borrow().address_missing) {
            link.address = Some(ENDPOINT.into());
        }
        plane.legacy.insert(BINDING.into(), link);
        instance.open(plane);
        Outcome::Ready
    }
}

struct PollCall;
impl SafeSlot for PollCall {
    type State = McpDoor;
    type In = DriveIn;
    type Out = OutHead;
    fn call(instance: Instance<'_, McpDoor>, _: Lent<'_, DriveIn>, _: Out<'_, OutHead>) -> Outcome {
        let plane = instance.get().unwrap();
        let request = crate::client::jsonrpc::envelope(
            "https://up.example/events",
            "tools/call",
            None,
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#.to_vec(),
            None,
        );
        CALLS.with(|calls| {
            let mut calls = calls.borrow_mut();
            let at = calls
                .iter()
                .position(|(ticket, _)| *ticket == instance.ticket())
                .unwrap_or_else(|| {
                    calls.push((instance.ticket(), None));
                    calls.len() - 1
                });
            match super::super::call(
                &instance,
                plane,
                (BINDING, MEMBER),
                &request,
                &mut calls[at].1,
                (0, TIMEOUT_MS),
            ) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(answer) => {
                    assert!(
                        calls[at].1.is_none(),
                        "a finished call releases its continuation"
                    );
                    STATE.with(|state| match answer {
                        Ok((body, _, id, _)) => {
                            assert_eq!(id, CALL_ID);
                            state
                                .borrow_mut()
                                .answers
                                .push(serde_json::from_slice(&body).unwrap());
                        }
                        Err(why) => state.borrow_mut().failures.push(why),
                    });
                    Outcome::Ready
                }
            }
        })
    }
}

#[repr(u64)]
#[derive(Clone, Copy)]
enum Action {
    Snapshot,
    Endpoint,
    InitializeAnswer,
    CallAnswer,
}

struct Inspect;
impl SafeSlot for Inspect {
    type State = McpDoor;
    type In = GenIn;
    type Out = OutHead;
    fn call(
        instance: Instance<'_, McpDoor>,
        input: Lent<'_, GenIn>,
        _: Out<'_, OutHead>,
    ) -> Outcome {
        let plane = instance.get().unwrap();
        let woken = plane.legacy.with(&BINDING.into(), |link| {
            let link = link.unwrap();
            let event = match input.generation {
                value if value == Action::Endpoint as u64 => "event: endpoint\ndata: /messages\n\n".to_string(),
                value if value == Action::InitializeAnswer as u64 => format!("data: {}\n\n", serde_json::json!({"jsonrpc":"2.0", "id":INITIALIZE_ID, "result":{"protocolVersion":Revision::R2024_11_05.wire()}})),
                value if value == Action::CallAnswer as u64 => format!("data: {}\n\n", serde_json::json!({"jsonrpc":"2.0", "id":CALL_ID, "result":{"ok":true}})),
                _ => String::new(),
            };
            let woken = feed(link, &event);
            STATE.with(|state| state.borrow_mut().snapshot = Some(Snapshot {
                init: link.init, init_by: link.init_by, parked: link.parked.clone(),
                waiters: link.waiters.len(), answers: link.answers.len(),
                continuations: instance.parked_count(), dead: link.dead.is_some(),
            }));
            woken
        });
        wake_all(plane, woken);
        Outcome::Ready
    }
}

struct Cancel;
impl SafeSlot for Cancel {
    type State = McpDoor;
    type In = CancelIn;
    type Out = CancelOut;
    fn call(
        instance: Instance<'_, McpDoor>,
        input: Lent<'_, CancelIn>,
        _: Out<'_, CancelOut>,
    ) -> Outcome {
        cancelled(instance.get().unwrap(), input.ticket);
        CALLS.with(|calls| {
            calls
                .borrow_mut()
                .retain(|(ticket, _)| *ticket != input.ticket)
        });
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

struct Fixture {
    instance: *mut c_void,
    // Keep the host tables alive until CLOSE has destroyed the instance and parked Exchange.
    _host: FakeHost,
}

impl Fixture {
    fn new(pause_stream: u64, address_missing: bool) -> Self {
        STATE.with(|state| {
            *state.borrow_mut() = State {
                pause_stream,
                address_missing,
                status: HTTP_ACCEPTED,
                ..State::default()
            }
        });
        CALLS.with(|calls| calls.borrow_mut().clear());
        let host = FakeHost::new()
            .ctx(HostCtx { handle: 71 })
            .wake(wake)
            .serve(fake::conn::ESTABLISH, Establish)
            .serve(fake::conn::WRITE_REQUEST, Write)
            .serve(fake::conn::READ_REPLY, Read)
            .serve(fake::conn::CLOSE, CloseStream);
        let open = kind_op::<Lifecycle, Safe<Open>, Capture, { slot::OPEN }>().unwrap();
        let mut input = blank_in::<OpenIn>();
        input.head.op = slot::OPEN;
        let opened = reply::call_hosted(
            open,
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

    fn poll(&self, ticket: Ticket, resuming: bool) -> Outcome {
        let op = kind_op::<Lifecycle, Safe<PollCall>, Capture, { slot::DRIVE }>().unwrap();
        let mut input = blank_in::<DriveIn>();
        input.head.op = slot::DRIVE;
        input.head.ticket = ticket;
        if resuming {
            input.head.flags = FLAG_RESUME;
        }
        reply::call(op, self.instance, &input, blank_out::<OutHead>()).outcome
    }

    fn inspect(&self, action: Action) {
        let op = kind_op::<Lifecycle, Safe<Inspect>, Capture, { slot::RETIRE }>().unwrap();
        let mut input = blank_in::<GenIn>();
        input.head.op = slot::RETIRE;
        input.generation = action as u64;
        assert_eq!(
            reply::call(op, self.instance, &input, blank_out::<OutHead>()).outcome,
            Outcome::Ready
        );
    }

    fn cancel(&self) {
        let op = kind_op::<Lifecycle, Safe<Cancel>, Capture, { slot::CANCEL }>().unwrap();
        let mut input = blank_in::<CancelIn>();
        input.head.op = slot::CANCEL;
        input.ticket = OWNER;
        assert_eq!(
            reply::call(op, self.instance, &input, blank_out::<CancelOut>()).outcome,
            Outcome::Ready
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let close = kind_op::<Lifecycle, Safe<Close>, Capture, { slot::CLOSE }>().unwrap();
        let mut input = blank_in::<InHead>();
        input.op = slot::CLOSE;
        let closed = reply::call(close, self.instance, &input, blank_out::<OutHead>());
        assert_eq!(closed.outcome, Outcome::Ready);
        CALLS.with(|calls| calls.borrow_mut().clear());
    }
}

fn pending_owner(fixture: &Fixture) {
    assert_eq!(fixture.poll(OWNER, false), Outcome::Pending);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state.dials.len(),
            2,
            "the owner resumes the pending host operation"
        );
        assert_eq!(
            state.dials[0], state.dials[1],
            "the host handle is retained"
        );
        assert!(state.bodies.is_empty());
    });
    fixture.inspect(Action::Snapshot);
    STATE.with(|state| assert_eq!(state.borrow().snapshot.as_ref().unwrap().continuations, 1));
}

fn complete(fixture: &Fixture) {
    fixture.inspect(Action::Snapshot);
    STATE.with(|state| {
        let state = state.borrow();
        let methods: Vec<_> = state
            .bodies
            .iter()
            .map(|body| body["method"].as_str().unwrap())
            .collect();
        assert_eq!(
            methods,
            [
                crate::adapt::METHOD_INITIALIZE,
                crate::adapt::METHOD_INITIALIZED,
                "tools/call"
            ]
        );
        assert_eq!(state.bodies[0]["id"], INITIALIZE_ID);
        assert_eq!(state.bodies[2]["id"], CALL_ID);
        assert_eq!(state.closed.len(), state.streams as usize);
        let snapshot = state.snapshot.as_ref().unwrap();
        assert_eq!(snapshot.init, Init::Done);
        assert_eq!(snapshot.init_by, None);
        assert!(snapshot.parked.is_empty());
        assert_eq!(snapshot.continuations, 0);
    });
    fixture.inspect(Action::CallAnswer);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Ready);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state.answers,
            [serde_json::json!({"jsonrpc":"2.0", "id":CALL_ID, "result":{"ok":true}})]
        );
        assert!(state.failures.is_empty());
    });
}

#[test]
fn an_initialization_post_resumes_its_first_pending_host_operation_and_wakes_followers() {
    let fixture = Fixture::new(INITIALIZE_STREAM, false);
    pending_owner(&fixture);
    assert_eq!(fixture.poll(FOLLOWER, false), Outcome::Pending);
    assert_eq!(fixture.poll(FOLLOWER, true), Outcome::Pending);
    fixture.inspect(Action::Snapshot);
    STATE.with(|state| assert_eq!(state.borrow().snapshot.as_ref().unwrap().parked, [FOLLOWER]));
    STATE.with(|state| state.borrow_mut().resumed = true);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    fixture.inspect(Action::InitializeAnswer);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    STATE.with(|state| assert!(state.borrow().woken.contains(&FOLLOWER)));
    complete(&fixture);
}

#[test]
fn an_initialized_notification_resumes_without_reposting_initialize() {
    let fixture = Fixture::new(NOTIFICATION_STREAM, false);
    assert_eq!(fixture.poll(OWNER, false), Outcome::Pending);
    fixture.inspect(Action::InitializeAnswer);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.bodies.len(), 1);
        assert_eq!(
            state.dials[state.dials.len() - 1],
            state.dials[state.dials.len() - 2]
        );
    });
    STATE.with(|state| state.borrow_mut().resumed = true);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    complete(&fixture);
}

#[test]
fn cancelling_a_pending_initialization_drops_its_exchange_and_wakes_a_successor() {
    let fixture = Fixture::new(INITIALIZE_STREAM, false);
    pending_owner(&fixture);
    assert_eq!(fixture.poll(FOLLOWER, false), Outcome::Pending);
    fixture.cancel();
    fixture.inspect(Action::InitializeAnswer);
    STATE.with(|state| {
        let state = state.borrow();
        let snapshot = state.snapshot.as_ref().unwrap();
        assert_eq!(snapshot.init, Init::Idle);
        assert_eq!(snapshot.init_by, None);
        assert_eq!(snapshot.continuations, 0);
        assert_eq!(snapshot.waiters, 0);
        assert_eq!(
            snapshot.answers, 0,
            "a cancelled owner keeps no late initialization answer"
        );
        assert!(snapshot.parked.is_empty());
        assert_eq!(state.woken, [FOLLOWER]);
        assert!(state.bodies.is_empty());
    });
    STATE.with(|state| state.borrow_mut().resumed = true);
    assert_eq!(fixture.poll(FOLLOWER, true), Outcome::Pending);
    fixture.inspect(Action::Snapshot);
    STATE.with(|state| {
        assert_eq!(
            state.borrow().snapshot.as_ref().unwrap().init_by,
            Some(FOLLOWER)
        )
    });
}

#[test]
fn cancelling_a_pending_initialized_notification_releases_the_same_owner() {
    let fixture = Fixture::new(NOTIFICATION_STREAM, false);
    assert_eq!(fixture.poll(OWNER, false), Outcome::Pending);
    fixture.inspect(Action::InitializeAnswer);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    assert_eq!(fixture.poll(FOLLOWER, false), Outcome::Pending);
    fixture.cancel();
    fixture.inspect(Action::Snapshot);
    STATE.with(|state| {
        let state = state.borrow();
        let snapshot = state.snapshot.as_ref().unwrap();
        assert_eq!(snapshot.init, Init::Idle);
        assert_eq!(snapshot.init_by, None);
        assert_eq!(snapshot.continuations, 0);
        assert_eq!(snapshot.waiters, 0);
        assert_eq!(snapshot.answers, 0);
        assert!(snapshot.parked.is_empty());
        assert!(state.woken.contains(&FOLLOWER));
        assert_eq!(state.bodies.len(), 1, "only initialize was sent");
    });
}

#[test]
fn an_initialize_post_refusal_finishes_the_owner_and_wakes_followers() {
    let fixture = Fixture::new(INITIALIZE_STREAM, false);
    pending_owner(&fixture);
    assert_eq!(fixture.poll(FOLLOWER, false), Outcome::Pending);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.resumed = true;
        state.status = HTTP_UNAUTHORIZED;
    });
    assert_eq!(fixture.poll(OWNER, true), Outcome::Ready);
    assert_eq!(fixture.poll(FOLLOWER, true), Outcome::Ready);
    fixture.inspect(Action::Snapshot);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.failures.len(), 2);
        assert!(state
            .failures
            .iter()
            .all(|why| why.contains(&HTTP_UNAUTHORIZED.to_string())));
        let snapshot = state.snapshot.as_ref().unwrap();
        assert!(snapshot.dead);
        assert_eq!(snapshot.continuations, 0);
        assert_eq!(snapshot.init_by, None);
        assert_eq!(snapshot.waiters, 0);
        assert!(state.woken.contains(&FOLLOWER));
    });
}

#[test]
fn an_initialized_notification_refusal_finishes_the_owner_and_wakes_followers() {
    let fixture = Fixture::new(NOTIFICATION_STREAM, false);
    assert_eq!(fixture.poll(OWNER, false), Outcome::Pending);
    fixture.inspect(Action::InitializeAnswer);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    assert_eq!(fixture.poll(FOLLOWER, false), Outcome::Pending);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.resumed = true;
        state.status = HTTP_UNAUTHORIZED;
    });
    assert_eq!(fixture.poll(OWNER, true), Outcome::Ready);
    assert_eq!(fixture.poll(FOLLOWER, true), Outcome::Ready);
    fixture.inspect(Action::Snapshot);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.failures.len(), 2);
        assert!(state
            .failures
            .iter()
            .all(|why| why.contains(&HTTP_UNAUTHORIZED.to_string())));
        let snapshot = state.snapshot.as_ref().unwrap();
        assert!(snapshot.dead);
        assert_eq!(snapshot.continuations, 0);
        assert_eq!(snapshot.init_by, None);
        assert_eq!(snapshot.waiters, 0);
        assert!(state.woken.contains(&FOLLOWER));
        assert_eq!(state.bodies.len(), 2, "the actual call was never sent");
    });
}

#[test]
fn repeated_polls_park_once_until_the_endpoint_event_arrives() {
    let fixture = Fixture::new(INITIALIZE_STREAM, true);
    assert_eq!(fixture.poll(OWNER, false), Outcome::Pending);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    fixture.inspect(Action::Snapshot);
    STATE.with(|state| assert_eq!(state.borrow().snapshot.as_ref().unwrap().parked, [OWNER]));
    fixture.inspect(Action::Endpoint);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    STATE.with(|state| state.borrow_mut().resumed = true);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    fixture.inspect(Action::InitializeAnswer);
    assert_eq!(fixture.poll(OWNER, true), Outcome::Pending);
    complete(&fixture);
}

#[test]
fn closing_an_instance_destroys_a_pending_initialize_without_sending_it() {
    let fixture = Fixture::new(INITIALIZE_STREAM, false);
    pending_owner(&fixture);
    drop(fixture);
    STATE.with(|state| {
        let state = state.borrow();
        assert!(state.bodies.is_empty());
        assert!(
            state.closed.is_empty(),
            "the pending dial produced no stream"
        );
    });
}
