// SPDX-License-Identifier: Apache-2.0
// Ordinary assertions on actual legacy orchestration and actual SDK Exchange values.
use super::*;
use busbar_contract::abi::host::conn::connector::{
    ConnectorSlots, EstablishIn, ReplyIn, RequestIn, StreamIn, SERVICES,
};
use busbar_contract::abi::host::service::ServiceOut;
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables};
use busbar_contract::abi::sdk::exchange::Exchange;
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
    // The actual orchestration keeps Calling separately from its owned SDK Exchange.
    // Literal SDK Instance parking counts are checked by the real-door companion path.
    static CALLS: RefCell<Vec<(Ticket, Option<Calling>)>> = const { RefCell::new(Vec::new()) };
}

extern "C" fn wake(_: HostCtx, ticket: Ticket) {
    STATE.with(|state| state.borrow_mut().woken.push(ticket));
}

fn finish(out: *mut ServiceOut, outcome: Outcome, value: u64, len: u64) -> RawOutcome {
    let raw = RawOutcome::of(outcome);
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            value,
            len,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            ..ServiceOut::ZERO
        });
    }
    raw
}
extern "C" fn establish(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<EstablishIn>().read_unaligned() };
    let answer = STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.dials.push(input.head.handle);
        let stream = state.streams + 1;
        if stream == state.pause_stream && !state.resumed {
            return None;
        }
        state.streams = stream;
        Some(stream)
    });
    match answer {
        Some(stream) => finish(out, Outcome::Ready, stream, 0),
        None => finish(out, Outcome::Pending, 0, 0),
    }
}
extern "C" fn write_request(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<RequestIn>().read_unaligned() };
    let piece = unsafe { input.piece.read_unaligned() };
    if piece.kind == REQUEST_BODY {
        let bytes = unsafe { std::slice::from_raw_parts(input.buf, input.len) };
        let Ok(body) = serde_json::from_slice(bytes) else {
            return finish(out, Outcome::Failed, 0, 0);
        };
        STATE.with(|state| state.borrow_mut().bodies.push(body));
    }
    finish(out, Outcome::Ready, 0, input.len as u64)
}
extern "C" fn read_reply(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<ReplyIn>().read_unaligned() };
    let code = STATE.with(|state| state.borrow().status);
    unsafe {
        input.piece.write(ReplyPiece {
            kind: REPLY_ACK,
            code,
            ..ReplyPiece::default()
        });
    }
    finish(out, Outcome::Ready, 0, 0)
}
extern "C" fn close_stream(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<StreamIn>().read_unaligned() };
    STATE.with(|state| state.borrow_mut().closed.push(input.stream));
    finish(out, Outcome::Ready, 0, 0)
}
struct LegacyHost {
    tables: Box<HostTables>,
    _conns: Box<ConnectorSlots>,
}
fn legacy_host() -> LegacyHost {
    let mut conns: Box<ConnectorSlots> = Box::new(unsafe { std::mem::zeroed() });
    conns.size = std::mem::size_of::<ConnectorSlots>() as u32;
    conns.slots = SERVICES;
    conns.establish = Some(establish);
    conns.write_request = Some(write_request);
    conns.read_reply = Some(read_reply);
    conns.close = Some(close_stream);
    let tables = Box::new(HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx { handle: 71 },
        wake: Some(wake),
        conns: &*conns,
        services: std::ptr::null(),
        io: std::ptr::null(),
    });
    LegacyHost {
        tables,
        _conns: conns,
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
struct InitializationCase<'host> {
    plane: McpDoor,
    posts: RefCell<Vec<(Ticket, Exchange)>>,
    _host: std::marker::PhantomData<&'host LegacyHost>,
}
impl<'host> InitializationCase<'host> {
    fn new(host: &'host LegacyHost, pause_stream: u64, address_missing: bool) -> Self {
        STATE.with(|state| {
            *state.borrow_mut() = State {
                pause_stream,
                address_missing,
                status: HTTP_ACCEPTED,
                ..State::default()
            }
        });
        CALLS.with(|calls| calls.borrow_mut().clear());
        let plane = McpDoor {
            host: Some(unsafe { Host::from_raw(&host.tables) }),
            wake: unsafe { busbar_contract::abi::sdk::services::Wake::from_raw(&host.tables) },
            ..McpDoor::default()
        };
        let mut link = link();
        if !address_missing {
            link.address = Some(ENDPOINT.into());
        }
        plane.legacy.insert(BINDING.into(), link);
        Self {
            plane,
            posts: RefCell::new(Vec::new()),
            _host: std::marker::PhantomData,
        }
    }
    fn poll(&self, ticket: Ticket, resuming: bool) -> Outcome {
        if !resuming {
            self.posts
                .borrow_mut()
                .retain(|(owner, _)| *owner != ticket);
        }
        let request = crate::client::jsonrpc::envelope(
            "https://up.example/events",
            "tools/call",
            None,
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#.to_vec(),
            None,
        );
        let result = CALLS.with(|calls| {
            let mut calls = calls.borrow_mut();
            let at = calls
                .iter()
                .position(|(owner, _)| *owner == ticket)
                .unwrap_or_else(|| {
                    calls.push((ticket, None));
                    calls.len() - 1
                });
            call_using(
                ticket,
                &self.plane,
                (BINDING, MEMBER),
                &request,
                &mut calls[at].1,
                (0, TIMEOUT_MS),
                |(base, member), request, timeout| {
                    let mut posts = self.posts.borrow_mut();
                    let mut state = posts
                        .iter()
                        .position(|(owner, _)| *owner == ticket)
                        .map(|at| posts.remove(at).1);
                    let polled = super::super::exchange_with_state(
                        self.plane.host.as_ref(),
                        ticket,
                        base,
                        &request.url,
                        member,
                        &mut state,
                        || super::super::door_sessions::exchange_request(request, timeout),
                    );
                    if let Some(state) = state {
                        posts.push((ticket, state));
                    }
                    post_result(polled, member)
                },
            )
        });
        match result {
            Poll::Pending => Outcome::Pending,
            Poll::Ready(answer) => {
                self.posts
                    .borrow_mut()
                    .retain(|(owner, _)| *owner != ticket);
                CALLS.with(|calls| {
                    assert!(
                        calls
                            .borrow()
                            .iter()
                            .find(|(owner, _)| *owner == ticket)
                            .unwrap()
                            .1
                            .is_none(),
                        "a finished call releases its continuation"
                    )
                });
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
    }
    fn inspect(&self, action: Action) {
        let woken=self.plane.legacy.with(&BINDING.into(),|link| {
            let link=link.unwrap();let event=match action {
                Action::Endpoint=>"event: endpoint\ndata: /messages\n\n".to_string(),
                Action::InitializeAnswer=>format!("data: {}\n\n",serde_json::json!({"jsonrpc":"2.0","id":INITIALIZE_ID,"result":{"protocolVersion":Revision::R2024_11_05.wire()}})),
                Action::CallAnswer=>format!("data: {}\n\n",serde_json::json!({"jsonrpc":"2.0","id":CALL_ID,"result":{"ok":true}})),
                Action::Snapshot=>String::new(),
            };
            let woken=feed(link,&event);STATE.with(|state|state.borrow_mut().snapshot=Some(Snapshot {init:link.init,init_by:link.init_by,parked:link.parked.clone(),waiters:link.waiters.len(),answers:link.answers.len(),continuations:self.posts.borrow().len(),dead:link.dead.is_some()}));woken
        });
        wake_all(&self.plane, woken);
    }
    fn cancel(&self) {
        cancelled(&self.plane, OWNER);
        CALLS.with(|calls| calls.borrow_mut().retain(|(ticket, _)| *ticket != OWNER));
        self.posts
            .borrow_mut()
            .retain(|(ticket, _)| *ticket != OWNER);
    }
}
impl Drop for InitializationCase<'_> {
    fn drop(&mut self) {
        self.posts.get_mut().clear();
        CALLS.with(|calls| calls.borrow_mut().clear());
    }
}
fn link() -> Link {
    let template = crate::client::jsonrpc::envelope(
        "https://up.example/events",
        "tools/call",
        None,
        crate::codec::json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"})),
        None,
    );
    Link::new(1, "https://up.example/events", "fs", &template)
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

/// Feeds `raw` (whole events) and answers the calls it woke.
fn feed(l: &mut Link, raw: &str) -> Vec<Ticket> {
    let (mut woken, mut announced) = (Vec::new(), Announced::new());
    l.events(
        raw.as_bytes(),
        ServerRequestGrants::default(),
        &mut woken,
        &mut announced,
    );
    woken
}

fn pending_owner(fixture: &InitializationCase) {
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

fn complete(fixture: &InitializationCase) {
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
    let host = legacy_host();
    let fixture = InitializationCase::new(&host, INITIALIZE_STREAM, false);
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
    let host = legacy_host();
    let fixture = InitializationCase::new(&host, NOTIFICATION_STREAM, false);
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
    let host = legacy_host();
    let fixture = InitializationCase::new(&host, INITIALIZE_STREAM, false);
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
    let host = legacy_host();
    let fixture = InitializationCase::new(&host, NOTIFICATION_STREAM, false);
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
    let host = legacy_host();
    let fixture = InitializationCase::new(&host, INITIALIZE_STREAM, false);
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
    let host = legacy_host();
    let fixture = InitializationCase::new(&host, NOTIFICATION_STREAM, false);
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
    let host = legacy_host();
    let fixture = InitializationCase::new(&host, INITIALIZE_STREAM, true);
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
fn closing_a_fixture_with_a_pending_dial_sends_no_initialize() {
    let host = legacy_host();
    let fixture = InitializationCase::new(&host, INITIALIZE_STREAM, false);
    pending_owner(&fixture);
    assert!(CALLS.with(|calls| !calls.borrow().is_empty()));
    drop(fixture);
    assert!(CALLS.with(|calls| calls.borrow().is_empty()));
    STATE.with(|state| {
        let state = state.borrow();
        assert!(state.bodies.is_empty());
        assert!(
            state.closed.is_empty(),
            "the pending dial produced no stream"
        );
    });
}
