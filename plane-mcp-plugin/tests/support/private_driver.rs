use super::*;
use busbar_contract::abi::host::conn::connector::{EstablishIn, ReplyIn, RequestIn, StreamIn};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::CompletionHandle;
use busbar_contract::abi::sdk::completion_retirement::{self, Capability};
use std::cell::RefCell;

#[derive(Default)]
struct State {
    heads: VecDeque<u32>,
    reads: Vec<(u64, CompletionHandle, usize, usize)>,
    closed: Vec<u64>,
    writes: Vec<CompletionHandle>,
    dials: Vec<CompletionHandle>,
    dial_ready: bool,
}

fn driver() -> Driver {
    let capability = Capability {
        owner: HostCtx { handle: 71 },
        ticket: ticket(1),
        epoch: 1,
        nonce: 1,
        acknowledged: [0; 32],
    };
    let mut driver = Driver::default();
    driver
        .begin(
            capability.owner,
            capability.ticket,
            &completion_retirement::append_capability(&[], capability).unwrap(),
        )
        .unwrap();
    driver
}

thread_local! {static STATE: RefCell<State> = RefCell::new(State::default());}

use busbar_contract::abi::host::conn::connector::{ConnectorSlots, SERVICES as CONNECTOR_SERVICES};
use busbar_contract::abi::host::service::ServiceOut;
use busbar_contract::abi::mechanism::call::RawOutcome;
use busbar_contract::abi::mechanism::ticket::HostTables;
use std::ffi::c_void;
fn finish(out: *mut ServiceOut, outcome: Outcome, value: u64, len: u64) -> RawOutcome {
    let raw = RawOutcome::of(outcome);
    // SAFETY: the actual SDK lends this complete exclusive service result for this call.
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
extern "C" fn read_reply(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the actual production Driver invokes READ_REPLY with its declared frame and live buffers.
    let input = unsafe { input.cast::<ReplyIn>().read_unaligned() };
    let outcome = STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.reads.push((
            input.stream,
            input.head.handle,
            input.buf as usize,
            input.piece as usize,
        ));
        if state.closed.contains(&input.stream) {
            return Outcome::Failed;
        }
        match state.heads.pop_front() {
            Some(code) => {
                unsafe {
                    input.piece.write(ReplyPiece {
                        kind: REPLY_HEAD,
                        code,
                        ..ReplyPiece::default()
                    });
                }
                Outcome::Ready
            }
            None => Outcome::Pending,
        }
    });
    finish(out, outcome, 0, 0)
}
extern "C" fn establish(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<EstablishIn>().read_unaligned() };
    let ready = STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.dials.push(input.head.handle);
        state.dial_ready
    });
    finish(
        out,
        if ready {
            Outcome::Ready
        } else {
            Outcome::Pending
        },
        if ready { 77 } else { 0 },
        0,
    )
}
extern "C" fn write_request(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<RequestIn>().read_unaligned() };
    STATE.with(|state| state.borrow_mut().writes.push(input.head.handle));
    finish(out, Outcome::Ready, 0, input.len as u64)
}
extern "C" fn close_stream(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let input = unsafe { input.cast::<StreamIn>().read_unaligned() };
    STATE.with(|state| state.borrow_mut().closed.push(input.stream));
    finish(out, Outcome::Ready, 0, 0)
}
fn with_host(run: impl FnOnce(&Host, &RefCell<State>)) {
    // Only the four connector values this actual Driver scenario consumes are served.
    let mut conns: ConnectorSlots = unsafe { std::mem::zeroed() };
    conns.size = std::mem::size_of::<ConnectorSlots>() as u32;
    conns.slots = CONNECTOR_SERVICES;
    conns.establish = Some(establish);
    conns.read_reply = Some(read_reply);
    conns.write_request = Some(write_request);
    conns.close = Some(close_stream);
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx { handle: 71 },
        wake: None,
        conns: &conns,
        services: std::ptr::null(),
        io: std::ptr::null(),
    };
    // SAFETY: complete immutable local tables remain live through run; all callbacks obey their exact slot layouts.
    let host = unsafe { Host::from_raw(&tables) };
    STATE.with(|state| {
        *state.borrow_mut() = State::default();
        run(&host, state);
    });
}
fn link() -> Link {
    let template = crate::client::jsonrpc::envelope(
        "https://up.example/events",
        "tools/call",
        None,
        crate::codec::json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call"})),
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
#[test]
fn a_terminal_reply_handle_is_reused_only_after_exact_host_retirement_confirmation() {
    with_host(|host, state| {
        let mut issued = driver();
        let mut l = link();
        posted(&mut l, 20);
        state.borrow_mut().heads.push_back(202);
        l.post_replies(host, ticket(1), &mut issued, &mut Vec::new());
        let completed = state.borrow().reads[0].1.seq;
        let ack = issued.retirement.acknowledgement(0).unwrap().unwrap();
        issued.issued = CYCLE_SPAN;
        let mut pending = None;
        assert!(
            Link::next(host, ticket(1), &mut issued, &mut pending).is_none(),
            "a terminal but unconfirmed handle cannot be recycled"
        );
        let mut receipt = ack.capability;
        receipt.nonce += 1;
        receipt.acknowledged = completion_retirement::ack_digest(&ack).unwrap();
        issued
            .begin(
                receipt.owner,
                receipt.ticket,
                &completion_retirement::append_capability(&[], receipt).unwrap(),
            )
            .unwrap();
        let mut connector = Link::next(host, ticket(1), &mut issued, &mut pending)
            .expect("confirmed retirement recycles the existing namespace without a lifetime cap");
        let mut buf = [0u8; 1];
        let mut piece = ReplyPiece::default();
        assert!(connector.read_reply(30, &mut buf, &mut piece).is_pending());
        let reused = state.borrow().reads.last().unwrap().1.seq;
        assert!(ack.handles.iter().any(|handle| handle.seq == reused));
        assert!(issued.issued == CYCLE_SPAN && completed >= LINK_SEQ);
        assert!(host.connector(Ticket::NONE).close(30).is_ready());
        assert!(host
            .connector_from(ticket(1), reused)
            .read_reply(30, &mut buf, &mut piece)
            .is_ready());
        issued.consumed(&mut pending);
    });
}

#[test]
fn a_dead_link_redeems_and_closes_a_pending_get_establish() {
    with_host(|host, state| {
        let mut l = link();
        let mut issued = driver();
        let (mut woken, mut announced) = (Vec::new(), Announced::new());
        l.read_stream(
            (host, ticket(1)),
            &mut issued,
            ServerRequestGrants::default(),
            &mut woken,
            &mut announced,
        );
        l.die("cancelled", &mut woken);
        l.read_stream(
            (host, ticket(1)),
            &mut issued,
            ServerRequestGrants::default(),
            &mut woken,
            &mut announced,
        );
        assert!(
            state.borrow().closed.is_empty(),
            "the establish has not produced a stream yet"
        );
        state.borrow_mut().dial_ready = true;
        l.read_stream(
            (host, ticket(1)),
            &mut issued,
            ServerRequestGrants::default(),
            &mut woken,
            &mut announced,
        );
        let state = state.borrow();
        assert_eq!(
            state.dials.len(),
            3,
            "a dead link still redeems its pending establish"
        );
        assert!(state.dials.iter().all(|handle| *handle == state.dials[0]));
        assert_eq!(
            state.closed,
            [77],
            "the returned stream is closed without sending a GET"
        );
        assert!(state.writes.is_empty());
    });
}

#[test]
fn a_dead_link_keeps_a_pending_reply_establish_until_its_stream_is_closed() {
    with_host(|host, state| {
        let mut l = link();
        l.address = Some("https://up.example/messages".into());
        l.outbox.push_back(b"{}".to_vec());
        let mut issued = driver();
        l.post_replies(host, ticket(1), &mut issued, &mut Vec::new());
        l.die("cancelled", &mut Vec::new());
        l.post_replies(host, ticket(1), &mut issued, &mut Vec::new());
        assert!(
            l.replying.is_some(),
            "the pending reply still owns its operation state"
        );
        state.borrow_mut().dial_ready = true;
        l.post_replies(host, ticket(1), &mut issued, &mut Vec::new());
        let state = state.borrow();
        assert_eq!(state.dials.len(), 3);
        assert!(state.dials.iter().all(|handle| *handle == state.dials[0]));
        assert_eq!(state.closed, [77]);
        assert!(
            state.writes.is_empty(),
            "a dead link sends no new reply bytes"
        );
        assert!(l.replying.is_none());
    });
}

#[test]
fn closing_a_dead_link_redeems_each_pending_read_before_releasing_its_buffers() {
    with_host(|host, state| {
        let mut l = link();
        l.step = Step::Read;
        l.stream = Some(10);
        posted(&mut l, 20);
        let mut issued = driver();
        let (mut woken, mut announced) = (Vec::new(), Announced::new());
        l.drive(
            (host, ticket(1), 1),
            &mut issued,
            ServerRequestGrants::default(),
            &mut woken,
            &mut announced,
        );
        let before: BTreeMap<_, _> = state
            .borrow()
            .reads
            .iter()
            .map(|&(stream, handle, buf, slot)| (stream, (handle, buf, slot)))
            .collect();
        state.borrow_mut().reads.clear();
        l.die("cancelled", &mut woken);
        l.drive(
            (host, ticket(1), 2),
            &mut issued,
            ServerRequestGrants::default(),
            &mut woken,
            &mut announced,
        );
        let state = state.borrow();
        let after: BTreeMap<_, _> = state
            .reads
            .iter()
            .map(|&(stream, handle, buf, slot)| (stream, (handle, buf, slot)))
            .collect();
        assert_eq!(before, after, "close is followed by terminal redemption of each original service with its buffers still live");
        assert!(state.closed.contains(&10) && state.closed.contains(&20));
        assert!(l.replying.is_none() && l.stream.is_none());
    });
}

fn posted(l: &mut Link, stream: u64) {
    l.address = Some("https://up.example/messages".into());
    let mut reply = l.reply_to("https://up.example/messages", b"{}".to_vec());
    reply.step = ReplyStep::Read;
    reply.stream = Some(stream);
    l.replying = Some(reply);
}

#[test]
fn a_reply_post_closes_on_its_final_head_without_reading_an_endless_body() {
    for final_code in [200, 202, 401, 503, 101] {
        with_host(|host, state| {
            state.borrow_mut().heads = [100, 103, final_code].into();
            let mut l = link();
            posted(&mut l, 20);
            let mut issued = driver();
            l.post_replies(host, ticket(1), &mut issued, &mut Vec::new());
            let state = state.borrow();
            assert_eq!(
                state.reads.len(),
                3,
                "interim heads are followed; the unused body is not read"
            );
            assert_eq!(
                state.closed,
                [20],
                "final HTTP {final_code} closes the connector"
            );
            assert!(l.replying.is_none(), "the next owed reply can progress");
            assert!(state.heads.is_empty());
        });
    }
}

#[test]
fn held_links_and_reply_posts_keep_distinct_pending_handles_and_read_buffers() {
    with_host(|host, state| {
        let (mut a, mut b) = (link(), link());
        for (l, stream) in [(&mut a, 10), (&mut b, 11)] {
            l.step = Step::Read;
            l.stream = Some(stream);
            posted(l, stream + 10);
        }
        let mut issued = driver();
        let (mut woken, mut announced) = (Vec::new(), Announced::new());
        for l in [&mut a, &mut b] {
            l.drive(
                (host, ticket(1), 1),
                &mut issued,
                ServerRequestGrants::default(),
                &mut woken,
                &mut announced,
            );
        }
        let first: BTreeMap<_, _> = state
            .borrow()
            .reads
            .iter()
            .map(|&(stream, handle, buf, slot)| (stream, (handle, buf, slot)))
            .collect();
        assert_eq!(first.len(), 4);
        for (stream, &(handle, buf, slot)) in &first {
            for (other, &(other_handle, other_buf, other_slot)) in &first {
                if stream != other {
                    assert_ne!(
                        handle, other_handle,
                        "each concurrent service owns its handle"
                    );
                    assert_ne!(buf, other_buf, "pending reads own disjoint byte buffers");
                    assert_ne!(slot, other_slot, "pending reads own disjoint descriptors");
                }
            }
        }
        state.borrow_mut().reads.clear();
        for l in [&mut b, &mut a] {
            l.drive(
                (host, ticket(1), 2),
                &mut issued,
                ServerRequestGrants::default(),
                &mut woken,
                &mut announced,
            );
        }
        for &(stream, handle, buf, slot) in &state.borrow().reads {
            assert_eq!(
                first[&stream],
                (handle, buf, slot),
                "a later tick and link order preserve the pending service"
            );
        }
    });
}
