use super::*;
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureSlot};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

struct Capture;
impl CaptureHome for Capture {
    fn retention() -> &'static busbar_contract::abi::sdk::capture::CaptureRetention {
        static RETENTION: std::sync::OnceLock<
            busbar_contract::abi::sdk::capture::CaptureRetention,
        > = std::sync::OnceLock::new();
        RETENTION.get_or_init(Default::default)
    }
    fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R {
        thread_local! {static SLOT:std::cell::RefCell<CaptureSlot>=std::cell::RefCell::new(CaptureSlot::default());}
        SLOT.with(|slot| f(&mut slot.borrow_mut()))
    }
}

struct Probe;
impl SafeSlot for Probe {
    type State = McpDoor;
    type In = OpenIn;
    type Out = OpenOut;
    fn call(
        instance: Instance<'_, McpDoor>,
        input: Lent<'_, OpenIn>,
        _: Out<'_, OpenOut>,
    ) -> Outcome {
        let plane = McpDoor::default();
        let mut l = link();
        l.address = Some("https://up.example/messages".into());
        let original = crate::client::jsonrpc::envelope(
            "https://up.example/events",
            "tools/call",
            None,
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#.to_vec(),
            Some("new-token"),
        );
        let mut calling = Some(Calling {
            generation: 1,
            ..Calling::default()
        });
        if input.generation == 1 {
            l.init = Init::Done;
            l.fields
                .push(("authorization".into(), "Bearer old-token".into()));
            plane.legacy.insert("binding".into(), l);
            assert!(
                matches!(
                    super::super::call(
                        &instance,
                        &plane,
                        ("binding", "fs"),
                        &original,
                        &mut calling,
                        (0, 1000)
                    ),
                    Poll::Ready(Err(_))
                ),
                "the unarmed host refuses the actual POST"
            );
            plane.legacy.with(&"binding".into(), |l| {
                let reply = l
                    .unwrap()
                    .reply_to("https://up.example/messages", b"{}".to_vec());
                let block = spanned(&reply.head, reply.head_piece.fields);
                let auth = fields::lines(block)
                    .find(|(name, _)| name.eq_ignore_ascii_case(b"authorization"))
                    .map(|(_, value)| value);
                assert_eq!(
                    auth,
                    Some(b"Bearer new-token".as_slice()),
                    "server replies use the latest admitted call's credential"
                );
            });
        } else if input.generation == 3 {
            l.url = "https://old.example/events".into();
            l.init = Init::Done;
            l.waiters.insert("8".into(), ticket(8));
            l.answers
                .insert("9".into(), (ticket(9), b"old answer".to_vec()));
            plane.legacy.insert("binding".into(), l);
            calling = None;
            assert!(super::super::call(
                &instance,
                &plane,
                ("binding", "fs"),
                &original,
                &mut calling,
                (0, 1000)
            )
            .is_pending());
            plane.legacy.with(&"binding".into(), |link| {
                let link = link.unwrap();
                assert!(
                    link.dead.is_some(),
                    "the retired endpoint receives no new POST"
                );
                assert!(
                    link.waiters.is_empty(),
                    "old callers are woken to the endpoint-change failure"
                );
                assert_eq!(
                    link.answers["9"].1.as_slice(),
                    b"old answer",
                    "already read answers are retained"
                );
                link.answers.clear();
            });
            assert!(super::super::call(
                &instance,
                &plane,
                ("binding", "fs"),
                &original,
                &mut calling,
                (0, 1000)
            )
            .is_pending());
            plane.legacy.with(&"binding".into(), |link| {
                let link = link.unwrap();
                assert_eq!(link.url, original.url);
                assert!(link.dead.is_none());
            });
        } else {
            l.init = Init::Running;
            l.init_by = Some(instance.ticket());
            l.waiters
                .insert(INITIALIZE_ID.to_string(), instance.ticket());
            l.answers.insert(INITIALIZE_ID.to_string(),(instance.ticket(),crate::codec::json(&serde_json::json!({"jsonrpc":"2.0","id":INITIALIZE_ID,"error":{"code":-32001,"message":"unauthorized"}}))));
            plane.legacy.insert("binding".into(), l);
            calling.as_mut().unwrap().init = CallInit::Answer;
            let Poll::Ready(Err(why)) = super::super::call(
                &instance,
                &plane,
                ("binding", "fs"),
                &original,
                &mut calling,
                (0, 1000),
            ) else {
                panic!("the server refused initialization")
            };
            assert!(
                why.contains("unauthorized") && why.contains("-32001"),
                "{why}"
            );
        }
        instance.open(McpDoor::default());
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

fn run(generation: u64) {
    use busbar_contract::abi::sdk::door::{blank_in, blank_out, kind_op, Lifecycle};
    let open = kind_op::<Lifecycle, Safe<Probe>, Capture, { slot::OPEN }>().unwrap();
    let mut input = blank_in::<OpenIn>();
    input.head.op = slot::OPEN;
    input.head.ticket = Ticket {
        slot: 9,
        generation: 1,
    };
    input.generation = generation;
    let result = busbar_contract::abi::sdk::test_support::reply::call(
        open,
        std::ptr::null_mut(),
        &input,
        blank_out::<OpenOut>(),
    );
    assert_eq!(result.outcome, Outcome::Ready, "{result:?}");
    let close = kind_op::<Lifecycle, Safe<Close>, Capture, { slot::CLOSE }>().unwrap();
    let mut input = blank_in::<InHead>();
    input.op = slot::CLOSE;
    let closed = busbar_contract::abi::sdk::test_support::reply::call(
        close,
        result.out.instance,
        &input,
        blank_out::<OutHead>(),
    );
    assert_eq!(closed.outcome, Outcome::Ready);
}

#[test]
fn a_reply_post_refreshes_credential_fields_from_the_current_call() {
    run(1);
}

#[test]
fn a_refused_initialize_preserves_the_remote_rpc_error() {
    run(2);
}

#[test]
fn an_endpoint_reload_retires_a_live_legacy_link_without_losing_read_answers() {
    run(3);
}
