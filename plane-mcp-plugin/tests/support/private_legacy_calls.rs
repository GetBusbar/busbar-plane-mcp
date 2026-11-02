// SPDX-License-Identifier: Apache-2.0
// Actual private legacy-call error, credential and endpoint state assertions.
use super::*;
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

fn poll_call(
    plane: &McpDoor,
    binding: (&str, &str),
    original: &OutboundRequest,
    state: &mut Option<Calling>,
    timing: (u32, u64),
) -> Poll<Called> {
    let mut exchange = None;
    call_using(
        ticket(9),
        plane,
        binding,
        original,
        state,
        timing,
        |(base, member), request, timeout| {
            post_result(
                super::super::exchange_with_state(
                    plane.host.as_ref(),
                    ticket(9),
                    base,
                    &request.url,
                    member,
                    &mut exchange,
                    || super::super::door_sessions::exchange_request(request, timeout),
                ),
                member,
            )
        },
    )
}

fn run(generation: u64) {
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
    if generation == 1 {
        l.init = Init::Done;
        l.fields
            .push(("authorization".into(), "Bearer old-token".into()));
        plane.legacy.insert("binding".into(), l);
        assert!(
            matches!(
                poll_call(
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
    } else if generation == 3 {
        l.url = "https://old.example/events".into();
        l.init = Init::Done;
        l.waiters.insert("8".into(), ticket(8));
        l.answers
            .insert("9".into(), (ticket(9), b"old answer".to_vec()));
        plane.legacy.insert("binding".into(), l);
        calling = None;
        assert!(poll_call(
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
        assert!(poll_call(
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
        l.init_by = Some(ticket(9));
        l.waiters.insert(INITIALIZE_ID.to_string(), ticket(9));
        l.answers.insert(INITIALIZE_ID.to_string(),(ticket(9),crate::codec::json(&serde_json::json!({"jsonrpc":"2.0","id":INITIALIZE_ID,"error":{"code":-32001,"message":"unauthorized"}}))));
        plane.legacy.insert("binding".into(), l);
        calling.as_mut().unwrap().init = CallInit::Answer;
        let Poll::Ready(Err(why)) = poll_call(
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
