// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::tool_program::Correlator;

pub(super) fn opened() -> [(Ticket, u64); 2] {
    [1, 2].map(|slot| {
        let ticket = Ticket {
            slot,
            generation: 7,
        };
        let Poll::Ready(Ok(stream)) = ChildConn.establish(ticket, 0, 0, "srv", 0) else {
            panic!("the child opens")
        };
        let mut buf = vec![0; 4096];
        let mut piece = ReplyPiece::default();
        assert!(matches!(
            ChildConn.read_reply(ticket, 1, stream, &mut buf, &mut piece),
            Poll::Ready(Ok(_))
        ));
        (ticket, stream)
    })
}

pub(super) fn received((ticket, stream): (Ticket, u64)) -> Vec<u8> {
    let mut buf = vec![0; 4096];
    let mut piece = ReplyPiece::default();
    let Poll::Ready(Ok(got)) = ChildConn.read_reply(ticket, 3, stream, &mut buf, &mut piece) else {
        panic!("the lease sees the child's answer")
    };
    buf.truncate(got.len);
    buf
}

pub(super) fn send((ticket, stream): (Ticket, u64), request: &[u8]) {
    assert!(matches!(
        ChildConn.write(ticket, 2, stream, request),
        Poll::Ready(Ok(_))
    ));
}

pub(super) fn close(leases: [(Ticket, u64); 2]) {
    for (ticket, stream) in leases {
        assert!(ChildConn.close(ticket, 4, stream).is_ready());
    }
    assert!(with(|c| c.leases.is_empty()));
}

#[test]
fn a_slot_zero_operator_and_a_unit_on_the_shared_child_have_distinct_typed_ids() {
    let _one = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset(1, Vec::new());
    // The existing numeric wire id for unit 7's first list. This fixture protects that wire
    // compatibility while the operator with slot 0/generation 7 shares the child with it.
    const UNIT_ID: u64 = 1_649_267_442_560;
    let leases = opened();
    let mut unit = Correlator::default();
    let mut operator = Correlator::default();
    let mut peer = Door::default();
    send(
        leases[0],
        &crate::client::jsonrpc::tools_list("", UNIT_ID, None).body,
    );
    assert!(
        operator
            .take(&received(leases[1]), list_id(7, 0), "srv", 1, &mut peer)
            .unwrap()
            .is_none(),
        "the slot-zero operator must ignore the unit's numeric reply"
    );
    assert!(unit
        .take(&received(leases[0]), UNIT_ID, "srv", 1, &mut peer)
        .unwrap()
        .is_some());
    let mut request: Value =
        serde_json::from_slice(&crate::client::jsonrpc::tools_list("", 0, None).body).unwrap();
    request["id"] = json!(list_id(7, 0));
    send(leases[1], &serde_json::to_vec(&request).unwrap());
    assert!(
        unit.take(&received(leases[0]), UNIT_ID, "srv", 1, &mut peer)
            .unwrap()
            .is_none(),
        "the unit must ignore the operator's typed reply"
    );
    assert!(operator
        .take(&received(leases[1]), list_id(7, 0), "srv", 1, &mut peer)
        .unwrap()
        .is_some());
    let lookalike =
        serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":UNIT_ID.to_string(), "result":{}}))
            .unwrap();
    assert!(
        unit.take(&lookalike, UNIT_ID, "srv", 1, &mut peer)
            .unwrap()
            .is_none(),
        "a numeric-looking string is not the unit's numeric id"
    );
    let requests = with(|c| c.received.clone());
    assert_ne!(requests[0]["id"], requests[1]["id"]);
    close(leases);
}

#[test]
fn an_operator_fetch_index_is_not_truncated_on_the_shared_child() {
    let _one = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset(1, Vec::new());
    let leases = opened();
    let request = |fetch| {
        let mut request: Value =
            serde_json::from_slice(&crate::client::jsonrpc::tools_list("", 0, None).body).unwrap();
        request["id"] = json!(list_id(7, fetch));
        serde_json::to_vec(&request).unwrap()
    };
    let mut later = Correlator::default();
    let mut peer = Door::default();
    send(leases[0], &request(0));
    assert!(
        later
            .take(&received(leases[1]), list_id(7, 128), "srv", 1, &mut peer)
            .unwrap()
            .is_none(),
        "fetch 128 must not accept fetch zero's answer"
    );
    send(leases[1], &request(128));
    assert!(later
        .take(&received(leases[1]), list_id(7, 128), "srv", 1, &mut peer)
        .unwrap()
        .is_some());
    let requests = with(|c| c.received.clone());
    assert_ne!(requests[0]["id"], requests[1]["id"]);
    close(leases);
}
