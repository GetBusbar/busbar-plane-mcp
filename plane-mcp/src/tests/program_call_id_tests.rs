// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::namespace::{opened, received, send};
use super::*;
use crate::tool_program::{call_id, Correlator};

fn admitted() -> (
    crate::call::AdmittedCall,
    crate::tools_config::McpServerDefCfg,
) {
    let section = crate::statement::test_support::read_tools_section(br#"{"srv":{"transport":"stdio","command":"/fixture/child","pin":{"mechanism":"unpinned"},"tools_allow":{"echo":{"schema_hash":"sha256:a"}}}}"#).unwrap();
    let catalogue = crate::catalogue::Catalogue::build(1, &section);
    let admitted = crate::call::AdmittedCall {
        entry: catalogue.tool_on("srv", "echo").unwrap().clone(),
        arguments: json!({"message":"echo"}),
        id: json!("caller"),
        progress_token: Some(json!("caller-progress")),
        capabilities: json!({"sampling":{}}),
        sent_digest: String::new(),
        relay: None,
    };
    (admitted, section.servers["srv"].clone())
}

fn request(unit: u64, round: u32) -> Vec<u8> {
    let (admitted, def) = admitted();
    crate::call::outbound_program(&admitted, "srv", &def, None, call_id(unit, round))
        .unwrap()
        .body
}

fn distinguish_calls(first: (u64, u32), second: (u64, u32)) {
    let _one = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset(1, Vec::new());
    let leases = opened();
    let low = request(first.0, first.1);
    let high = request(second.0, second.1);
    let low_json: Value = serde_json::from_slice(&low).unwrap();
    let high_json: Value = serde_json::from_slice(&high).unwrap();
    let mut original = Correlator::default();
    let mut other = Correlator::default();
    let mut peer = Door::default();
    send(leases[0], &low);
    assert!(
        other
            .take(
                &received(leases[1]),
                json!(call_id(second.0, second.1)),
                "srv",
                1,
                &mut peer
            )
            .unwrap()
            .is_none(),
        "another full unit/round must never consume this call's child response"
    );
    assert!(original
        .take(
            &received(leases[0]),
            json!(call_id(first.0, first.1)),
            "srv",
            1,
            &mut peer
        )
        .unwrap()
        .is_some());
    assert_ne!(low_json["id"], high_json["id"]);
    assert_ne!(
        low_json.pointer("/params/_meta/progressToken"),
        high_json.pointer("/params/_meta/progressToken")
    );

    assert!(ChildConn.close(leases[0].0, 4, leases[0].1).is_ready());
    assert!(with(|child| child.leases.contains_key(&leases[1].1)));
    with(|child| {
        child.chatter = vec![
            json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":low_json.pointer("/params/_meta/progressToken").unwrap(),"progress":1}}),
            json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":high_json.pointer("/params/_meta/progressToken").unwrap(),"progress":2}}),
        ]
    });
    send(leases[1], &high);
    for _ in 0..2 {
        assert!(other
            .take(
                &received(leases[1]),
                json!(call_id(second.0, second.1)),
                "srv",
                1,
                &mut peer
            )
            .unwrap()
            .is_none());
    }
    assert_eq!(
        other.progress.len(),
        1,
        "only this call's progress survives the other cancellation"
    );
    assert_eq!(other.progress[0]["params"]["progress"], 2);
    let reply = other
        .take(
            &received(leases[1]),
            json!(call_id(second.0, second.1)),
            "srv",
            1,
            &mut peer,
        )
        .unwrap()
        .unwrap();
    let (admitted, def) = admitted();
    let settled = crate::call::settle_call_as(
        &admitted,
        Some(&def),
        200,
        &reply,
        false,
        second.1,
        call_id(second.0, second.1),
    );
    let crate::call::Settled::Answer { status, body, line } = settled else {
        panic!("the surviving child call completes");
    };
    assert_eq!(status, 200);
    assert_eq!(line.outcome, "dispatched");
    assert!(line.reason.is_empty());
    assert_eq!(line.server, "srv");
    let answered: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        answered["result"],
        json!({"resultType":crate::codec::RESULT_TYPE_COMPLETE})
    );
    assert!(ChildConn.close(leases[1].0, 5, leases[1].1).is_ready());
    assert!(with(|child| child.leases.is_empty()));
}

#[test]
fn complete_unit_ids_keep_responses_progress_and_cancelled_leases_separate_on_one_child() {
    distinguish_calls((7, 0), ((1_u64 << 32) | 7, 0));
}

#[test]
fn complete_rounds_keep_responses_and_progress_separate_on_one_child() {
    distinguish_calls((7, 0), (7, 128));
}

#[test]
fn call_requests_keep_legacy_ids_and_encode_large_tuples_without_numeric_precision_loss() {
    let legacy: Value = serde_json::from_slice(&request(7, 0)).unwrap();
    assert_eq!(legacy["id"], json!(1_099_511_628_672_u64));
    assert_eq!(
        legacy.pointer("/params/_meta/progressToken"),
        Some(&json!("busbar-1099511628672"))
    );
    let large: Value = serde_json::from_slice(&request(u64::MAX, u32::MAX)).unwrap();
    assert_eq!(
        large["id"],
        json!("busbar-call:unit:18446744073709551615:4294967295")
    );
    assert_eq!(
        large.pointer("/params/_meta/progressToken"),
        Some(&json!(
            "busbar-busbar-call:unit:18446744073709551615:4294967295"
        ))
    );
    for (unit, round) in [(7, 128), ((1_u64 << 32) | 7, 0), (u64::MAX, u32::MAX)] {
        let call = json!(call_id(unit, round));
        assert_ne!(call, crate::tool_program::unit_list_id(unit, round));
        assert_ne!(call, crate::tool_program::list_id(unit, round));
    }
}

struct CallOwner(u64);

impl Peer for CallOwner {
    fn grants(&self) -> ServerRequestGrants {
        ServerRequestGrants {
            sampling: true,
            ..ServerRequestGrants::default()
        }
    }
    fn claim(&mut self, _: u64, _: &Value) -> bool {
        false
    }
    fn owner(&mut self, _: u64, _: &Value) -> AskOwner {
        AskOwner::Call(call_id(self.0, 0))
    }
    fn notice(&mut self) {}
}

#[test]
fn a_high_units_child_ask_and_serialized_retry_never_belong_to_the_low_unit() {
    let high = (1_u64 << 32) | 7;
    let ask = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":"child-ask","method":"sampling/createMessage","params":{}}),
    )
    .unwrap();
    let mut peer = CallOwner(high);
    let mut low = Correlator::relaying();
    let mut owner = Correlator::relaying();
    assert!(low
        .take(&ask, call_id(7, 0), "srv", 1, &mut peer)
        .unwrap()
        .is_none());
    assert!(
        low.asks.is_empty(),
        "another unit cannot inherit the child's authority ask"
    );
    assert!(owner
        .take(&ask, call_id(high, 0), "srv", 1, &mut peer)
        .unwrap()
        .is_none());
    assert_eq!(owner.asks.len(), 1);
    assert_eq!(
        crate::tool_program::first_in_line([(call_id(high, 0), 1)], 1),
        Some(call_id(high, 0))
    );
    let leg = crate::ask::ChildLeg {
        launch: None,
        generation: 1,
        wait: call_id(high, 0),
        asks: vec![("child-ask".into(), json!("child-ask"))],
        work: None,
    };
    let encoded = serde_json::to_value(&leg).unwrap();
    assert_eq!(encoded["w"], json!("busbar-call:unit:4294967303:0"));
    let decoded: crate::ask::ChildLeg = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, leg);
}
