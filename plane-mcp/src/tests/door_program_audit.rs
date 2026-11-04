// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Audit regressions for the stdio servers' leg in the door.

use super::*;

fn key(member: &str, id: u64) -> AnsweredKey {
    (member.to_string(), 1, id.to_string())
}

/// ONE CHILD FLOODING THE MEMO FORGETS ITS OWN DECISIONS, never another member's: a member whose
/// child writes more requests than the memo holds evicts its own oldest, so the live decision of a
/// quieter member is still the one made when its next exchange reads the same request.
#[test]
fn a_flooding_child_never_evicts_another_members_decision() {
    let mut memo = Answered::with_cap(8);
    assert_eq!(
        memo.decide(key("quiet", 1), || Some(serde_json::json!("call-1"))),
        (Some(serde_json::json!("call-1")), true)
    );
    for id in 0..64 {
        memo.decide(key("flood", id), || None);
    }
    assert_eq!(
        memo.decide(key("quiet", 1), || Some(serde_json::json!("again"))),
        (Some(serde_json::json!("call-1")), false),
        "the quiet member's decision survives the flood"
    );
    assert_eq!(
        memo.decide(key("flood", 0), || Some(serde_json::json!("redo"))),
        (Some(serde_json::json!("redo")), true),
        "the flooding member's own oldest decision was the one forgotten"
    );
}

/// A FAILED REPLY WRITE NEVER UNDOES AN ANSWER ALREADY READ: the child wrote the call's result in
/// the same piece as a request of its own (refused, so a reply is owed), and the reply could not be
/// written (here no host is armed). The call settles with its answer, not with the write failure.
#[test]
fn a_failed_reply_write_keeps_the_answer_already_read() {
    let plane = McpDoor::default();
    let mut relay = ProgramRelay::waiting(&plane, "srv", 7);
    let def: crate::tools_config::McpServerDefCfg = serde_json::from_value(serde_json::json!({
        "transport":"stdio", "command":"/usr/bin/child", "pin":{"mechanism":"unpinned"}
    }))
    .unwrap();
    let bytes = b"{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"x/unknown\"}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[]}}\n";
    let settled = far(
        &plane,
        Ticket {
            slot: 4,
            generation: 1,
        },
        "srv",
        &def,
        &mut relay,
        Some(1),
        bytes,
        true,
    );
    match settled {
        Far::Settled(Ok(answer)) => {
            let answer: serde_json::Value = serde_json::from_slice(&answer).unwrap();
            assert_eq!(answer["id"], 7);
            assert_eq!(answer["result"], serde_json::json!({ "content": [] }));
        }
        Far::Settled(Err(why)) => panic!("the answer read was replaced by `{why}`"),
        _ => panic!("the call settles with the answer it read"),
    }
}
