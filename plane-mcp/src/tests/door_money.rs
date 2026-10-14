// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! $ THE DOOR'S MONEY ANSWERS: what a unit reports beside the answer its caller is written. The
//! plane reports its units and whether a fee unit was incurred; the kernel writes them (THE DESIGN
//! §7, "The plane reports; the kernel writes").

use serde_json::{json, Value};

use super::*;

/// One server with one approved tool.
const SECTION: &str = r#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"},
  "tools_allow": {"read_file": {"schema_hash": "sha256:aa"}}}}"#;

/// `fs_read_file`, admitted.
fn admitted() -> AdmittedCall {
    let section = crate::door::read_tools_section(SECTION.as_bytes()).expect("the section reads");
    let catalogue = Catalogue::build(1, &section);
    let params = json!({ "name": "fs_read_file", "arguments": {}, "_meta": {} });
    match crate::call::admit_call(
        &catalogue,
        &json!(30),
        Some(&params),
        &|_| None,
        &|_, _| true,
        &mut |_, _| AskDecision::Proceed,
    ) {
        Admission::Go(a) => a,
        other => panic!("the call is admitted: {other:?}"),
    }
}

/// $ A CALL THAT NEVER LEFT ITS QUEUE EARNS NO FEE UNIT AND IS NOT LOGGED DISPATCHED
/// (ARCHITECT/coordinator ruling 2026-10-14: #62 "bill what was delivered", BUSBAR-1.6.0.md l.2252;
/// Q35 "a hop refused before the socket is refunded", 1.6.0-QUESTIONS.md, applied uniformly across
/// planes). A call queued behind another call on its stdio member's child, whose deadline passed
/// before its turn came, was never sent. Its caller is still answered the upstream-failure tool
/// error, 200 `isError`, but the plane reports NO fee unit, so the kernel gives back the fee its
/// admission counted. The call log names it `refused` / `queue_deadline`, audited rejected, never
/// `dispatched`, because that word means the call went out.
///
/// RED before the ruling: the door answered this call through `call::upstream_failed`, which logs
/// `dispatched` / `upstream_failed` and audits the call; and through `Pending::answer` alone,
/// which reports the fee unit `(CLASS_FEE_INDEX, 1)` for the 200.
#[test]
fn a_call_that_never_left_its_queue_earns_no_fee_unit_and_is_not_logged_dispatched() {
    let answer = queue_deadline_answer(
        crate::call::never_sent(&admitted(), door_program::BUSY),
        None,
        "k",
        1,
        Some(7),
    )
    .expect("an answer");
    assert_eq!(answer.status, 200, "the 200 isError answer shape stays");
    let body: Value = serde_json::from_slice(&answer.bytes).expect("a JSON-RPC answer");
    assert_eq!(body["id"], json!(30));
    assert_eq!(body["result"]["isError"], json!(true), "{body}");
    assert!(
        answer.units.is_empty(),
        "no fee unit and no class: nothing was sent, nothing was delivered: {:?}",
        answer
            .units
            .iter()
            .map(|u| (u.class, u.amount))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        answer.records,
        vec![(
            door::RECORD_CALL,
            b"k".to_vec(),
            crate::record::call_suffix(
                7,
                "fs",
                "fs_read_file",
                busbar_contract::vocab::OUTCOME_REFUSED,
                crate::call::REASON_QUEUE_DEADLINE,
                "sha256:aa",
                1,
            ),
        )],
        "the call log's one line: refused, queue_deadline, never dispatched"
    );
    assert_eq!(
        answer.audits,
        vec![crate::call::AuditRow::tool("fs_read_file", false)],
        "audited rejected"
    );
}

/// A call that WAS sent and whose upstream then failed keeps its fee unit and its `dispatched`
/// line: the fee follows what went out, not how the far end answered (Q35, "a hop that left is
/// billed whatever the backend then answered").
#[test]
fn a_call_that_went_out_and_failed_keeps_its_fee_unit_and_its_dispatched_line() {
    let crate::call::Settled::Answer { status, body, line } =
        crate::call::upstream_failed(&admitted(), "down")
    else {
        panic!("an answer");
    };
    assert_eq!(
        (line.outcome, line.reason.as_str()),
        (
            busbar_contract::vocab::OUTCOME_DISPATCHED,
            busbar_contract::vocab::REASON_UPSTREAM_FAILED
        )
    );
    let answer = Pending::answer(status, body, None, &[]).logged(Some(&line), "k", 1, Some(7));
    assert_eq!(
        answer
            .units
            .iter()
            .map(|u| (u.class, u.amount))
            .collect::<Vec<_>>(),
        vec![(door::CLASS_FEE_INDEX, 1)],
        "the fee unit alone"
    );
}
