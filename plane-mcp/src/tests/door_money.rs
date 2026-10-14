// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! $ THE DOOR'S MONEY ANSWERS: what a unit reports beside the answer its caller is written. The
//! plane reports its units and whether a fee unit was incurred; the kernel writes them (the design's
//! money section, "The plane reports; the kernel writes").

use serde_json::{json, Value};

use super::*;

/// One server with one approved tool.
const SECTION: &str = r#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"},
  "tools_allow": {"read_file": {"schema_hash": "sha256:aa"}}}}"#;

/// `fs_read_file`, admitted under the kernel's trust verdict `trust`.
fn admission(trust: crate::call::Trust) -> Admission {
    let section = crate::door::read_tools_section(SECTION.as_bytes()).expect("the section reads");
    let catalogue = Catalogue::build(1, &section);
    let params = json!({ "name": "fs_read_file", "arguments": {}, "_meta": {} });
    crate::call::admit_trusted(
        &catalogue,
        &json!(30),
        Some(&params),
        &|_| None,
        &|_, _| true,
        &mut |_| trust.clone(),
        &mut |_, _| AskDecision::Proceed,
    )
}

/// `fs_read_file`, admitted: its server serves.
fn admitted() -> AdmittedCall {
    match admission(crate::call::Trust::Verdict(
        busbar_contract::abi::host::service::DISTRUST_NONE,
    )) {
        Admission::Go(a) => a,
        other => panic!("the call is admitted: {other:?}"),
    }
}

/// `fs_read_file`, whose server the door's live tool-list check could not reach: its answer and its
/// call-log line.
fn unreached() -> (Vec<u8>, crate::call::CallLine) {
    match admission(crate::call::Trust::Unreached("down".to_string())) {
        Admission::Unreached(body, line) => (body, line),
        other => panic!("the call is unreached: {other:?}"),
    }
}

/// The counts an answer reports, `(class, amount)`.
fn units(answer: &Pending) -> Vec<(u32, u64)> {
    answer.units.iter().map(|u| (u.class, u.amount)).collect()
}

/// The call log's one line for `fs_read_file`, as the door writes it under scope `k`, generation 1,
/// at 7.
fn logged(outcome: &str, reason: &str) -> Vec<(u32, Vec<u8>, Vec<u8>)> {
    vec![(
        door::RECORD_CALL,
        b"k".to_vec(),
        crate::record::call_suffix(7, "fs", "fs_read_file", outcome, reason, "sha256:aa", 1),
    )]
}

/// The answer's body, a JSON-RPC tool error answering the caller's id.
fn tool_error(answer: &Pending) {
    assert_eq!(answer.status, 200, "the 200 isError answer shape stays");
    let body: Value = serde_json::from_slice(&answer.bytes).expect("a JSON-RPC answer");
    assert_eq!(body["id"], json!(30));
    assert_eq!(body["result"]["isError"], json!(true), "{body}");
}

/// $ A CALL THAT NEVER LEFT ITS QUEUE EARNS NO FEE UNIT AND IS NOT LOGGED DISPATCHED
/// (ARCHITECT ruling 2026-10-14 (1) on busbar-plane-mcp#14: #62 "bill what was delivered",
/// BUSBAR-1.6.0.md l.2252; Q35 "a hop refused before the socket is refunded", 1.6.0-QUESTIONS.md,
/// applied uniformly across planes). A call queued behind another call on its stdio member's child,
/// whose deadline passed before its turn came, was never sent. Its caller is still answered the
/// upstream-failure tool error, 200 `isError`, but the plane reports NO fee unit, so the kernel gives
/// back the fee its admission counted. The call log names it `refused` / `queue_deadline`, audited
/// rejected, never `dispatched`, because that word means the call went out.
///
/// RED before the ruling: the door answered this call through `call::upstream_failed`, which logs
/// `dispatched` / `upstream_failed` and audits the call; and through `Pending::answer` alone,
/// which reports the fee unit `(CLASS_FEE_INDEX, 1)` for the 200.
#[test]
fn a_call_that_never_left_its_queue_earns_no_fee_unit_and_is_not_logged_dispatched() {
    let crate::call::Settled::Answer { status, body, line } =
        crate::call::never_sent(&admitted(), door_program::BUSY)
    else {
        panic!("an answer");
    };
    let answer = never_sent_answer(status, body, &line, None, ("k", 1, Some(7)));
    tool_error(&answer);
    assert_eq!(
        units(&answer),
        Vec::<(u32, u64)>::new(),
        "no fee unit and no class: nothing was sent, nothing was delivered"
    );
    assert_eq!(
        answer.records,
        logged(
            busbar_contract::vocab::OUTCOME_REFUSED,
            crate::call::REASON_QUEUE_DEADLINE
        ),
        "the call log's one line: refused, queue_deadline, never dispatched"
    );
    assert_eq!(
        answer.audits,
        vec![crate::call::AuditRow::tool("fs_read_file", false)],
        "audited rejected"
    );
}

/// The twin of the queued call: a call that WAS sent and whose upstream then failed keeps its fee
/// unit and its `dispatched` line. The fee follows what went out, not how the far end answered (Q35,
/// "a hop that left is billed whatever the backend then answered").
#[test]
fn a_call_that_went_out_and_failed_keeps_its_fee_unit_and_its_dispatched_line() {
    let crate::call::Settled::Answer { status, body, line } =
        crate::call::upstream_failed(&admitted(), "down")
    else {
        panic!("an answer");
    };
    let answer = Pending::answer(status, body, None, &[]).logged(Some(&line), "k", 1, Some(7));
    tool_error(&answer);
    assert_eq!(
        units(&answer),
        vec![(door::CLASS_FEE_INDEX, 1)],
        "the fee unit alone"
    );
    assert_eq!(
        answer.records,
        logged(
            busbar_contract::vocab::OUTCOME_DISPATCHED,
            busbar_contract::vocab::REASON_UPSTREAM_FAILED
        ),
        "dispatched, then failed"
    );
}

/// $ A CALL WHOSE SERVER THE TOOL-LIST CHECK COULD NOT REACH EARNS NO FEE UNIT (ARCHITECT ruling
/// 2026-10-14 (a) on busbar-plane-mcp#14, the same as (1): #62, BUSBAR-1.6.0.md l.2252; Q35). The
/// door's live re-fetch of the server's tool list failed (ARCHITECT Q3 (c)), so the call never left.
/// Its caller is answered the upstream-failure tool error, 200 `isError`, and the plane reports NO
/// fee unit, so the kernel gives back the fee its admission counted.
///
/// RED before the ruling: the door answered `Admission::Unreached` as it answers busbar's own ask of
/// its caller, through `Pending::answer` alone, which reports the fee unit `(CLASS_FEE_INDEX, 1)`
/// for the 200.
#[test]
fn a_call_whose_server_the_tool_list_check_could_not_reach_earns_no_fee_unit() {
    let (body, line) = unreached();
    let answer = never_sent_answer(200, body, &line, None, ("k", 1, Some(7)));
    tool_error(&answer);
    assert_eq!(
        units(&answer),
        Vec::<(u32, u64)>::new(),
        "no fee unit and no class: the call never left"
    );
}

/// The twin of the unreached call: its call-log line stays what it was, `refused` under its fixed
/// reason `upstream_failed`, audited rejected. The call did not go out, so it is never `dispatched`.
#[test]
fn a_call_whose_server_the_tool_list_check_could_not_reach_stays_logged_refused() {
    let (body, line) = unreached();
    let answer = never_sent_answer(200, body, &line, None, ("k", 1, Some(7)));
    assert_eq!(
        answer.records,
        logged(
            busbar_contract::vocab::OUTCOME_REFUSED,
            busbar_contract::vocab::REASON_UPSTREAM_FAILED
        ),
        "refused, upstream_failed: never dispatched"
    );
    assert_eq!(
        answer.audits,
        vec![crate::call::AuditRow::tool("fs_read_file", false)],
        "audited rejected"
    );
}
