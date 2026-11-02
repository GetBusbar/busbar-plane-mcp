use super::*;

#[test]
fn a_task_budget_refusal_keeps_the_kernels_status_and_budget_reason() {
    use busbar_contract::abi::plane::{RefusalCode, RefusalIn, RefusalOut, REFUSAL_KERNEL};
    let _serial = fresh();
    let d = open(&section());
    let body = call("st_read_file", &json!({}));
    assert_eq!(d.arrive(1, &body).outcome, Outcome::Ready);
    let mut reply = vec![0u8; 4096];
    let mut fields = [z::<OutField>(); 8];
    let mut arena = vec![0u8; 4096];
    let mut records = [z::<RecordWrite>(); 8];
    let mut input: RefusalIn = z();
    input.head = head::<RefusalIn>(
        slot::REFUSAL,
        Ticket {
            slot: 1,
            generation: 1,
        },
    );
    input.unit = 1;
    input.cause = REFUSAL_KERNEL;
    input.reason = RefusalCode::OverBudget.code();
    input.status = 429;
    input.text = str_of("the requests budget is spent");
    input.target = str_of("/mcp");
    input.reply_buf = reply.as_mut_ptr();
    input.reply_cap = reply.len();
    input.fields_buf = fields.as_mut_ptr();
    input.fields_cap = fields.len();
    input.arena_buf = arena.as_mut_ptr();
    input.arena_cap = arena.len();
    input.records_buf = records.as_mut_ptr();
    input.records_cap = records.len();
    let mut output: RefusalOut = z();
    output.head = out_head::<RefusalOut>();
    // SAFETY: The fixture owns this live door instance; the exact input/output frames and every borrowed buffer remain live throughout the synchronous call.
    let result = unsafe {
        ops().refusal.unwrap()(
            d.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(result.outcome(), Outcome::Ready);
    assert_eq!(output.status, 429);
    let body: Value = serde_json::from_slice(&reply[..output.reply_written as usize]).unwrap();
    assert_eq!(body["id"], 30);
    assert_eq!(body["error"]["data"]["reason"], "budget_exhausted");
}

#[test]
fn a_completed_task_result_keeps_markup_across_nodes() {
    let _serial = fresh();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let sent = run(&d, 2, "st", &last_nested());
    let result = json!({"content":[{"type":"text","text":"<b>x</b> Vec<String>"}],"structuredContent":{"opaque":"<script>keep</script>"}});
    let response = rpc_result(&sent.json()["id"], result.clone());
    d.piece(2, &Given::far(ALICE, 200, &response));
    let other = open(&section());
    let found = get(&other, 3, &task);
    assert_eq!(
        found.json()["result"]["result"],
        result,
        "the real host-record round trip never normalises a tool result"
    );
}

#[test]
fn a_task_fails_when_a_far_answer_crosses_the_existing_reply_bound_over_pieces() {
    use busbar_contract::abi::sdk::exchange::{REPLY_MAX, REPLY_OVER_BOUND};
    let _serial = fresh();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let sent = run(&d, 2, "st", &last_nested());
    assert!(sent.far);
    let first = vec![b' '; REPLY_MAX];
    let mut piece = Given::far(ALICE, 200, &first);
    piece.flags &= !PIECE_LAST;
    d.piece(2, &piece);
    d.piece(2, &Given::far(ALICE, 200, b"x"));
    assert_failed(&get(&d, 3, &task), REPLY_OVER_BOUND);
}

#[test]
fn a_refused_unbound_task_body_cannot_fail_the_task_it_names() {
    let _serial = fresh();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let legitimate = last_nested();
    let mut forged: Value = serde_json::from_slice(&legitimate).unwrap();
    forged["params"]["arguments"] = json!({"different":"a caller who never bound this task"});
    let forged = serde_json::to_vec(&forged).unwrap();
    assert_eq!(d.arrive_run(99, &forged).outcome, Outcome::Ready);
    assert_eq!(
        d.refuse(99, "this unbound invocation was refused"),
        Outcome::Ready
    );
    assert_eq!(get(&d, 3, &task).json()["result"]["status"], "working");
    let sent = run(&d, 2, "st", &legitimate);
    assert!(sent.far, "{}", sent.text());
    d.piece(
        2,
        &Given::far(
            ALICE,
            200,
            &result_of(&sent, "the legitimate runner still completes"),
        ),
    );
    assert_completed(&get(&d, 4, &task), "the legitimate runner still completes");
}

fn raw_refusal_writes(d: &Door, unit: u64, text: &str, reply_cap: usize) -> (Outcome, u32) {
    use busbar_contract::abi::plane::{RefusalCode, RefusalIn, RefusalOut, REFUSAL_KERNEL};
    let mut reply = vec![0u8; reply_cap];
    let mut fields = [z::<OutField>(); 8];
    let mut arena = vec![0u8; 16384];
    let mut records = [z::<RecordWrite>(); 32];
    let mut input: RefusalIn = z();
    input.head = head::<RefusalIn>(
        slot::REFUSAL,
        Ticket {
            slot: unit as u32,
            generation: 1,
        },
    );
    input.unit = unit;
    input.cause = REFUSAL_KERNEL;
    input.reason = RefusalCode::NoDestination.code();
    input.status = 502;
    input.text = str_of(text);
    input.target = str_of(door_facts::TASK_RUN_MOUNT);
    input.reply_buf = reply.as_mut_ptr();
    input.reply_cap = reply.len();
    input.fields_buf = fields.as_mut_ptr();
    input.fields_cap = fields.len();
    input.arena_buf = arena.as_mut_ptr();
    input.arena_cap = arena.len();
    input.records_buf = records.as_mut_ptr();
    input.records_cap = records.len();
    let mut output: RefusalOut = z();
    output.head = out_head::<RefusalOut>();
    // SAFETY: The fixture owns this live door instance; the exact input/output frames and every borrowed buffer remain live throughout the synchronous call.
    let result = unsafe {
        ops().refusal.unwrap()(
            d.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    (result.outcome(), output.records_written)
}

#[test]
fn only_the_bound_unit_can_recall_its_failed_tasks_owed_refusal_records() {
    const WHY: &str = "the bound runner was refused";
    let _serial = fresh();
    let d = open(&section());
    let task = create(&d, 1, "st", "st_read_file");
    let legitimate = last_nested();
    let sent = run(&d, 2, "st", &legitimate);
    assert!(sent.far);
    assert_eq!(
        raw_refusal_writes(&d, 2, WHY, 0),
        (Outcome::Failed, 0),
        "short output retains the bound unit's receipt"
    );
    let mut forged: Value = serde_json::from_slice(&legitimate).unwrap();
    forged["params"]["arguments"] = json!({"not":"the bound runner"});
    assert_eq!(
        d.arrive_run(99, &serde_json::to_vec(&forged).unwrap())
            .outcome,
        Outcome::Ready
    );
    assert_eq!(
        raw_refusal_writes(&d, 99, "unbound", 4096),
        (Outcome::Ready, 0),
        "a body naming failed work never emits another run's owed records"
    );
    assert_eq!(
        d.refuse(2, WHY),
        Outcome::Ready,
        "the original bound unit can re-call after its Task.runner was cleared"
    );
    let other = open(&section());
    assert_failed(&get(&other, 4, &task), WHY);
}

#[test]
fn a_bound_relayed_ask_retry_keeps_its_refusal_receipt_after_short_output() {
    const WHY: &str = "the bound relayed runner was refused";
    let _serial = fresh();
    let d = open(&section());
    let task = create(&d, 1, "ask", "ask_read_file");
    let first = run(&d, 2, "ask", &last_nested());
    assert!(first.far);
    let asked = rpc_result(
        &first.json()["id"],
        json!({"resultType":"input_required","inputRequests":{"ok":{"method":"elicitation/create","params":{"message":"sure?"}}},"requestState":"up-1"}),
    );
    d.piece(2, &Given::far(ALICE, 200, &asked));
    assert_eq!(
        get(&d, 3, &task).json()["result"]["status"],
        "input_required"
    );
    let update = verb(
        "tasks/update",
        &task,
        &json!({"inputResponses":{"ok":{"action":"accept"}}}),
    );
    assert_eq!(d.arrive(4, &update).outcome, Outcome::Ready);
    assert_eq!(d.piece(4, &Given::caller(ALICE, &update)).status, 200);
    let retry = run(&d, 5, "ask", &last_nested());
    assert!(retry.far, "{}", retry.text());
    assert_eq!(raw_refusal_writes(&d, 5, WHY, 0), (Outcome::Failed, 0));
    assert_eq!(d.refuse(5, WHY), Outcome::Ready);
    let other = open(&section());
    assert_failed(&get(&other, 6, &task), WHY);
}
