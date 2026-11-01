use super::*;

#[test]
fn custom_event_ids_are_not_counted_as_dropped_rpc_replies() {
    let mut l = link();
    feed(&mut l, "event: custom\ndata: {\"id\":99}\n\n");
    assert_eq!(l.dropped, 0, "a custom event is not an RPC response");
    feed(
        &mut l,
        "event: message\ndata: {\"id\":99,\"result\":{}}\n\n",
    );
    assert_eq!(l.dropped, 1, "the unmatched RPC response is still audited");
}

#[test]
fn an_oversized_event_names_the_local_size_refusal() {
    let mut l = link();
    assert!(l.wait(7, ticket(1)));
    let raw = format!("data: {}", "x".repeat(MAX_EVENT + 1));
    let woken = feed(&mut l, &raw);
    let reason = l.dead.as_deref().expect("the event was refused");
    assert!(reason.contains(&MAX_EVENT.to_string()), "{reason}");
    assert_ne!(reason, STREAM_CLOSED, "a local refusal is not remote EOF");
    assert!(woken.contains(&ticket(1)));
}

#[test]
fn a_dead_initialize_releases_its_waiter_and_retains_completed_answers() {
    let mut l = link();
    l.init = Init::Running;
    l.init_by = Some(ticket(1));
    l.waiters.insert(INITIALIZE_ID.to_string(), ticket(1));
    l.answers
        .insert("7".into(), (ticket(2), b"completed".to_vec()));
    let mut woken = Vec::new();
    l.die("initialize POST failed", &mut woken);
    assert!(
        l.waiters.is_empty(),
        "failed calls no longer keep a dead link live"
    );
    assert_eq!(l.answers.get("7").unwrap().1, b"completed");
    assert!(woken.contains(&ticket(1)));
}

#[test]
fn accumulated_legacy_notifications_obey_the_existing_reply_byte_bound() {
    let mut l = link();
    assert!(l.wait(7, ticket(1)));
    let payload = "x".repeat(MAX_EVENT / 2);
    let note = serde_json::json!({"jsonrpc":"2.0","method":"notifications/message", "params":{"level":"info", "data": payload}});
    let raw = format!("data: {note}\n\n");
    let max = busbar_contract::abi::sdk::exchange::REPLY_MAX;
    for _ in 0..(max / raw.len() + 2) {
        feed(&mut l, &raw);
    }
    let held: usize = l
        .logs
        .iter()
        .map(|v| serde_json::to_vec(v).unwrap().len())
        .sum();
    assert!(
        held <= max,
        "retained {held} bytes beyond the existing {max}-byte reply bound"
    );
    assert!(
        l.dead.is_some(),
        "a bound refusal is observable, not silent loss"
    );
}
