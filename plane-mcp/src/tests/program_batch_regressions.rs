use super::*;

#[test]
fn a_privileged_ask_cannot_be_hidden_before_or_between_cheaper_asks() {
    use crate::client::jsonrpc::{parse_response, RpcOutcome, ServerAsk};
    for requests in [
        json!({"a":{"method":"sampling/createMessage","params":{}},"b":{"method":"roots/list","params":{}}}),
        json!({"a":{"method":"roots/list","params":{}},"b":{"method":"sampling/createMessage","params":{}},"c":{"method":"elicitation/create","params":{}}}),
    ] {
        let response = bytes(
            &json!({"jsonrpc":"2.0","id":7,"result":{"resultType":"input_required","inputRequests":requests}}),
        );
        assert_eq!(
            parse_response(&response, 7),
            RpcOutcome::InputRequired {
                kind: ServerAsk::Sampling
            }
        );
    }
}

#[test]
fn a_notification_batch_never_becomes_the_calls_answer() {
    let mut corr = Correlator::default();
    let mut peer = Door::default();
    let notifications = bytes(&json!([
        {"jsonrpc":"2.0", "method":"notifications/tools/list_changed"},
        {"jsonrpc":"2.0", "id":99, "result":{"other":true}}
    ]));
    assert!(corr
        .take(&notifications, 7, "srv", 1, &mut peer)
        .unwrap()
        .is_none());
    assert_eq!(peer.noticed, 1);
    let response = bytes(&json!({"jsonrpc":"2.0", "id":7, "result":{"ours":true}}));
    let answer = corr
        .take(&response, 7, "srv", 1, &mut peer)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&answer).unwrap()["result"]["ours"],
        json!(true)
    );
}

#[test]
fn a_batched_matching_reply_keeps_its_exact_id() {
    let mut corr = Correlator::default();
    let mut peer = Door::default();
    let batch = bytes(&json!([
        {"jsonrpc":"2.0", "id":99, "result":{}},
        {"jsonrpc":"2.0", "id":7, "result":{"ours":true}}
    ]));
    let answer = corr.take(&batch, 7, "srv", 1, &mut peer).unwrap().unwrap();
    let answer: Value = serde_json::from_slice(&answer).unwrap();
    assert_eq!(answer["id"], json!(7));
    assert_eq!(answer["result"]["ours"], json!(true));
}
