// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn a_json_hop_keeps_only_the_negotiators_body_copy() {
    let plane = McpDoor::default();
    let mut state = Negotiating::begin(
        &plane,
        "srv",
        "caller",
        OutboundRequest {
            url: "https://example.test/mcp".into(),
            headers: vec![],
            body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec(),
        },
    );
    state.stateless_known = true;
    let body = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#.to_vec();
    let Action::Finish(answer) = state.feed(Some((200, vec![], body.clone()))) else {
        panic!("known stateless hop finishes");
    };
    assert_eq!(answer.body, body);
    assert!(state.raw.0.is_empty());
    assert!(!state.raw.1);
}

#[test]
fn marker_object_ids_are_refused_at_session_arrival() {
    for key in ["$serde_json::private::Number", r"\u0024serde_json::private::Number"] {
        let body = format!(r#"{{"jsonrpc":"2.0","id":{{"{key}":"27"}},"result":{{}}}}"#);
        let SessionArrived::Session(arrival) = arrive(None, "POST", "/mcp", body.as_bytes(), &|name| {
            (name == adapt::H_SESSION_ID).then(|| "session".to_string())
        }) else { panic!("session arrival") };
        assert!(matches!(arrival.unit, SessionUnit::Message { kind: Kind::Refused(_), .. }));
    }
    let SessionArrived::Session(arrival) = arrive(None, "POST", "/mcp", br#"{"jsonrpc":"2.0","id":27,"result":{}}"#, &|name| {
        (name == adapt::H_SESSION_ID).then(|| "session".to_string())
    }) else { panic!("session arrival") };
    assert!(matches!(arrival.unit, SessionUnit::Message { kind: Kind::Accept(_), .. }));
}
