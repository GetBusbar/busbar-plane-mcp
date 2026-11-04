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
