use super::*;

#[test]
fn an_unarmed_reply_exchange_is_failed_instead_of_reported_as_delivered() {
    let plane = McpDoor::default();
    let mut relay = ProgramRelay::waiting(&plane, "srv", 7);
    let def: crate::tools_config::McpServerDefCfg = serde_json::from_value(serde_json::json!({
        "transport":"stdio", "command":"/usr/bin/child", "pin":{"mechanism":"unpinned"}
    }))
    .unwrap();
    let result = refuse_asks(
        &plane,
        Ticket {
            slot: 4,
            generation: 1,
        },
        "srv",
        &def,
        &mut relay,
        vec![br#"{"jsonrpc":"2.0","id":8,"error":{"code":-32000,"message":"refused"}}"#.to_vec()],
    );
    match result {
        Far::Settled(Err(reason)) => assert!(!reason.is_empty()),
        _ => panic!("an unsent child reply must retain the actual exchange failure"),
    }
}
