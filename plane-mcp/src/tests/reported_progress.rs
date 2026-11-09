use super::*;
use serde_json::json;

#[test]
fn stdio_progress_mapping_applies_the_existing_frame_bound() {
    let section=crate::statement::test_support::read_tools_section(br#"{"srv":{"transport":"stdio","command":"/fixture/child","pin":{"mechanism":"unpinned"},"tools_allow":{"echo":{"schema_hash":"sha256:a"}}}}"#).unwrap();
    let catalogue = crate::catalogue::Catalogue::build(1, &section);
    let mut admitted = crate::call::AdmittedCall {
        entry: catalogue.tool_on("srv", "echo").unwrap().clone(),
        arguments: json!({}),
        id: json!(7),
        progress_token: Some(json!("caller-token")),
        capabilities: json!({}),
        sent_digest: String::new(),
        initial_input_responses: None,
        relay: None,
    };
    let frames:Vec<_>=(0..257).map(|n|json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"far-token","progress":n}})).collect();
    let mapped = relay_progress(&admitted, frames.clone());
    assert_eq!(mapped.len(), 256);
    assert_eq!(mapped[255]["params"]["progress"], 255);
    assert!(mapped
        .iter()
        .all(|frame| frame["params"]["progressToken"] == "caller-token"));
    admitted.progress_token = None;
    assert!(relay_progress(&admitted, frames).is_empty());
}
