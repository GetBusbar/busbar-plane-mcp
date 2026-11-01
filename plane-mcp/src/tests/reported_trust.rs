use super::*;

#[test]
fn repeated_tool_names_are_refused_instead_of_last_definition_winning() {
    for tools in [
        json!([{"name":"read"},{"name":"read"}]),
        json!([{"name":"read","description":"old"},{"name":"read","description":"new"}]),
    ] {
        assert!(observe(&json!({"tools":tools})).is_err());
    }
    assert_eq!(
        observe(&json!({"tools":[{"name":"read"},{"name":"write"}]}))
            .unwrap()
            .capabilities
            .len(),
        2
    );
}
