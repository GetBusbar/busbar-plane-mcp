// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::client::jsonrpc::tools_list;
use crate::connections::AuthorizationBinding;
use serde_json::json;

fn binding() -> AuthorizationBinding {
    AuthorizationBinding {
        issuer: "https://issuer.test".into(),
        resource: "https://upstream.test/mcp".into(),
        redirect_uri: "https://busbar.test/callback".into(),
        client_id: "public-client".into(),
    }
}
fn activate(plane: &McpDoor, caller: &str) -> DiscoveryKey {
    table(plane, |t| {
        let key = key(caller, "server");
        t.grant_consent(key.clone(), binding(), ["read".into()].into())
            .unwrap();
        let a = t
            .begin_authorization(&key, [1; 32], [2; 32], 1000, 5000)
            .unwrap();
        let p = t
            .consume_callback(&key, &a.state, &binding(), 1100)
            .unwrap();
        t.complete_authorization(p, 1200, 10000).unwrap();
        t.discovery_key(&key, 1200).unwrap()
    })
}
fn sighting(tool: &str) -> PublishedList {
    let result = json!({"tools":[{"name":tool,"inputSchema":{"type":"object"}}]});
    let response = busbar_contract::abi::sdk::exchange::ExchangeResponse {
        status: 200,
        reason: None,
        fields: vec![],
        body: busbar_contract::jsonrpc::result_bytes(b"1", &crate::codec::json(&result)),
    };
    PublishedList {
        generation: 1,
        sighting: sighting_of(Ok(response), 1),
    }
}
#[test]
fn user_discovery_never_uses_another_credentials_cache_or_global_sighting() {
    let plane = McpDoor::default();
    let bob = activate(&plane, "bob-key");
    let joe = activate(&plane, "joe-key");
    assert_ne!(bob.session_key(), joe.session_key());
    plane.connection_lists.insert(bob, sighting("bob_private"));
    plane.connection_lists.insert(joe, sighting("joe_private"));
    let crate::trust::Sighting::Seen(bob) = list(&plane, "bob-key", "server", 2000).sighting else {
        panic!("Bob discovery")
    };
    assert!(bob.capabilities.contains_key("bob_private"));
    assert!(!bob.capabilities.contains_key("joe_private"));
    assert!(matches!(
        list(&plane, "other-key", "server", 2000).sighting,
        crate::trust::Sighting::Never
    ));
    assert!(plane.sightings.with_all(|s| s.is_empty()));
}
#[test]
fn expiry_revocation_and_refresh_fence_cache_and_sessions() {
    let plane = McpDoor::default();
    let before = activate(&plane, "bob");
    plane
        .connection_lists
        .insert(before.clone(), sighting("private"));
    assert!(matches!(
        list(&plane, "bob", "server", 10000).sighting,
        crate::trust::Sighting::Never
    ));
    let after = table(&plane, |t| {
        let k = key("bob", "server");
        let p = t.begin_refresh(&k, 2000, 5000).unwrap();
        t.complete_refresh(p, 2100, 20000).unwrap();
        t.discovery_key(&k, 2200).unwrap()
    });
    assert_ne!(before.session_key(), after.session_key());
    assert!(matches!(
        list(&plane, "bob", "server", 2200).sighting,
        crate::trust::Sighting::Never
    ));
    plane.connection_lists.insert(after, sighting("new"));
    table(&plane, |t| t.revoke(&key("bob", "server")).unwrap());
    assert!(matches!(
        list(&plane, "bob", "server", 2200).sighting,
        crate::trust::Sighting::Never
    ));
}
#[test]
fn negotiation_returns_all_hops_to_governed_dispatch_without_a_connector() {
    let plane = McpDoor::default();
    let mut n = door_sessions::Negotiating::begin(
        &plane,
        "server",
        "bob-revision-1",
        tools_list("https://upstream.test/mcp", 1, None),
    );
    let door_sessions::Governed::Send(init) =
        n.governed_answer(&plane, "server", 400, vec![], vec![])
    else {
        panic!("must negotiate through governed emit")
    };
    let v: Value = serde_json::from_slice(&init.body).unwrap();
    assert_eq!(v["method"], "initialize");
    assert_eq!(init.url, "https://upstream.test/mcp");
    // Even an upstream auth refusal never falls back to an unauthenticated connector.
    let mut refused = door_sessions::Negotiating::begin(
        &plane,
        "server",
        "bob",
        tools_list("https://upstream.test/mcp", 1, None),
    );
    assert!(matches!(
        refused.governed_answer(&plane, "server", 401, vec![], vec![]),
        door_sessions::Governed::Done(door_sessions::Negotiated::Answer(401, ..))
    ));
}
#[test]
fn token_parser_captures_credentials_and_sanitizes_bad_token_values() {
    let token=busbar_contract::abi::sdk::cred::json_reply::<TokenReply>(br#"{"access_token":"access-secret","refresh_token":"refresh-secret","token_type":"Bearer","expires_in":60}"#).unwrap();
    assert!(!token.access_token.is_empty());
    assert!(!token.refresh_token.unwrap().is_empty());
    let Err(error) = busbar_contract::abi::sdk::cred::json_reply::<TokenReply>(
        br#"{"access_token":"secret","token_type":"Bearer","expires_in":"do-not-print-me"}"#,
    ) else {
        panic!("bad expiry accepted")
    };
    assert!(!error.to_string().contains("do-not-print-me"));
}
#[test]
fn connection_methods_are_distinct_operations_and_route_only_to_named_member() {
    for method in [
        "connections/authorize",
        "connections/callback",
        "connections/refresh",
        "connections/revoke",
        "connections/discover",
    ] {
        let row = crate::tool_ops::method_row_for(method).unwrap();
        let d = Disposition::Request { row, id: json!(1) };
        let v = json!({"params":{"server":"configured","client_id":"spoofed-client"}});
        assert_eq!(route(&d, Some(&v)), Some("configured"));
        assert_eq!(key("verified", "configured").downstream_client, "verified");
    }
}
