// SPDX-License-Identifier: Apache-2.0
use super::*;
use serde_json::json;

fn discovery(user: &str, server: &str) -> DiscoveryKey {
    DiscoveryKey {
        connection_id: "consent-7".into(),
        connection: crate::connections::ConnectionKey {
            user: user.into(),
            upstream: server.into(),
            downstream_client: user.into(),
        },
        revision: 2,
        capability_profile: json!([apps::MIME]).to_string(),
        approval_revision: 3,
    }
}
#[test]
fn apps_resource_namespaces_isolate_users_members_sessions_and_approval_revisions() {
    let key = discovery("bob", "one");
    let uri = uri_for("session-a", &key, "ui://same/view");
    assert!(uri.starts_with("ui://busbar/"));
    assert!(!uri.contains("bob"));
    let mut keys = vec![discovery("joe", "one"), discovery("bob", "two")];
    let mut revision = key.clone();
    revision.revision += 1;
    keys.push(revision);
    let mut approval = key.clone();
    approval.approval_revision += 1;
    keys.push(approval);
    let mut legacy = key.clone();
    legacy.capability_profile.clear();
    keys.push(legacy);
    for other in keys {
        assert_ne!(uri, uri_for("session-a", &other, "ui://same/view"));
    }
    assert_ne!(uri, uri_for("session-b", &key, "ui://same/view"));
    assert_ne!(uri, uri_for("session-a", &key, "ui://same/other"));
}
#[test]
fn apps_and_legacy_upstream_sessions_do_not_reuse_negotiation() {
    let plane = McpDoor::default();
    plane
        .upstreams
        .insert((), crate::tool_sessions::UpstreamTable::new(16, 65536));
    let mut request = crate::client::jsonrpc::tools_list("https://upstream.test/mcp", 1, None);
    Profile([apps::MIME.into()].into()).apply(&mut request);
    let mut apps = door_sessions::Negotiating::begin(&plane, "server", "bob", request);
    let door_sessions::Governed::Send(init) =
        apps.governed_answer(&plane, "server", 400, vec![], vec![])
    else {
        panic!("initialize")
    };
    let body: Value = serde_json::from_slice(&init.body).unwrap();
    assert_eq!(
        body["params"]["capabilities"]["extensions"][apps::EXTENSION]["mimeTypes"],
        json!([apps::MIME])
    );
    let door_sessions::Governed::Send(_) = apps.governed_answer(&plane, "server", 200, vec![(crate::adapt::H_SESSION_ID.into(), "upstream-app-session".into())], crate::codec::json(&json!({"jsonrpc":"2.0", "id": crate::client::compat::INITIALIZE_ID, "result":{"protocolVersion":"2025-11-25","capabilities":{}}}))) else { panic!("initialized") };
    let door_sessions::Governed::Send(call) =
        apps.governed_answer(&plane, "server", 202, vec![], vec![])
    else {
        panic!("list")
    };
    assert!(call
        .headers
        .iter()
        .any(|(k, v)| k == crate::adapt::H_SESSION_ID && v == "upstream-app-session"));
    let body: Value = serde_json::from_slice(&call.body).unwrap();
    apps.governed_answer(
        &plane,
        "server",
        200,
        vec![],
        crate::codec::json(&json!({"jsonrpc":"2.0","id":body["id"],"result":{"tools":[]}})),
    );
    let mut again = crate::client::jsonrpc::tools_list("https://upstream.test/mcp", 3, None);
    Profile([apps::MIME.into()].into()).apply(&mut again);
    let again = door_sessions::Negotiating::begin(&plane, "server", "bob", again);
    assert!(again
        .first_request()
        .unwrap()
        .headers
        .iter()
        .any(|(k, v)| k == crate::adapt::H_SESSION_ID && v == "upstream-app-session"));
    let legacy = door_sessions::Negotiating::begin(
        &plane,
        "server",
        "bob",
        crate::client::jsonrpc::tools_list("https://upstream.test/mcp", 2, None),
    );
    assert!(!legacy
        .first_request()
        .unwrap()
        .headers
        .iter()
        .any(|(k, _)| k == crate::adapt::H_SESSION_ID));
}
