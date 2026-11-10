// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Protocol lifecycle through the actual gateway and TLS upstream. No browser-rendering claim.
use super::tool_door::{self, Rig, TlsToolServer};
use crate::root::serve::planes_tests::PUBLISHING;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
const MIME: &str = "text/html;profile=mcp-app";
const URI: &str = "ui://same/view";

fn tools(drift: bool) -> Value {
    json!([
        {"name":"view", "description":"", "inputSchema":{"type":"object"}, "_meta":{"ui":{"resourceUri":URI,"visibility":["model","app"]}}},
        {"name":"refresh", "description":"", "inputSchema":{"type":"object"}, "_meta":{"ui":{"resourceUri":URI,"visibility":if drift {vec!["model","app"]} else {vec!["app"]}}}}
    ])
}
fn approved() -> Value {
    let mut result = json!({});
    for (tool, digest) in tools(false).as_array().unwrap().iter().zip([
        "sha256:c6f747831057ddbec878a4563296bfab38f2bcd182b2d70c30773223553903f2",
        "sha256:7133e3e1010a50d0df13d2325bff7b37a16f10c8594ebdea856e2fc1a0ca4111",
    ]) {
        result[tool["name"].as_str().unwrap()] = json!({"schema_hash":digest,"description":"","input_schema":tool["inputSchema"],"meta":tool["_meta"]});
    }
    result
}
async fn session_request(
    rig: &Rig,
    token: &str,
    session: Option<&str>,
    method: &str,
    params: Value,
) -> (u16, axum::http::HeaderMap, Value) {
    use tower::ServiceExt as _;
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(tool_door::endpoint())
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .header("mcp-protocol-version", "2025-11-25");
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    let body = json!({"jsonrpc":"2.0","id":73,"method":method,"params":params});
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        rig.router.clone().oneshot(
            request
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        ),
    )
    .await
    .expect("bounded Apps request")
    .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!("non-JSON Apps result: {}", String::from_utf8_lossy(&bytes))
        }),
    )
}
async fn open(rig: &Rig, token: &str, apps: bool) -> String {
    let caps = if apps {
        json!({"extensions":{"io.modelcontextprotocol/ui":{"mimeTypes":[MIME]}}})
    } else {
        json!({})
    };
    let (status, headers, result) = session_request(rig, token, None, "initialize", json!({"protocolVersion":"2025-11-25","clientInfo":{"name":"protocol-fixture","version":"1"},"capabilities":caps})).await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(
        result["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/ui"].is_object(),
        apps,
        "{result}"
    );
    headers
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}
async fn discover(rig: &Rig, token: &str, session: &str, member: &str) {
    let (_, _, result) = session_request(
        rig,
        token,
        Some(session),
        "connections/discover",
        json!({"server":member}),
    )
    .await;
    assert_eq!(result["result"]["discovered"], true, "{result}");
}
fn resource(list: &Value, name: &str) -> String {
    list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == name)
        .unwrap()["_meta"]["ui"]["resourceUri"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn names(list: &Value) -> Vec<&str> {
    list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect()
}
fn refused(result: &Value) -> bool {
    result.get("error").is_some() || result["result"]["isError"] == true
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_mcp_apps_tls_sessions_visibility_resources_and_revocation() {
    let _one = PUBLISHING.lock().await;
    let mode = Arc::new(AtomicUsize::new(0));
    let upstream_mode = mode.clone();
    let profiles = Arc::new(AtomicUsize::new(0));
    let upstream_profiles = profiles.clone();
    let reads = Arc::new(AtomicUsize::new(0));
    let upstream_reads = reads.clone();
    let server = TlsToolServer::replying(Arc::new(move |request| {
        let body = request.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        if request.starts_with("POST /token ") {
            let form: std::collections::BTreeMap<_,_> = url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();
            let owner = form.get("code").expect("authorization code");
            return (200, json!({"access_token":format!("{owner}-private-token"),"token_type":"Bearer","expires_in":600,"scope":"read"}).to_string());
        }
        let lower = request.to_ascii_lowercase();
        let owner = if lower.contains("authorization: bearer bob-private-token") { "bob" }
            else if lower.contains("authorization: bearer joe-private-token") { "joe" }
            else { return (401, json!({"error":"missing owner credential"}).to_string()); };
        let rpc: Value = serde_json::from_str(body).unwrap();
        let mode = upstream_mode.load(Ordering::SeqCst);
        let result = match rpc["method"].as_str().unwrap() {
            "tools/list" => {
                let apps = rpc.pointer("/params/_meta/io.modelcontextprotocol~1clientCapabilities/extensions/io.modelcontextprotocol~1ui/mimeTypes").is_some();
                upstream_profiles.fetch_or(if apps {1} else {2}, Ordering::SeqCst);
                json!({"tools": tools(mode == 4)})
            },
            "resources/read" => {
                upstream_reads.fetch_add(1, Ordering::SeqCst);
                assert_eq!(rpc["params"]["uri"], URI);
                let text = match mode { 2 => "x".repeat(8192), _ => format!("<!doctype html><html><body>{owner}<script>window.fixture=1</script></body></html>") };
                json!({"contents":[{"uri":URI,"mimeType":if mode == 3 {"text/plain"} else {MIME},"text":text,"_meta":{"ui":if mode == 1 {json!({"csp":{"connectDomains":["https://unapproved.test"]}})} else {json!({})}}}]})
            },
            "tools/call" => json!({"content":[{"type":"text","text":owner},{"type":"resource_link","uri":URI,"name":"view","mimeType":MIME}]}),
            other => panic!("unexpected Apps upstream method: {other}"),
        };
        (200, json!({"jsonrpc":"2.0","id":rpc["id"],"result":result}).to_string())
    })).await;
    let issuer = format!("https://127.0.0.1:{}", server.port);
    let mut section = server.section();
    section["fs"]["upstream_credentials"] = "connection".into();
    section["fs"]["oauth"] = serde_yaml::to_value(json!({"issuer":issuer,"resource":format!("{issuer}/rpc"),"client_id":"public-client","redirect_uri":"https://client.test/callback","authorization_endpoint":format!("{issuer}/authorize"),"token_endpoint":format!("{issuer}/token"),"scopes":["read"]})).unwrap();
    section["fs"]["apps"] = serde_yaml::to_value(
        json!({"enabled":true,"max_resource_bytes":4096,"resources":{URI:{"ui":{}}}}),
    )
    .unwrap();
    section["fs"]["tools_allow"] = serde_yaml::to_value(approved()).unwrap();
    section["alt"] = section["fs"].clone();
    let rig = server.rig("mcp-apps-owner", section, &|app| app).await;
    let bob = rig.bound_token();
    let (_, joe) = rig
        .gov
        .mint_signed_async(
            busbar_kernel::governance::NewKeySpec {
                name: "joe-apps".into(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
        .unwrap();
    let joe = rig.bound_token_for(joe.expose(&busbar_kernel::seal::lend()));
    super::connections::enroll(&rig, &bob, "bob", &issuer).await;
    super::connections::enroll(&rig, &joe, "joe", &issuer).await;
    let (_, start) = super::connections::ask(
        &rig,
        &bob,
        "connections/authorize",
        json!({"server":"alt","consent":true}),
    )
    .await;
    let url = url::Url::parse(start["result"]["authorization_url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let (_, end) = super::connections::ask(
        &rig,
        &bob,
        "connections/callback",
        json!({"server":"alt","state":state,"iss":issuer,"code":"bob"}),
    )
    .await;
    assert_eq!(end["result"]["status"], "active", "{end}");
    let bob_apps = open(&rig, &bob, true).await;
    let joe_apps = open(&rig, &joe, true).await;
    let legacy = open(&rig, &bob, false).await;
    discover(&rig, &bob, &bob_apps, "fs").await;
    discover(&rig, &bob, &bob_apps, "alt").await;
    discover(&rig, &joe, &joe_apps, "fs").await;
    discover(&rig, &bob, &legacy, "fs").await;
    let (_, _, bob_list) =
        session_request(&rig, &bob, Some(&bob_apps), "tools/list", json!({})).await;
    assert!(names(&bob_list).contains(&"fs_refresh"), "{bob_list}");
    let bob_uri = resource(&bob_list, "fs_view");
    let alt_uri = resource(&bob_list, "alt_view");
    assert_ne!(bob_uri, alt_uri, "same upstream URI on different members");
    let (_, _, joe_list) =
        session_request(&rig, &joe, Some(&joe_apps), "tools/list", json!({})).await;
    let joe_uri = resource(&joe_list, "fs_view");
    assert_ne!(bob_uri, joe_uri);
    let (_, _, legacy_list) =
        session_request(&rig, &bob, Some(&legacy), "tools/list", json!({})).await;
    assert_eq!(names(&legacy_list), vec!["fs_view"], "{legacy_list}");
    assert!(legacy_list["result"]["tools"][0]["_meta"]
        .get("ui")
        .is_none());
    for (token, session, uri, owner) in [
        (&bob, &bob_apps, &bob_uri, "bob"),
        (&bob, &bob_apps, &alt_uri, "bob"),
        (&joe, &joe_apps, &joe_uri, "joe"),
    ] {
        let (_, _, result) = session_request(
            &rig,
            token,
            Some(session),
            "resources/read",
            json!({"uri":uri}),
        )
        .await;
        assert_eq!(result["result"]["contents"][0]["uri"], *uri, "{result}");
        assert_eq!(
            result["result"]["contents"][0]["text"],
            format!(
                "<!doctype html><html><body>{owner}<script>window.fixture=1</script></body></html>"
            ),
            "{result}"
        );
        assert_eq!(
            result["result"]["contents"][0]["_meta"]["io.busbar/mutable"],
            true
        );
    }
    let reads_before_foreign = reads.load(Ordering::SeqCst);
    for (token, session, uri) in [(&joe, &joe_apps, &bob_uri), (&bob, &legacy, &bob_uri)] {
        let (_, _, result) = session_request(
            &rig,
            token,
            Some(session),
            "resources/read",
            json!({"uri":uri}),
        )
        .await;
        assert!(refused(&result), "cross-context read: {result}");
    }
    assert_eq!(
        reads.load(Ordering::SeqCst),
        reads_before_foreign,
        "foreign mappings never reach resources/read"
    );
    assert_eq!(
        profiles.load(Ordering::SeqCst),
        3,
        "both negotiated profiles reached isolated discovery"
    );
    let (_, _, called) = session_request(
        &rig,
        &bob,
        Some(&bob_apps),
        "tools/call",
        json!({"name":"fs_refresh","arguments":{}}),
    )
    .await;
    assert_eq!(called["result"]["content"][0]["text"], "bob", "{called}");
    assert_eq!(called["result"]["content"][1]["uri"], bob_uri, "{called}");
    let (_, _, called) = session_request(
        &rig,
        &bob,
        Some(&legacy),
        "tools/call",
        json!({"name":"fs_refresh","arguments":{}}),
    )
    .await;
    assert!(refused(&called), "legacy app-only call: {called}");
    for mode_value in [1, 2, 3] {
        mode.store(mode_value, Ordering::SeqCst);
        let (_, _, read) = session_request(
            &rig,
            &bob,
            Some(&bob_apps),
            "resources/read",
            json!({"uri":bob_uri}),
        )
        .await;
        assert!(refused(&read), "unsafe resource mode {mode_value}: {read}");
    }
    mode.store(4, Ordering::SeqCst);
    discover(&rig, &bob, &bob_apps, "fs").await;
    let (_, _, drifted) = session_request(
        &rig,
        &bob,
        Some(&bob_apps),
        "tools/call",
        json!({"name":"fs_refresh","arguments":{}}),
    )
    .await;
    assert!(refused(&drifted), "metadata drift: {drifted}");
    mode.store(0, Ordering::SeqCst);
    let (_, revoke) =
        super::connections::ask(&rig, &bob, "connections/revoke", json!({"server":"fs"})).await;
    assert_eq!(revoke["result"]["revoked"], true, "{revoke}");
    let (_, _, read) = session_request(
        &rig,
        &bob,
        Some(&bob_apps),
        "resources/read",
        json!({"uri":bob_uri}),
    )
    .await;
    assert!(refused(&read), "revoked resource: {read}");
    server.close().await;
}
