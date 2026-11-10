// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owner cell: real MCP door, authenticated callers, host custody and a real TLS upstream.
use super::tool_door::{self, Rig, TlsToolServer};
use crate::root::serve::planes_tests::PUBLISHING;
use serde_json::{json, Value};
use std::sync::Arc;

async fn ask(rig: &Rig, token: &str, method: &str, mut params: Value) -> (u16, Value) {
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":tool_door::protocol_version(),"io.modelcontextprotocol/clientCapabilities":{}});
    let request = json!({"jsonrpc":"2.0","id":31,"method":method,"params":params});
    let (status, body) = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tool_door::send_as(&rig.router, Some(token), &request.to_string(), method, None),
    )
    .await
    .expect("bounded connection operation");
    (
        status.as_u16(),
        serde_json::from_slice(&body)
            .unwrap_or_else(|_| panic!("non-JSON response: {}", String::from_utf8_lossy(&body))),
    )
}

async fn enroll(rig: &Rig, token: &str, owner: &str, issuer: &str) {
    let (status, auth) = ask(
        rig,
        token,
        "connections/authorize",
        json!({"server":"fs","consent":true,"client_id":"untrusted","user":"other-user"}),
    )
    .await;
    assert_eq!(status, 200, "{auth}");
    let url = url::Url::parse(
        auth["result"]["authorization_url"]
            .as_str()
            .expect("authorization URL"),
    )
    .unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    assert!(url
        .query_pairs()
        .any(|(k, v)| k == "code_challenge_method" && v == "S256"));
    let (status, answer) = ask(
        rig,
        token,
        "connections/callback",
        json!({"server":"fs","state":state,"iss":issuer,"code":owner}),
    )
    .await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["status"], "active", "{answer}");
    assert!(!answer.to_string().contains("private-token"));
    let (_, replay) = ask(
        rig,
        token,
        "connections/callback",
        json!({"server":"fs","state":state,"iss":issuer,"code":owner}),
    )
    .await;
    assert!(replay.get("error").is_some(), "callback replay: {replay}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_mcp_tls_connections_isolate_bob_joe_refresh_and_revoke() {
    let _one = PUBLISHING.lock().await;
    let mut server = TlsToolServer::replying(Arc::new(|request| {
        let body = request.split_once("\r\n\r\n").map_or("",|(_,body)|body);
        if request.starts_with("POST /token ") {
            let form: std::collections::BTreeMap<_,_> = url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();
            assert_eq!(form.get("client_id").map(String::as_str),Some("public-client"));
            let (owner, rotated) = if let Some(code) = form.get("code") {
                assert_eq!(form.get("grant_type").map(String::as_str),Some("authorization_code"));
                assert!(form.get("code_verifier").is_some_and(|v|v.len()>=43));
                (code.as_str(),false)
            } else {
                assert_eq!(form.get("grant_type").map(String::as_str),Some("refresh_token"));
                let refresh=form.get("refresh_token").expect("retained refresh body");
                (refresh.strip_suffix("-private-refresh").expect("refresh owner"),true)
            };
            return (200,json!({"access_token":format!("{owner}-private-token{}",if rotated {"-rotated"} else {""}),"refresh_token":format!("{owner}-private-refresh"),"token_type":"Bearer","expires_in":60,"scope":"read"}).to_string());
        }
        let lower=request.to_ascii_lowercase();
        let owner=if lower.contains("authorization: bearer bob-private-token") {"bob"}
            else if lower.contains("authorization: bearer joe-private-token") {"joe"}
            else {return (401,json!({"error":"missing owner credential"}).to_string())};
        let rpc:Value=serde_json::from_str(body).expect("upstream JSON-RPC");
        let result=if rpc["method"]=="tools/list" {json!({"tools":tool_door::tool_listing()})}
            else {json!({"content":[{"type":"text","text":owner}]})};
        (200,json!({"jsonrpc":"2.0","id":rpc["id"],"result":result}).to_string())
    })).await;
    let issuer = format!("https://127.0.0.1:{}", server.port);
    let mut tools = server.section();
    tools["fs"]["upstream_credentials"] = "connection".into();
    tools["fs"]["oauth"]=serde_yaml::to_value(json!({"issuer":issuer,"resource":format!("{issuer}/rpc"),"client_id":"public-client","redirect_uri":"https://client.test/callback","authorization_endpoint":format!("{issuer}/authorize"),"token_endpoint":format!("{issuer}/token"),"scopes":["read"]})).unwrap();
    let rig = server.rig("mcp-custody-owner", tools, &|app| app).await;
    let bob = rig.bound_token();
    let (_, joe) = rig
        .gov
        .mint_signed_async(
            busbar_kernel::governance::NewKeySpec {
                name: "joe".into(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
        .unwrap();
    let joe = rig.bound_token_for(joe.expose(&busbar_kernel::seal::lend()));
    enroll(&rig, &bob, "bob", &issuer).await;
    let (_, foreign) = ask(
        &rig,
        &joe,
        "connections/discover",
        json!({"server":"fs","user":rig.key.id,"client_id":"client-1"}),
    )
    .await;
    assert!(foreign.get("error").is_some(), "unenrolled Joe: {foreign}");
    enroll(&rig, &joe, "joe", &issuer).await;
    for (token, owner) in [(&bob, "bob"), (&joe, "joe")] {
        let (status, discovery) =
            ask(&rig, token, "connections/discover", json!({"server":"fs"})).await;
        assert_eq!(status, 200, "{discovery}");
        assert_eq!(discovery["result"]["discovered"], true, "{discovery}");
        let (status, body) = tool_door::send(&rig.router, Some(token), tool_door::CALL).await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let answer: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(answer["result"]["content"][0]["text"], owner, "{answer}");
    }
    let (status, refresh) = ask(&rig, &bob, "connections/refresh", json!({"server":"fs"})).await;
    assert_eq!(status, 200, "{refresh}");
    assert_eq!(refresh["result"]["revision"], 2, "{refresh}");
    let (status, body) = tool_door::send(&rig.router, Some(&bob), tool_door::CALL).await;
    assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
    let (_, revoke) = ask(&rig, &bob, "connections/revoke", json!({"server":"fs"})).await;
    assert_eq!(revoke["result"]["revoked"], true, "{revoke}");
    let count = std::iter::from_fn(|| server.heard.try_recv().ok()).collect::<Vec<_>>();
    assert!(
        count
            .iter()
            .any(|r| r.contains("bob-private-token-rotated")),
        "rotated host field reached TLS peer"
    );
    let (_, refused) = ask(&rig, &bob, "connections/refresh", json!({"server":"fs"})).await;
    assert!(refused.get("error").is_some(), "revoked refresh: {refused}");
    let (_, body) = tool_door::send(&rig.router, Some(&bob), tool_door::CALL).await;
    let refused: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        refused.get("error").is_some() || refused["result"]["isError"] == true,
        "revoked call: {refused}"
    );
    assert!(
        server.heard.try_recv().is_err(),
        "revoked work must not reach TLS peer"
    );
    let (status, body) = tool_door::send(&rig.router, Some(&joe), tool_door::CALL).await;
    assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
    assert!(String::from_utf8_lossy(&body).contains("joe"));
    server.close().await;
}
