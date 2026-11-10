// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn key(user: &str) -> ConnectionKey {
    ConnectionKey {
        user: user.into(),
        upstream: "calendar".into(),
        downstream_client: "assistant".into(),
    }
}

fn binding() -> AuthorizationBinding {
    AuthorizationBinding {
        issuer: "https://login.example".into(),
        resource: "https://calendar.example/mcp".into(),
        redirect_uri: "https://busbar.example/oauth/callback".into(),
        client_id: "busbar".into(),
    }
}

fn consent(connections: &mut Connections, key: &ConnectionKey) {
    connections
        .grant_consent(
            key.clone(),
            binding(),
            BTreeSet::from(["calendar.read".into()]),
        )
        .unwrap();
}

fn authorize(connections: &mut Connections, key: &ConnectionKey) {
    consent(connections, key);
    let request = connections
        .begin_authorization(key, [11; 32], [22; 32], 10, 100)
        .unwrap();
    let permit = connections
        .consume_callback(key, &request.state, &binding(), 20)
        .unwrap();
    connections.complete_authorization(permit, 30, 300).unwrap();
}

#[test]
fn bob_and_joe_consent_discovery_and_sessions_are_isolated() {
    let mut connections = Connections::new(4);
    let bob = key("bob");
    let joe = key("joe");
    authorize(&mut connections, &bob);
    assert_eq!(
        connections.discovery_key(&joe, 40),
        Err(Error::ConsentRequired)
    );
    assert!(matches!(
        connections.begin_authorization(&joe, [1; 32], [2; 32], 40, 100),
        Err(Error::ConsentRequired)
    ));
    authorize(&mut connections, &joe);
    let bob_partition = connections.discovery_key(&bob, 40).unwrap();
    let joe_partition = connections.discovery_key(&joe, 40).unwrap();
    assert_ne!(bob_partition, joe_partition);
    assert_ne!(bob_partition.session_key(), joe_partition.session_key());
    let another_client = ConnectionKey {
        downstream_client: "other-assistant".into(),
        ..bob.clone()
    };
    assert_eq!(
        connections.discovery_key(&another_client, 40),
        Err(Error::ConsentRequired)
    );
    let another_upstream = ConnectionKey {
        upstream: "mail".into(),
        ..bob.clone()
    };
    assert_eq!(
        connections.discovery_key(&another_upstream, 40),
        Err(Error::ConsentRequired)
    );
    connections.revoke(&bob).unwrap();
    assert_eq!(
        connections.discovery_key(&bob, 40),
        Err(Error::ConsentRequired)
    );
    assert_eq!(connections.discovery_key(&joe, 40).unwrap(), joe_partition);
}

#[test]
fn callback_requires_exact_tuple_state_and_all_binding_fields_then_is_consumed_once() {
    let mut connections = Connections::new(2);
    let bob = key("bob");
    let joe = key("joe");
    consent(&mut connections, &bob);
    consent(&mut connections, &joe);
    let request = connections
        .begin_authorization(&bob, [1; 32], [2; 32], 10, 100)
        .unwrap();
    let joe_request = connections
        .begin_authorization(&joe, [3; 32], [4; 32], 10, 100)
        .unwrap();
    assert!(matches!(
        connections.consume_callback(&joe, &request.state, &binding(), 20),
        Err(Error::InvalidState)
    ));
    assert!(matches!(
        connections.consume_callback(&bob, &joe_request.state, &binding(), 20),
        Err(Error::InvalidState)
    ));
    let mut changed = binding();
    changed.issuer.push('/');
    let mut resource = binding();
    resource.resource.push('/');
    let mut redirect = binding();
    redirect.redirect_uri.push('/');
    let mut client = binding();
    client.client_id.push('2');
    for mismatch in [changed, resource, redirect, client] {
        assert!(matches!(
            connections.consume_callback(&bob, &request.state, &mismatch, 20),
            Err(Error::BindingMismatch)
        ));
    }
    let permit = connections
        .consume_callback(&bob, &request.state, &binding(), 20)
        .unwrap();
    assert!(matches!(
        connections.consume_callback(&bob, &request.state, &binding(), 20),
        Err(Error::InvalidState)
    ));
    assert_eq!(permit.verifier(), URL_SAFE_NO_PAD.encode([2; 32]));
    assert_eq!(permit.binding(), &binding());
    assert_eq!(
        request.code_challenge,
        URL_SAFE_NO_PAD.encode(sha256(permit.verifier().as_bytes()))
    );
    connections
        .complete_authorization(permit, 30, 1000)
        .unwrap();
}

#[test]
fn s256_matches_rfc7636_vector() {
    // RFC 7636 Appendix B's 32 bytes, encoded into the expected 43-character verifier.
    let entropy = URL_SAFE_NO_PAD
        .decode("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        .unwrap();
    let mut connections = Connections::new(1);
    let bob = key("bob");
    consent(&mut connections, &bob);
    let request = connections
        .begin_authorization(&bob, [1; 32], entropy.try_into().unwrap(), 10, 100)
        .unwrap();
    assert_eq!(
        request.code_challenge,
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn revoked_or_reconsented_exchange_cannot_install_a_late_response() {
    for revoke in [false, true] {
        let mut connections = Connections::new(1);
        let bob = key("bob");
        consent(&mut connections, &bob);
        let request = connections
            .begin_authorization(&bob, [1; 32], [2; 32], 10, 100)
            .unwrap();
        let permit = connections
            .consume_callback(&bob, &request.state, &binding(), 20)
            .unwrap();
        if revoke {
            connections.revoke(&bob).unwrap();
        } else {
            consent(&mut connections, &bob);
        }
        assert_eq!(
            connections.complete_authorization(permit, 30, 1000),
            Err(Error::StaleCompletion)
        );
        assert!(connections.discovery_key(&bob, 40).is_err());
    }
}

#[test]
fn refresh_rotation_invalidates_cache_and_revocation_refuses_late_completion_or_failure() {
    let mut connections = Connections::new(1);
    let bob = key("bob");
    authorize(&mut connections, &bob);
    let before = connections.discovery_key(&bob, 40).unwrap();
    let refresh = connections.begin_refresh(&bob, 40, 100).unwrap();
    assert!(matches!(
        connections.begin_refresh(&bob, 40, 100),
        Err(Error::NotActive)
    ));
    assert_eq!(connections.discovery_key(&bob, 40).unwrap(), before);
    connections.complete_refresh(refresh, 50, 500).unwrap();
    assert_ne!(connections.discovery_key(&bob, 50).unwrap(), before);
    let refresh = connections.begin_refresh(&bob, 60, 100).unwrap();
    connections.revoke(&bob).unwrap();
    assert_eq!(
        connections.complete_refresh(refresh, 70, 700),
        Err(Error::StaleCompletion)
    );
    assert_eq!(
        connections.discovery_key(&bob, 70),
        Err(Error::ConsentRequired)
    );
    authorize(&mut connections, &bob);
    let refresh = connections.begin_refresh(&bob, 60, 100).unwrap();
    connections.revoke(&bob).unwrap();
    assert_eq!(
        connections.fail_refresh(refresh),
        Err(Error::StaleCompletion)
    );
}

#[test]
fn callback_exchange_access_and_refresh_expiry_fail_closed_at_deadline() {
    let mut connections = Connections::new(1);
    let bob = key("bob");
    consent(&mut connections, &bob);
    let request = connections
        .begin_authorization(&bob, [1; 32], [2; 32], 10, 100)
        .unwrap();
    assert!(matches!(
        connections.consume_callback(&bob, &request.state, &binding(), 100),
        Err(Error::Expired)
    ));
    assert!(matches!(
        connections.consume_callback(&bob, &request.state, &binding(), 101),
        Err(Error::InvalidState)
    ));
    let request = connections
        .begin_authorization(&bob, [1; 32], [2; 32], 10, 100)
        .unwrap();
    let permit = connections
        .consume_callback(&bob, &request.state, &binding(), 20)
        .unwrap();
    assert_eq!(
        connections.complete_authorization(permit, 100, 200),
        Err(Error::Expired)
    );
    authorize(&mut connections, &bob);
    assert_eq!(connections.discovery_key(&bob, 300), Err(Error::Expired));
    // An expired access token may still be refreshed, but late refresh results cannot be used.
    let refresh = connections.begin_refresh(&bob, 300, 400).unwrap();
    assert_eq!(
        connections.complete_refresh(refresh, 400, 500),
        Err(Error::Expired)
    );
    assert_eq!(connections.discovery_key(&bob, 400), Err(Error::Expired));
    let retry = connections.begin_refresh(&bob, 400, 500).unwrap();
    connections.complete_refresh(retry, 450, 600).unwrap();
    assert!(connections.discovery_key(&bob, 450).is_ok());
}

#[test]
fn repeated_entropy_does_not_reanimate_old_state_and_metadata_contains_no_secrets() {
    let mut connections = Connections::new(1);
    let bob = key("bob");
    consent(&mut connections, &bob);
    let first = connections
        .begin_authorization(&bob, [1; 32], [2; 32], 10, 100)
        .unwrap();
    let second = connections
        .begin_authorization(&bob, [1; 32], [2; 32], 10, 100)
        .unwrap();
    assert_ne!(first.state, second.state);
    assert!(matches!(
        connections.consume_callback(&bob, &first.state, &binding(), 20),
        Err(Error::InvalidState)
    ));
    let record = serde_json::to_string(connections.get(&bob).unwrap()).unwrap();
    assert!(!record.contains(&second.state));
    assert!(!record.contains(&URL_SAFE_NO_PAD.encode([2; 32])));
    assert!(!record.contains("token"));
}

#[test]
fn invalid_consent_and_capacity_are_refused_without_replacing_existing_consent() {
    let mut connections = Connections::new(1);
    let bob = key("bob");
    consent(&mut connections, &bob);
    let before = connections.get(&bob).unwrap().clone();
    for issuer in [
        "http://login.example",
        "https://login.example/#fragment",
        "https://login.example/?issuer=x",
        "https://user:pass@login.example",
    ] {
        let binding = AuthorizationBinding {
            issuer: issuer.into(),
            ..binding()
        };
        assert_eq!(
            connections.grant_consent(bob.clone(), binding, BTreeSet::new()),
            Err(Error::BindingMismatch)
        );
    }
    assert_eq!(connections.get(&bob).unwrap(), &before);
    assert_eq!(
        connections.grant_consent(key("joe"), binding(), BTreeSet::new()),
        Err(Error::Capacity)
    );
}

#[test]
fn host_revision_and_public_enrollment_identity_survive_revoke_reconsent() {
    let mut connections = Connections::new(1);
    let bob = key("bob");
    consent(&mut connections, &bob);
    assert_eq!(connections.get(&bob).unwrap().revision, 0);
    authorize(&mut connections, &bob);
    let active = connections.get(&bob).unwrap().clone();
    assert_eq!(active.revision, 1);
    let old_partition = connections.discovery_key(&bob, 40).unwrap();
    let revoked = connections.revoke(&bob).unwrap();
    assert_eq!(revoked.id, active.id);
    assert_eq!(revoked.revision, 2);
    authorize(&mut connections, &bob);
    let reconsented = connections.get(&bob).unwrap();
    assert_eq!(reconsented.revision, 1);
    assert_ne!(reconsented.id, active.id);
    assert_ne!(connections.discovery_key(&bob, 40).unwrap(), old_partition);
}

fn connection_config() -> serde_json::Value {
    serde_json::json!({"calendar": {
        "url":"https://calendar.example/mcp", "pin":{"mechanism":"unpinned"},
        "upstream_credentials":"connection",
        "oauth": {
            "issuer":"https://login.example", "resource":"https://calendar.example/",
            "client_id":"busbar", "redirect_uri":"https://busbar.example/oauth/callback",
            "authorization_endpoint":"https://login.example/authorize",
            "token_endpoint":"https://login.example/token", "scopes":["calendar.read"]
        }
    }})
}

#[test]
fn connection_config_and_schema_require_real_public_client_registration_and_honor_overrides() {
    use crate::tools_config::ToolsCfg;
    use busbar_contract::config::UpstreamCreds;
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../settings.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let explicit = connection_config();
    let mut inherited = explicit.clone();
    inherited["calendar"]
        .as_object_mut()
        .unwrap()
        .remove("upstream_credentials");
    inherited["upstream_credentials"] = "connection".into();
    let mut overridden = inherited.clone();
    overridden["calendar"]["upstream_credentials"] = "own".into();
    overridden["calendar"]
        .as_object_mut()
        .unwrap()
        .remove("oauth");
    for source in [explicit, inherited, overridden] {
        let config: ToolsCfg = serde_json::from_value(source.clone()).unwrap();
        assert!(validator.is_valid(&source), "{source}");
        let effective = config.effective_upstream_credentials("calendar");
        assert!(matches!(
            effective,
            Some(UpstreamCreds::Connection | UpstreamCreds::Own)
        ));
    }
    let mut absent = connection_config();
    absent["calendar"].as_object_mut().unwrap().remove("oauth");
    let mut wrong_mode = connection_config();
    wrong_mode["calendar"]["upstream_credentials"] = "own".into();
    let mut implicit_own = connection_config();
    implicit_own["calendar"]
        .as_object_mut()
        .unwrap()
        .remove("upstream_credentials");
    let mut plain_http = connection_config();
    plain_http["calendar"]["url"] = "http://calendar.example/mcp".into();
    let mut exchange = connection_config();
    exchange["calendar"]["token_exchange"] = serde_json::json!({"token_url":"https://login.example/token", "subject_token":{"module":"vault"}});
    exchange["calendar"]["aud"] = "https://calendar.example/".into();
    assert!(serde_json::from_value::<ToolsCfg>(exchange.clone())
        .unwrap_err()
        .to_string()
        .contains("cannot be combined"));
    let mut bad_issuer = connection_config();
    bad_issuer["calendar"]["oauth"]["issuer"] = "https://login.example/?confused=yes".into();
    let mut bad_scope = connection_config();
    bad_scope["calendar"]["oauth"]["scopes"] = serde_json::json!(["calendar.read calendar.write"]);
    let mut secret = connection_config();
    secret["calendar"]["oauth"]["client_secret"] = "not-supported".into();
    let stdio = serde_json::json!({"upstream_credentials":"connection", "local": {
        "transport":"stdio", "command":"/bin/mcp", "pin":{"mechanism":"unpinned"}
    }});
    for source in [
        absent,
        wrong_mode,
        implicit_own,
        plain_http,
        exchange,
        bad_issuer,
        bad_scope,
        secret,
        stdio,
    ] {
        assert!(
            serde_json::from_value::<ToolsCfg>(source.clone()).is_err(),
            "accepted config: {source}"
        );
        assert!(!validator.is_valid(&source), "accepted schema: {source}");
    }
    let mut conflicting_audience = connection_config();
    conflicting_audience["calendar"]["aud"] = "https://other.example/".into();
    assert!(serde_json::from_value::<ToolsCfg>(conflicting_audience)
        .unwrap_err()
        .to_string()
        .contains("must exactly match"));
}
