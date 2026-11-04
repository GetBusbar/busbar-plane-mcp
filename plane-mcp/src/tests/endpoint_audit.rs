// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Audit regressions for the `mcp:` endpoint block's boot refusals.

use super::{McpCfg, McpCfgError, McpResource};

fn with_issuer(issuer: &str) -> McpCfg {
    McpCfg {
        canonical_uri: "https://gateway.example.com/mcp".to_string(),
        authorization_servers: vec![issuer.to_string()],
        scopes_supported: Vec::new(),
        allowed_origins: Vec::new(),
    }
}

/// An RFC 8414 issuer identifier carries no query and no fragment: an entry that does is refused at
/// boot with its own diagnosis, instead of being published as metadata no client can resolve.
#[test]
fn an_issuer_with_a_query_or_fragment_is_refused_at_boot() {
    for issuer in [
        "https://login.example.com/?tenant=a#x",
        "https://login.example.com?tenant=a",
        "https://login.example.com/realm#x",
        "https://login.example.com#x",
    ] {
        let err = McpResource::from_cfg(&with_issuer(issuer)).expect_err(issuer);
        assert_eq!(
            err,
            McpCfgError::AuthorizationServerHasQueryOrFragment(issuer.to_string()),
            "`{issuer}`"
        );
        let text = err.to_string();
        assert!(text.contains(issuer), "the refusal names the entry: {text}");
        assert!(text.contains("query or fragment"), "{text}");
    }
}

/// A plain issuer, with or without a path, still boots and is published trimmed.
#[test]
fn a_plain_issuer_still_boots() {
    for issuer in [
        "https://login.example.com",
        " https://login.example.com/realms/a ",
        "http://127.0.0.1:8080",
    ] {
        let r = McpResource::from_cfg(&with_issuer(issuer)).expect(issuer);
        assert_eq!(r.authorization_servers(), [issuer.trim().to_string()]);
    }
}

#[test]
fn invalid_authorities_and_embedded_credentials_are_refused() {
    for uri in [
        "https://user:pass@h.example/mcp",
        "https://bad host/mcp",
        "https://h.example:99999/mcp",
        "https://[bad]/mcp",
    ] {
        let mut cfg = with_issuer("https://login.example.com");
        cfg.canonical_uri = uri.into();
        assert!(McpResource::from_cfg(&cfg).is_err(), "{uri}");
    }
}
