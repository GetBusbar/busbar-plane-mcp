// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLOSED SET OF ISSUED METHODS, checked against the GENERATED matrix rather than against a
//! list in a comment.
//!
//! The failure this file exists to catch is the one `tests/method_coverage.rs` was written for, one
//! level down: a column of the matrix whose contents are a property of its call sites drifts from
//! the specification silently, because an absent verb and a considered-and-inapplicable verb look
//! identical in source. The variants production constructs are compared against busbar's
//! `qa/method-inventory.json` by `src/tests/method_inventory_tests.rs` (it reads busbar at the pin);
//! this file holds the builder's own shape over [`UpstreamVerb::all`].

use super::super::verb::UpstreamVerb;

/// `all()` IS ONE INSTANCE OF EVERY VARIANT, not most of them.
///
/// Without this, a variant added to the enum and forgotten in `all()` would narrow every test above
/// and below silently — the exact shape of the four batteries this release found reporting green
/// over a shrinking denominator.
#[test]
fn every_variant_appears_in_all_exactly_once() {
    let all = UpstreamVerb::all();
    let mut names: Vec<&str> = all.iter().map(UpstreamVerb::method).collect();
    let before = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        before,
        names.len(),
        "`UpstreamVerb::all()` lists a method twice, which would double-count the column"
    );
}

/// A NOTIFICATION HAS NO `id` AND A REQUEST DOES, and it is the VARIANT that decides.
///
/// This is the property `McpWire::notify` exists for. A notification carrying an `id` is a request,
/// and a peer would be right to answer it — which on a stdio child puts an unexpected line on the
/// stream and desynchronises every later call.
#[test]
fn notifications_carry_no_id_and_requests_do() {
    let mut notifications = 0;
    for verb in UpstreamVerb::all() {
        let request = verb.build("https://u.example.com/mcp", 42, None);
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("the body is JSON");
        assert_eq!(
            body["jsonrpc"],
            "2.0",
            "{} must carry the JSON-RPC version",
            verb.method()
        );
        assert_eq!(
            body["method"],
            verb.method(),
            "the body's method must be the verb's own"
        );
        if verb.is_notification() {
            notifications += 1;
            assert!(
                body.get("id").is_none(),
                "{} is a notification and must carry NO `id` member: {body}",
                verb.method()
            );
        } else {
            assert_eq!(
                body["id"],
                42,
                "{} is a request and must carry the id it was built with: {body}",
                verb.method()
            );
        }
    }
    assert_eq!(
        notifications, 1,
        "`notifications/initialized`, the one notification busbar issues through this builder, \
         must be classified as one; a request misclassified as one would never be answered, and a \
         notification misclassified as a request hangs the leg"
    );
}

/// EVERY VERB CARRIES `params._meta`, which this revision REQUIRES on every request.
///
/// Asserted over the whole set rather than on a sample, because the failure mode is exactly one verb
/// forgetting it — and busbar's own ingress answers `-32602` to a request whose `_meta` is missing,
/// so a verb that omitted it would be one busbar could not itself accept.
#[test]
fn every_verb_carries_the_required_meta() {
    for verb in UpstreamVerb::all() {
        let request = verb.build("https://u.example.com/mcp", 1, None);
        let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json");
        let meta = &body["params"]["_meta"];
        assert!(
            meta.is_object(),
            "{} must carry `params._meta`: {body}",
            verb.method()
        );
        assert_eq!(
            meta["io.modelcontextprotocol/protocolVersion"],
            crate::codec::PROTOCOL_VERSION,
            "{} must state the protocol revision in `_meta`",
            verb.method()
        );
    }
}

/// THE MIRRORED `Mcp-Method` HEADER IS THE BODY'S OWN METHOD, on every verb.
///
/// A mirrored header whose value is computed twice is a mirrored header that can differ, which is
/// the request-smuggling primitive the mirroring exists to close.
#[test]
fn the_mirrored_method_header_matches_the_body() {
    for verb in UpstreamVerb::all() {
        let request = verb.build("https://u.example.com/mcp", 1, None);
        let sent: Vec<&str> = request
            .headers
            .iter()
            .filter(|(n, _)| n == "mcp-method")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(
            sent,
            vec![verb.method()],
            "{} must mirror its method in exactly one `Mcp-Method` header",
            verb.method()
        );
    }
}

/// THE CREDENTIAL IS SENT WHEN THERE IS ONE AND NEVER OTHERWISE.
///
/// The negative half is the one that matters: a verb that attached a bearer unconditionally would
/// send an empty `Authorization: Bearer ` to a public upstream, which is a malformed credential
/// header rather than an absent one.
#[test]
fn the_credential_is_present_only_when_one_was_planned() {
    for verb in UpstreamVerb::all() {
        let bare = verb.build("https://u.example.com/mcp", 1, None);
        assert!(
            !bare.headers.iter().any(|(n, _)| n == "authorization"),
            "{} must send no `Authorization` when no credential was planned",
            verb.method()
        );
        let credentialled = verb.build("https://u.example.com/mcp", 1, Some("tok"));
        assert!(
            credentialled
                .headers
                .iter()
                .any(|(n, v)| n == "authorization" && v == "Bearer tok"),
            "{} must send the planned credential",
            verb.method()
        );
    }
}
