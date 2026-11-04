// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane's vocabulary against the conformance battery: its method names, error code
//! table, metadata keys and revision, read from the battery's own sources (this repo's
//! `testing/mcp-conformance`, moved here from busbar by busbar 7f43d8a777), so a battery
//! that starts sending something new fails HERE rather than in a run someone has to
//! interpret.

use crate::{codec, tool_ops as ops};
use std::path::PathBuf;

/// The battery's own source tree: this repo's `testing/mcp-conformance` (busbar at the pin
/// no longer carries it).
fn battery() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testing/mcp-conformance")
}

/// Every method name the battery's suites and fake peers name.
fn battery_methods() -> Vec<String> {
    let mut found = Vec::new();
    let mut walk = |dir: PathBuf| {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("the battery's {} is readable ({e})", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "mjs") {
                let text = std::fs::read_to_string(&path).expect("a battery source is readable");
                for piece in text.split(['\'', '"', '`']) {
                    if looks_like_a_method(piece) && !found.contains(&piece.to_string()) {
                        found.push(piece.to_string());
                    }
                }
            }
        }
    };
    walk(battery().join("src/suites"));
    walk(battery().join("src/core"));
    walk(battery().join("fakepeer"));
    assert!(
        !found.is_empty(),
        "no method names were read out of the battery"
    );
    found
}

/// Whether a quoted piece of the battery's source is a method name of this protocol.
fn looks_like_a_method(piece: &str) -> bool {
    let heads = [
        "server/",
        "tools/",
        "prompts/",
        "resources/",
        "completion/",
        "tasks/",
        "subscriptions/",
        "notifications/",
        "sampling/",
        "roots/",
        "elicitation/",
    ];
    heads.iter().any(|head| {
        piece.strip_prefix(head).is_some_and(|tail| {
            !tail.is_empty() && tail.split('/').all(|segment| !segment.is_empty())
        })
    }) && !piece.contains(' ')
}

#[test]
fn battery_method_names_are_complete_and_unknown_names_still_reach_the_coverage_gate() {
    assert!(!looks_like_a_method("notifications/"));
    assert!(!looks_like_a_method("notifications//changed"));
    assert!(!looks_like_a_method("tools/call with a space"));
    assert!(looks_like_a_method("notifications/tools/list_changed"));
    assert!(looks_like_a_method(
        "tools/a_new_method_the_plane_must_account_for"
    ));
}

/// Every method the battery sends is one this plane carries, in one of its three roles.
#[test]
fn every_method_the_battery_sends_is_carried() {
    for method in battery_methods() {
        let carried = ops::method_row_for(&method).is_some() || NOTICES.contains(&method.as_str());

        let emitted_only = matches!(
            method.as_str(),
            "notifications/message"
                | "notifications/progress"
                | "notifications/cancelled"
                | "notifications/subscriptions/acknowledged"
        );
        assert!(
            carried || emitted_only,
            "the battery names {method} and this plane neither carries nor emits it"
        );
    }
}

/// How many rows of each role the method table declares, and how many notices this plane knows.
const CLIENT_ROWS: usize = 13;
/// The rows only a paired server may send. See [`CLIENT_ROWS`].
const PROVIDER_ROWS: usize = 3;
/// The notices the battery sends that this plane takes (a notification obliges no answer).
const NOTICES: &[&str] = &[
    "notifications/roots/list_changed",
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
    "notifications/resources/list_changed",
    "notifications/resources/updated",
];

/// The declared method rows of one role.
fn rows_of(sender: ops::Sender) -> Vec<&'static ops::RpcMethodRow> {
    ops::METHODS.iter().filter(|r| r.sender == sender).collect()
}

/// The method table keeps the roles the door serves: how many rows each role has, and every
/// row's class is one the plane declares.
#[test]
fn the_method_table_keeps_its_roles_and_its_declared_classes() {
    assert_eq!(rows_of(ops::Sender::Client).len(), CLIENT_ROWS);
    assert_eq!(rows_of(ops::Sender::Provider).len(), PROVIDER_ROWS);
    for row in ops::METHODS {
        assert!(
            ops::OP_CLASSES.contains(&row.op),
            "{} names the undeclared class {}",
            row.method,
            row.op
        );
    }
}

/// The revision the battery declares is the revision the codec declares.
#[test]
fn the_revision_is_the_codecs_own() {
    let spec = std::fs::read_to_string(battery().join("src/core/spec.mjs"))
        .expect("the battery's own revision is readable");
    assert!(
        spec.contains(codec::PROTOCOL_VERSION),
        "the battery and the codec no longer agree on the revision"
    );
}

/// The battery's own error code table is the one this plane writes from.
#[test]
fn the_error_codes_are_the_batterys_own() {
    let source = std::fs::read_to_string(battery().join("src/core/jsonrpc.mjs"))
        .expect("the battery's own code table is readable");
    for code in [
        busbar_contract::jsonrpc::PARSE_ERROR,
        codec::CODE_INVALID_REQUEST,
        codec::CODE_METHOD_NOT_FOUND,
        codec::CODE_INVALID_PARAMS,
        codec::CODE_INTERNAL,
        codec::CODE_HEADER_MISMATCH,
        codec::CODE_MISSING_CLIENT_CAPABILITY,
        codec::CODE_UNSUPPORTED_PROTOCOL_VERSION,
    ] {
        assert!(
            names_the_number(&source, code),
            "the battery no longer names the code {code}"
        );
    }

    let written = [
        busbar_contract::jsonrpc::PARSE_ERROR,
        codec::CODE_INVALID_REQUEST,
        codec::CODE_METHOD_NOT_FOUND,
        codec::CODE_INVALID_PARAMS,
        codec::CODE_INTERNAL,
        codec::CODE_HEADER_MISMATCH,
        codec::CODE_MISSING_CLIENT_CAPABILITY,
        codec::CODE_UNSUPPORTED_PROTOCOL_VERSION,
        codec::CODE_REFUSED,
        codec::CODE_UPSTREAM_UNAVAILABLE,
    ];
    for retired in &[-32002_i64, -32042] {
        assert!(
            names_the_number(&source, *retired),
            "the battery no longer names the retired code {retired}"
        );
        assert!(!written.contains(retired));
    }
}

/// Whether a source file names EXACTLY this number, rather than merely containing its digits.
fn names_the_number(source: &str, code: i64) -> bool {
    let needle = code.to_string();
    let bytes = source.as_bytes();
    source.match_indices(&needle).any(|(at, _)| {
        let before_ok = at == 0 || !bytes[at - 1].is_ascii_digit();
        let after = at + needle.len();
        let after_ok = after == bytes.len() || !bytes[after].is_ascii_digit();
        before_ok && after_ok
    })
}

/// The metadata keys are the ones the battery actually sends.
#[test]
fn the_metadata_keys_are_the_batterys_own() {
    let source = std::fs::read_to_string(battery().join("src/core/jsonrpc.mjs"))
        .expect("the battery's own key table is readable");
    for key in [
        codec::META_PROTOCOL_VERSION,
        codec::META_CLIENT_CAPABILITIES,
        "progressToken",
    ] {
        assert!(source.contains(key), "the battery no longer sends {key}");
    }
}
