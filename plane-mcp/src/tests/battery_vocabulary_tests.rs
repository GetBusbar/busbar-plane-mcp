// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane's vocabulary against the conformance battery: its method names, error code table,
//! metadata keys and revision, read from the battery's own sources at the pin (`BUSBAR_CHECKOUT`, a
//! checkout of GetBusbar/busbar at `.busbar-ref`, which plugin-ci exports), so a battery that starts
//! sending something new fails HERE rather than in a run someone has to interpret.
//!
//! Moved in from the plugin crate's `tests/door_witness.rs` when this crate's only public item
//! became `door`: these tests read the plane's own tables. The door driven both ways stays there.

use crate::{codec, tool_ops as ops};
use std::path::PathBuf;

/// The battery's own source tree: busbar's `testing/mcp-conformance` at the pin (`BUSBAR_CHECKOUT`).
/// An unset variable is a failure, never a skip: these tests read the battery or prove nothing.
fn battery() -> PathBuf {
    let busbar = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the battery is busbar's testing/mcp-conformance at .busbar-ref \
         (plugin-ci exports it)",
    );
    PathBuf::from(busbar).join("testing/mcp-conformance")
}

/// Every method name the battery's suites and fake peers name.
///
/// Read out of the battery rather than restated, which is the whole point: a battery that starts
/// sending a method this plane does not carry must fail at build time, not in a run.
fn battery_methods() -> Vec<String> {
    let mut found = Vec::new();
    let mut walk = |dir: PathBuf| {
        // A directory that is not there is NOT "no methods here". The three below are the three
        // places the battery keeps the names this plane is checked against, and a missing one used
        // to return quietly: the surviving two still filled `found`, the non-empty floor below
        // still held, and the coverage this test claims silently shrank to whatever was left. If
        // the battery moves a directory, that must be a red here rather than a smaller test.
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("the battery's {} is readable ({e})", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "mjs") {
                let text = std::fs::read_to_string(&path).expect("a battery source is readable");
                for piece in text.split('\'').skip(1).step_by(2) {
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
    heads.iter().any(|h| piece.starts_with(h)) && !piece.contains(' ')
}

/// Every method the battery sends is one this plane carries, in one of its three roles.
#[test]
fn every_method_the_battery_sends_is_carried() {
    for method in battery_methods() {
        let carried = ops::method_row_for(&method).is_some() || NOTICES.contains(&method.as_str());
        // The battery names three notices this node emits rather than receives, and one deliberate
        // nonsense name. Everything else it names, it sends.
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
///
/// Every loop below is a FILTER over a declared table, so a table that lost the rows a loop selects
/// would leave that loop iterating zero times — and a conformance test that drove nothing reports
/// `ok`. These three numbers are what turns "the loop found nothing" into a failure. Raise one
/// deliberately, in the commit that adds the row.
const CLIENT_ROWS: usize = 13;
/// The rows only a paired server may send. See [`CLIENT_ROWS`].
const PROVIDER_ROWS: usize = 3;
/// The notices the battery sends that this plane takes (a notification obliges no answer).
const NOTICES: &[&str] = &[
    "notifications/roots/list_changed",
    "notifications/tools/list_changed",
    "notifications/resources/updated",
];

/// The declared method rows of one role.
fn rows_of(sender: ops::Sender) -> Vec<&'static ops::RpcMethodRow> {
    ops::METHODS.iter().filter(|r| r.sender == sender).collect()
}

/// The method table keeps the roles the door serves: how many rows each role has, and every row's
/// class is one the plane declares.
///
/// The surviving, plane-free half of what the decode-driven tests asserted (finding 12): the door
/// reads this same table (`ops::method_row_for`), so the table is what is pinned here.
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
    // And the two the battery calls RETIRED are two this plane cannot write.
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
///
/// A bare substring search answers yes for a code that is a prefix of a longer one — `-32700` is
/// inside `-327001` — and yes for the digits of a code that appears in a version string, a byte
/// count or a comment. Either way the check would report the battery still names a code it had
/// dropped. Requiring a non-digit on each side is what makes the match the number itself.
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
