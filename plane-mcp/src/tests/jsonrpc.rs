// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `jsonrpc.rs`.

use super::{CODES, RETIRED_CODES};

/// The serializer writes members in sorted order (this lock builds `serde_json` without
/// `preserve_order`): a value parsed and printed again does NOT keep the bytes it came in, which is
/// why an answer relayed byte for byte is never re-encoded.
#[test]
fn the_serializer_writes_members_in_sorted_order() {
    let v = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
    assert_eq!(
        serde_json::to_string(&v).unwrap(),
        r#"{"id":1,"jsonrpc":"2.0","result":{}}"#
    );
}

/// This plane writes none of the codes the current revision retired.
#[test]
fn no_retired_code_is_writable() {
    for retired in RETIRED_CODES {
        assert!(
            !CODES.contains(retired),
            "the plane can write the retired code {retired}"
        );
    }
}
