// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE APPROVAL DIGEST, PINNED: the plane's own [`tool_digest`] (name, description and
//! canonical input schema, each length-framed) over two fixed inputs, to the constants
//! every other reader of the digest asserts.

use crate::trust::tool_digest;
use serde_json::json;

#[test]
fn the_digest_of_the_cross_language_pin_fixture_is_pinned() {
    let schema = json!({
        "type": "object",
        "properties": { "a": { "type": "string" }, "n": { "type": "integer" } },
        "required": ["a"],
        "additionalProperties": false,
    });
    assert_eq!(
        tool_digest("pin", "the cross-language digest pin", &schema),
        "sha256:9a5b7d6295550c8e7a74b6c3068639c5497d2fc0856d554d2ce8cee17f30fd5d"
    );
}

#[test]
fn the_black_box_cases_approve_the_digest_of_the_tool_their_upstream_serves() {
    let schema = json!({
        "type": "object",
        "properties": { "label": { "type": "string" } },
        "additionalProperties": false,
    });
    assert_eq!(
        tool_digest("ping", "Returns the label it was given.", &schema),
        "sha256:7939d1408e8fc1ac98025ed864c53703091d173e733b1d5c6156f14732da75b0"
    );
}
