// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE APPROVAL DIGEST, PINNED: the plane's own [`tool_digest`] (name, description and canonical
//! input schema, each length-framed) over two fixed inputs, to the constants every other reader of
//! the digest asserts.
//!
//! - The cross-language pin fixture: busbar's `scripts/mcp-subject/tool-digest.mjs` asserts the same
//!   constant (`PIN_EXPECTED`). A drift on either side lets an operator approve a digest one side
//!   computes and the other never matches.
//! - The `ping` tool this repo's black-box cases approve (`tests/blackbox/*_live_approval_*.json`,
//!   `an_approved_tool_serves_through_the_real_binary.json`): their `schema_hash` is this value, so
//!   the cases approve exactly what the plane computes for the tool their upstream serves.
//!
//! Moved here from busbar's `crates/busbar/tests/qa_mcp_integrity.rs`, where the same constant was
//! asserted against a re-implementation of the digest in the test itself; here it is the plane's.

use busbar_plane_mcp::trust::tool_digest;
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
