// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DECLARES ITSELF ONCE (THE DESIGN: "Each fact is declared once"; "Compiled-in =
//! dropped-in through the same table ... NOTHING CHANGES about the plugin itself").
//!
//! A busbar build that links the plane reads `busbar_plane_mcp::DECLARES`; the release signs the
//! file its `declares_file:` names into the dropped-in plane's manifest. Both must be the same
//! document, or a dropped-in plane loses the breaker posture and the diagnostic codes the linked one
//! states.

/// The declaration the release packs: the `declares_file:` its workflow names, read from the repo.
fn packed() -> (String, String) {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let release = std::fs::read_to_string(format!("{root}/.github/workflows/release.yml"))
        .expect("the release workflow reads");
    let named = release
        .lines()
        .find_map(|l| l.trim().strip_prefix("declares_file:"))
        .map(|v| v.trim().trim_matches('"').to_string())
        .expect("the release names its declares_file");
    let text = std::fs::read_to_string(format!("{root}/{named}"))
        .expect("the packed declaration reads");
    (named, text)
}

#[test]
fn the_packed_declaration_is_the_linked_one() {
    let (named, text) = packed();
    assert_eq!(
        text,
        busbar_plane_mcp::DECLARES,
        "the release packs `{named}`, which is not the declaration a linked build reads \
         (busbar_plane_mcp::DECLARES): a dropped-in plane would state other facts"
    );
}

#[test]
fn the_packed_declaration_states_no_contract_abi_range() {
    let (_, text) = packed();
    let doc: serde_json::Value = serde_json::from_str(&text).expect("the declaration is JSON");
    assert!(
        doc.get("contract_abi").is_none(),
        "the packed declaration states a contract_abi range; a plugin declares its kind's ABI \
         version, never a range"
    );
    assert!(
        doc.get("breaker").is_some() && doc.get("diagnostics").is_some(),
        "the packed declaration does not state the plane's breaker posture and its diagnostics"
    );
}
