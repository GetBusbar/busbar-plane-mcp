// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DECLARES ITSELF ONCE, AND THE DECLARATION RIDES THE STATEMENT (ARCHITECT ruling
//! 2026-10-21; BUSBAR-1.6.0.md l.246; THE DESIGN: "Each fact is declared once"; "Compiled-in =
//! dropped-in through the same table ... NOTHING CHANGES about the plugin itself").
//!
//! A busbar build that links the plane reads its `declares` off the door's Statement
//! (`EXT_DECLARES`); the release signs the file its `declares_file:` names into the dropped-in
//! plane's manifest. Both must be the same document, byte for byte, or a dropped-in plane states
//! other facts than the linked one: the breaker posture and the diagnostic codes the linked door
//! carries, which the signed file once lacked.

/// The declaration the release signs: the `declares_file:` its workflow names, and its bytes read
/// from the repo.
fn signed() -> (String, Vec<u8>) {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let release = std::fs::read_to_string(format!("{root}/.github/workflows/release.yml"))
        .expect("the release workflow reads");
    let named = release
        .lines()
        .find_map(|l| l.trim().strip_prefix("declares_file:"))
        .map(|v| v.trim().trim_matches('"').to_string())
        .expect("the release names its declares_file");
    let bytes = std::fs::read(format!("{root}/{named}")).expect("the signed declaration reads");
    (named, bytes)
}

/// The `declares` document the door's Statement states, read back as the loader reads a linked row.
fn stated() -> Vec<u8> {
    let row = busbar_plugin_loader::dispatch::LinkedRow::of_loaded(loaded_door())
        .expect("the linked door states its Statement");
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("the Statement renders");
    busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes)
        .expect("the Statement states a declares document")
        .to_vec()
}

#[test]
fn the_statement_states_the_whole_declares_document() {
    assert_eq!(
        busbar_contract::abi::mechanism::extensions::declares(
            &busbar_contract::abi::mechanism::rendering::read(
                &busbar_plugin_loader::dispatch::LinkedRow::of_loaded(loaded_door())
                    .unwrap()
                    .statement
            )
            .unwrap()
            .extensions
            .bytes
        ),
        Some(&include_bytes!("../../plane-mcp/declares.json")[..]),
    );
}

#[test]
fn the_signed_declaration_is_the_one_the_door_states() {
    let (named, signed) = signed();
    assert_eq!(
        named, "plane-mcp/declares.json",
        "the release signs another file than the one the door's Statement carries"
    );
    assert!(
        signed == stated(),
        "the release signs `{named}`, which is not the declaration the door's Statement states: a \
         dropped-in plane would state other facts than the linked one"
    );
}

#[test]
fn the_signed_declaration_states_the_breaker_and_the_diagnostics_and_no_contract_abi_range() {
    let (_, signed) = signed();
    let doc: serde_json::Value = serde_json::from_slice(&signed).expect("the declaration is JSON");
    assert!(
        doc.get("contract_abi").is_none(),
        "the signed declaration states a contract_abi range; a plugin declares its kind's ABI \
         version, never a range"
    );
    assert!(
        doc.get("breaker").is_some() && doc.get("diagnostics").is_some(),
        "the signed declaration does not state the plane's breaker posture and its diagnostics"
    );
}

/// This plugin's own door, named for the loader.
fn loaded_door() -> busbar_plugin_loader::dispatch::LoadedDoor {
    // This crate's sealed door function (`&'static Door`), taken by the loader's safe conversion.
    let door: busbar_contract::abi::mechanism::door::DoorFn = busbar_plane_mcp::door;
    busbar_plugin_loader::dispatch::LoadedDoor::from(door)
}
