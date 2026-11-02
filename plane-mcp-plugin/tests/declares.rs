// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Checks that the Statement and release recipe use the same declares document.

/// The declaration the release signs: the `declares:` of this plugin's entry in busbar's
fn signed() -> (String, Vec<u8>) {
    const NAMED: &str = "plane-mcp/declares.json";
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let yaml = std::env::var("BUSBAR_PLUGINS_YAML")
        .unwrap_or_else(|_| format!("{root}/../busbar/plugins.yaml"));
    let named = match std::fs::read_to_string(yaml) {
        Ok(yaml) => yaml
            .split("\n  - repo: ")
            .find(|e| {
                e.trim_start_matches("- repo: ")
                    .starts_with("busbar-plane-mcp\n")
            })
            .expect("plugins.yaml has an entry for this repo")
            .lines()
            .find_map(|l| l.trim().strip_prefix("declares:"))
            .map(|v| v.trim().trim_matches('"').to_string())
            .expect("the entry names its declares file"),
        Err(_) => NAMED.to_string(),
    };
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
    let door: busbar_contract::abi::mechanism::door::DoorFn = busbar_plane_mcp::door;
    busbar_plugin_loader::dispatch::LoadedDoor::from(door)
}
