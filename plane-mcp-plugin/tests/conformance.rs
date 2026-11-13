// SPDX-License-Identifier: Apache-2.0
//! MCP's actual host composition; product script migration is tracked in assertion-migration.json.
#[path = "support/mcp_network.rs"]
mod mcp_network;
fn inputs() -> &'static str {
    static INPUTS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    INPUTS.get_or_init(|| {
        let template = include_str!("conformance.json");
        let marker = "__MCP_CONFORMANCE_PEER_KEY_PIN__";
        assert_eq!(template.matches(marker).count(), 2);
        assert_eq!(template.matches("__MCP_CONFORMANCE_CA_PEM__").count(), 2);
        // The credential listing and both child `env` blocks carry the same canary.
        let canary = "__MCP_CONFORMANCE_CHILD_ENV_CANARY__";
        assert_eq!(template.matches(canary).count(), 3);
        template
            .replace(canary, &child_env_canary())
            .replace(marker, &mcp_network::peer_key_pin())
            .replace("localhost:56712", mcp_network::authority())
            .replace(
                "\"__MCP_CONFORMANCE_CA_PEM__\"",
                &serde_json::to_string(mcp_network::anchors())
                    .expect("the actual public TLS root serialises"),
            )
    })
}

/// The child-environment canary, minted per run so no credential-shaped literal lives in source:
/// `mcp-child-env-canary-<64 random bits as hex>` (only `[a-z0-9-]`, so every spelling the
/// scrubbing check derives from it is unambiguous). `RandomState` is seeded from the OS RNG.
fn child_env_canary() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos()),
    );
    format!("mcp-child-env-canary-{:016x}", hasher.finish())
}

fn plugin_path() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
            .expect("build the actual MCP plugin and set BUSBAR_PLUGIN_CDYLIB"),
    );
    assert!(
        path.is_absolute() && path.is_file(),
        "fresh actual MCP artifact required: {}",
        path.display()
    );
    path
}
#[path = "support/mcp_cases.rs"]
mod mcp_cases;

#[path = "support/mcp_refusals.rs"]
mod mcp_refusals;

#[test]
fn the_actual_mcp_images_and_declared_needs_are_exact() {
    use busbar_plugin_loader::dispatch::load::{door_addresses_of_library, rendering_of_library};
    let statement = busbar_plugin_loader::dispatch::rendering_of(busbar_plane_mcp::door).unwrap();
    assert_eq!(
        rendering_of_library(&plugin_path()).unwrap(),
        Some(statement.clone())
    );
    let (door, ops) = door_addresses_of_library(&plugin_path())
        .unwrap()
        .expect("MCP exports a door");
    let linked = busbar_plane_mcp::door();
    // SAFETY: this actual macro-produced immutable static door owns its complete table.
    let parts = unsafe { busbar_contract::abi::mechanism::door::Door::read_parts(linked) };
    assert_ne!(door, linked as *const _ as usize);
    assert_ne!(ops, parts.ops as usize);
    let read = busbar_contract::abi::mechanism::rendering::read(&statement).unwrap();
    let declares: serde_json::Value =
        serde_json::from_str(include_str!("../../plane-mcp/declares.json")).unwrap();
    let mut declared: Vec<_> = declares["needs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_string())
        .collect();
    let mut actual: Vec<_> = read
        .needs
        .iter()
        .filter(|n| !n.transport.is_empty())
        .map(|n| n.transport.clone())
        .collect();
    declared.sort();
    declared.dedup();
    actual.sort();
    actual.dedup();
    assert_eq!(declared, actual);
    assert!(
        !(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()),
        "release conformance requested"
    );
}
