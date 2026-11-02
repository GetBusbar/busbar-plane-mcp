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
        template
            .replace(marker, &mcp_network::peer_key_pin())
            .replace("localhost:56712", mcp_network::authority())
    })
}

busbar_test_kit::conformance_suite! {
    door: busbar_plane_mcp::door,
    cdylib: "busbar_plane_mcp_plugin",
    inputs: inputs(),
    host: mcp_network::host,
    tls: mcp_network::anchors(),
}
