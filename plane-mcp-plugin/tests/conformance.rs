// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PUBLISHED CONFORMANCE SUITE, run over this plane (TODO ABI-b4; OWNER 2026-10-03: plugins
//! test themselves against busbar's published suite). The linked door (`busbar_plane_mcp::door`) and
//! this crate's dropped-in image (the `busbar-plane-mcp-plugin` cdylib, which `cargo test` builds
//! beside the test), each through the one loader, driven by busbar-plugin-loader's plane script
//! over `conformance.json`, every step at its pinned crossing count, the two folds equal: one
//! relayed `tools/call` per unit (each unit arrives first and its caller's body follows its
//! ATTEMPT, as the plane holds a call from its arrival), answered whole, through a narrow buffer,
//! and after a short one. `plugin-ci.yml` runs it under `--release`.
//!
//! THE HOST IS BUSBAR'S OWN CONNECTOR (`host:`): every need the plane declares binds over it as a
//! running busbar binds it, its TLS trusting the suite's test anchors (`tls:`). So the plane's
//! verify-on-call fetch of the registered server's tool list is a real HTTPS exchange with the
//! suite's far end ([`server`], at `conformance_host::FAR_END`, which the settings' `fs` url
//! names), not a probe.

// The suite's host connector, as the fleet heal renders it (`busbar_test_kit::conformance_host!`):
// its far end, its anchors, the network transport doors (`tcp`, `http`) and the host's own proof.
#[path = "support/conformance_host.rs"]
mod conformance_host;

/// The doors the host serves: the rendered network ones, and the PROCESS carrier for the stdio
/// need (`busbar-transport-stdio`, at the rev busbar's dist links at the pin), which the heal
/// leaves out because the far end dials no process; without it the host refuses to bind a plane
/// that declares a stdio need (`UnservedScheme`).
const DOORS: busbar_test_kit::conformance_host::Doors = &[
    conformance_host::DOORS[0],
    conformance_host::DOORS[1],
    ("stdio", busbar_transport_stdio::door::MACRO_DOOR),
];

/// THE REGISTERED SERVER `fs`, at the suite's far end: each HTTP request is answered, under the
/// JSON-RPC request's own id, with its one tool, `read_file` (the plane's `tools/list` fetch).
fn server(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let len = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if seen.len() < end + len {
        return None;
    }
    let asked: serde_json::Value =
        serde_json::from_slice(&seen[end..end + len]).unwrap_or(serde_json::Value::Null);
    let reply = serde_json::json!({
        "jsonrpc": "2.0",
        "id": asked["id"],
        "result": {"tools": [{
            "name": "read_file",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "x-mcp-header": "Path"}}}
        }]}
    })
    .to_string();
    let mut out = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        reply.len()
    )
    .into_bytes();
    out.extend_from_slice(reply.as_bytes());
    Some(out)
}

/// THE SUITE'S HOST (`conformance::Host`): the far end started, then busbar's connector over
/// [`DOORS`]. One per leg.
fn host(
    wake: busbar_test_kit::conformance_host::ConnWake,
    anchors: Option<&str>,
) -> std::sync::Arc<dyn busbar_test_kit::conformance_host::DeclaredConns> {
    conformance_host::far_end(server);
    busbar_test_kit::conformance_host::host(DOORS, wake, anchors)
}

busbar_test_kit::conformance_suite! {
    door: busbar_plane_mcp::door,
    cdylib: "busbar_plane_mcp_plugin",
    inputs: include_str!("conformance.json"),
    host: host,
    tls: conformance_host::anchors(),
}
