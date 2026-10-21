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

use busbar_plugin_loader::dispatch::LoadedDoor;

/// This plugin's own door, named for the loader.
fn loaded_door() -> LoadedDoor {
    // SAFETY: `busbar_plane_mcp::door` is this crate's own door: it answers the `'static` door of
    // this plugin.
    #[allow(unused_unsafe)]
    let loaded = unsafe { LoadedDoor::from_raw(busbar_plane_mcp::door) };
    loaded
}

busbar_plugin_loader::conformance_suite! {
    loaded: loaded_door(),
    cdylib: "busbar_plane_mcp_plugin",
    inputs: include_str!("conformance.json"),
}
