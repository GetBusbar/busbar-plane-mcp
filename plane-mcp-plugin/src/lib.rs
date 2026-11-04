// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `mcp` plane as a droppable busbar plugin: the `cdylib` a signed tarball carries
//! (`kind: plane`, key `mcp`).

#![deny(unsafe_code)]

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_plane_mcp::door);
}
