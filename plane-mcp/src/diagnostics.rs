// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MCP plane diagnostics: the catalog entries for the codes this plane RAISES, and no other.
//!
//! The catalog reaches the host through the plane's `declares.json` (its `diagnostics`), which the
//! door's Statement carries under `EXT_DECLARES` and the release signs into a dropped-in plane's
//! manifest; the composition root installs each declared code into the runtime catalog. This
//! module is the same catalog as Rust values, for the tests: they hold `declares.json` equal to
//! [`DIAGNOSTICS`] field for field, and the codes the door raises (its Statement's diagnostic ids,
//! each spelled `BUSBAR-NNNN` so the host's log resolves its catalog entry) equal to the codes
//! [`DIAGNOSTICS`] holds. A code is REGISTERED, never renumbered; a code nothing raises is not
//! declared.

use busbar_contract::diagnostic::{Class, Diagnostic, Severity};

/// An MCP `2024-11-05` event stream opened on the ungoverned chain: raised once per plane instance,
/// on its first such stream (THE DESIGN, the mcp bullet: an ungoverned chain is unisolated and says
/// so, with a per-instance boot diagnostic latched on the first legacy stream).
pub const MCP_LEGACY_STREAM_UNGOVERNED: Diagnostic = Diagnostic {
    code: 7106,
    class: Class::Plane,
    slug: "mcp-legacy-stream-ungoverned",
    title: "MCP 2024-11-05 event stream opened on the ungoverned chain (sessions unisolated)",
    severity: Severity::Actionable,
    summary: "A caller opened an MCP 2024-11-05 event stream while the deployment runs the \
              ungoverned chain. Every caller there is one owner, so a session id (which this \
              revision carries in a URL) isolates nothing between callers: any caller that learns \
              it can post into the session. Raised once per plane instance, on the first such \
              stream.",
    action: "Govern the deployment (configure an auth chain) so each MCP session is bound to the \
             key that opened it, or accept that callers of this deployment are not isolated from \
             one another.",
    since: "1.6.0",
    retired: false,
};

/// THE CODES THIS PLANE RAISES, ascending: the catalog its `declares.json` states.
pub static DIAGNOSTICS: &[&Diagnostic] = &[&MCP_LEGACY_STREAM_UNGOVERNED];

#[cfg(test)]
#[path = "tests/diagnostics_tests.rs"]
mod diagnostics_tests;
