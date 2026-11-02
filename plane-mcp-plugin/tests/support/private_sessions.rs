// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(unsafe_code)]

use crate::tests::door_facts_tests::stated as door_facts;
#[path = "../../../plane-mcp/tests/support/carrier_retirement.rs"]
mod carrier_retirement;
#[path = "../../../plane-mcp/tests/support/completion_retirement_host.rs"]
mod completion_retirement_host;
#[path = "../../../plane-mcp/tests/support/inspection_wire.rs"]
mod inspection_wire;
#[path = "../../../plane-mcp/tests/support/sessions_lines.rs"]
mod sessions_lines;
include!("../../../plane-mcp/tests/support/session_cases.rs");
