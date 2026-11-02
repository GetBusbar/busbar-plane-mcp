// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercises caller-isolated 2025-06-18 sessions and 2024-11-05 legacy streams through the MCP C ABI with host stand-ins.

#![allow(unsafe_code)]

#[path = "support/door_facts.rs"]
#[allow(dead_code)]
mod door_facts;

#[path = "support/completion_retirement_host.rs"]
mod completion_retirement_host;

#[path = "support/sessions_lines.rs"]
mod sessions_lines;

#[path = "support/carrier_retirement.rs"]
mod carrier_retirement;
#[path = "support/inspection_wire.rs"]
mod inspection_wire;

include!("support/session_cases.rs");
