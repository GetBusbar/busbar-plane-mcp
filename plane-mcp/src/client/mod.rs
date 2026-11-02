// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLIENT DIRECTION'S WIRE DIALECT: what busbar sends an upstream MCP server and how it reads

/// The session revisions, spoken as a client: lowering, the ladder's reading, the message address.
pub mod compat;
pub mod jsonrpc;
/// One upstream call carried across the revisions, as a sans-I/O state machine.
pub mod negotiate;
pub mod peer;
pub mod verb;
