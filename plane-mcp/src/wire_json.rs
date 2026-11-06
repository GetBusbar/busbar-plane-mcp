// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exact JSON values at MCP wire boundaries, before envelope validation and correlation.

pub(crate) use busbar_contract::spans::parse_value as parse;

/// Parse one event's text with the same type and number guarantees as [`parse`].
pub(crate) fn parse_str(text: &str) -> Result<serde_json::Value, serde_json::Error> {
    parse(text.as_bytes())
}
