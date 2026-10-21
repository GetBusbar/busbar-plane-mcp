// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! This protocol's result DISCRIMINATORS, the one part of the envelope vocabulary the plane spells
//! itself.
//!
//! The envelope is read and written elsewhere: an arrival's envelope by the contract's reader
//! (`busbar_contract::jsonrpc::read`, in [`crate::tool_arrival`]), an error answer by the
//! contract's writer (`busbar_contract::jsonrpc::error_body`), and the requests busbar sends an
//! upstream by [`crate::client::jsonrpc`]. What is left here is the `resultType` each successful
//! result carries, stamped by this node rather than passed through from whatever a server said
//! about its own result.

/// The discriminator on a result this node is handing over as finished.
pub const RESULT_TYPE_COMPLETE: &str = "complete";

/// The discriminator on a result that asks the caller for something first.
pub const RESULT_TYPE_INPUT_REQUIRED: &str = "input_required";

// THE ERROR-CODE TABLE IS THE DIALECT'S, AND THERE IS ONE OF IT: `codec` defines it; the tests
// read it on the path they always spelled.
#[cfg(test)]
pub use crate::codec::{
    CODES, CODE_HEADER_MISMATCH, CODE_INTERNAL, CODE_INVALID_PARAMS, CODE_INVALID_REQUEST,
    CODE_METHOD_NOT_FOUND, CODE_MISSING_CLIENT_CAPABILITY, CODE_PARSE_ERROR,
    CODE_UNSUPPORTED_PROTOCOL_VERSION, RETIRED_CODES,
};

#[cfg(test)]
#[path = "tests/jsonrpc.rs"]
mod tests;
