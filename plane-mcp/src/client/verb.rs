// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLOSED SET OF METHODS BUSBAR ISSUES TO AN UPSTREAM MCP SERVER THROUGH ONE BUILDER, each with
//! a production construction site.
//!
//! ## Why a closed enum and not a `&str` method name
//!
//! `qa/method-inventory.json` is a MATRIX and this module is one of its columns: `mcp × <transport>
//! × busbar-as-client × client-originated`. A builder that took the method as a string would make
//! the column's contents a property of its call sites, so a method could be added by one caller and
//! be invisible to every gate. The enum is what makes an enumeration of the column possible, and
//! `src/tests/method_inventory_tests.rs` compares the variants PRODUCTION CONSTRUCTS (counted in
//! the shipped source, never in this file's own list) against the generated inventory: a variant
//! with no production construction site does not ship, and is not here.
//!
//! ## What is issued, and from where
//!
//! - `initialize` and `notifications/initialized`: the handshake a STDIO CHILD demands before any
//!   other request (`crate::tool_program::initialize`, `initialized_notification`). Over streamable
//!   HTTP the stateless revision deleted the handshake; a session revision's is the client
//!   ladder's (`super::compat`).
//!
//! A caller's resource subscription is never carried upstream: busbar records the uri and relays
//! what the member announces, so `resources/subscribe` and `resources/unsubscribe` are not issued.
//!
//! `tools/call` and `tools/list` are built by `super::jsonrpc` on the dispatch and verify paths.
//! Every other client-originated method of the inventory is one busbar does not send an upstream
//! today; the inventory test names each, so issuing one means adding its variant here AND its
//! production construction site.
//!
//! ## Params are DATA, never argv
//!
//! Every variant's payload is serialised into the JSON-RPC `params` object. Nothing here can reach
//! a child's argument vector, which is config-only.

use super::jsonrpc::{envelope, OutboundRequest};
use crate::codec::{META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION, PROTOCOL_VERSION};

/// THE PROTOCOL REVISION BUSBAR OFFERS A CHILD IN ITS HANDSHAKE.
///
/// The same string busbar's own front door serves, and it is offered rather than imposed: a child
/// that answers `initialize` with a different `protocolVersion` has told busbar what it speaks, and
/// that answer is recorded rather than argued with. busbar is a gateway, not a conformance test.
pub const CLIENT_PROTOCOL_VERSION: &str = PROTOCOL_VERSION;

/// What busbar calls itself to a child. A constant, not a config key: an operator who could rename
/// busbar in a handshake could make one deployment impersonate another in the child's own logs.
const CLIENT_NAME: &str = "busbar";

/// ONE METHOD BUSBAR SENDS TO AN UPSTREAM, with its parameters.
///
/// Every variant carries the data its `params` needs and nothing else. There is deliberately no
/// `Other(String)` arm: an arm that accepted an arbitrary method name would reopen exactly the
/// hole this enum closes. Every variant has a production construction site (see the module
/// header); none is kept for a caller that does not exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamVerb {
    /// The handshake a stdio child demands.
    Initialize {
        /// busbar's release, sent as `clientInfo.version`. Handed in by the engine: a plane reads
        /// no build environment of its own.
        client_version: &'static str,
    },
    /// The handshake's acknowledgement. A NOTIFICATION: it has no reply, and a client that waited
    /// for one would hang against every conformant server.
    NotificationsInitialized,
}

impl UpstreamVerb {
    /// THE WIRE METHOD NAME. Exhaustive, with no wildcard arm, so a variant added without a name is
    /// a compile error rather than a method that silently sends the wrong word.
    pub fn method(&self) -> &'static str {
        match self {
            UpstreamVerb::Initialize { .. } => "initialize",
            UpstreamVerb::NotificationsInitialized => "notifications/initialized",
        }
    }

    /// Whether this verb is a JSON-RPC NOTIFICATION — no `id`, and NO REPLY EVER.
    ///
    /// Decided on the VARIANT rather than by testing whether the method name starts with
    /// `notifications/`, because that string test is a rule about spelling that would silently
    /// reclassify any future method whose name happened to match. The distinction matters at the
    /// transport: the engine's `mcp::client::wire::McpWire::notify` does not read, and a request sent down that path
    /// would wait for an answer nobody would ever read — which on a stdio child means the answer
    /// stays in the pipe and desynchronises every subsequent call.
    pub fn is_notification(&self) -> bool {
        matches!(self, UpstreamVerb::NotificationsInitialized)
    }

    /// The `params` object, WITHOUT `_meta` — which [`Self::build`] adds, once, for every verb.
    ///
    /// Split that way so no variant can forget the revision's required `_meta`.
    fn params(&self) -> serde_json::Value {
        match self {
            UpstreamVerb::Initialize { client_version } => serde_json::json!({
                "protocolVersion": CLIENT_PROTOCOL_VERSION,
                // THE EMPTY CAPABILITY SET, and it is the honest one. Sampling, elicitation and
                // roots are deny-by-default per server (`super::jsonrpc::ServerRequestGrants`), so
                // declaring a capability busbar then refuses to honour would invite a child to build
                // a call sequence around authority it will not be given.
                "capabilities": {},
                "clientInfo": { "name": CLIENT_NAME, "version": client_version },
            }),
            UpstreamVerb::NotificationsInitialized => serde_json::json!({}),
        }
    }

    /// The `Mcp-Name` header's value for this verb, when the revision requires one.
    ///
    /// `Some` only where the request NAMES a target the header can mirror. A header that mirrored a
    /// value the body does not carry would be a header busbar's own ingress answers `-32020` to.
    /// WHICH member of this verb's `params` the `Mcp-Name` header mirrors, and its value.
    ///
    /// The RULE is `crate::codec::name_source_of`'s and is not restated here. This function
    /// once carried its own copy and the two disagreed about the three tasks methods, so a
    /// `tasks/get` issued over streamable HTTP went out with no `Mcp-Name` — the exact header
    /// busbar's own ingress answers `-32020` to. Reading the ingress's table means the requests
    /// busbar SENDS satisfy the MUSTs busbar ENFORCES, by construction rather than by two authors
    /// agreeing.
    ///
    /// It returns an owned `String` because the value is read back out of the serialised `params`
    /// rather than off the variant: the member the header mirrors is decided by the wire method, so
    /// looking it up by name is what keeps the two in step. A per-variant `match` would be the
    /// second copy again, wearing a different shape.
    fn target(&self) -> Option<String> {
        let source = crate::codec::name_source_of(self.method())?;
        self.params()
            .get(source)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }

    /// BUILD the request. One envelope function, shared with `tools/call`, so the mirrored headers
    /// this revision REQUIRES cannot be got right on one verb and wrong on another.
    ///
    /// `request_id` is IGNORED for a notification, which carries no `id` member at all — a
    /// notification with an `id` is a request, and a peer would be right to answer it.
    pub fn build(
        &self,
        url: &str,
        request_id: u64,
        authorization: Option<&str>,
    ) -> OutboundRequest {
        let mut params = self.params();
        if let Some(obj) = params.as_object_mut() {
            obj.insert(
                "_meta".to_string(),
                serde_json::json!({
                    META_PROTOCOL_VERSION: CLIENT_PROTOCOL_VERSION,
                    META_CLIENT_CAPABILITIES: {},
                }),
            );
        }
        let method = self.method();
        let body = if self.is_notification() {
            serde_json::json!({ "jsonrpc": "2.0", "method": method, "params": params })
        } else {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            })
        };
        envelope(url, method, self.target().as_deref(), body, authorization)
    }
}

#[cfg(test)]
impl UpstreamVerb {
    /// ONE INSTANCE OF EVERY VARIANT, for the tests of the builder's shape. The method inventory
    /// test counts production construction sites, never this list.
    pub fn all() -> Vec<UpstreamVerb> {
        vec![
            UpstreamVerb::Initialize {
                client_version: "0.0.0",
            },
            UpstreamVerb::NotificationsInitialized,
        ]
    }
}

#[cfg(test)]
#[path = "tests/verb_tests.rs"]
mod verb_tests;
