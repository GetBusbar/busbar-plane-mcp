// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `2024-11-05` HTTP+SSE client rung, held: busbar reaches a registered
//! server that speaks only the legacy event-stream revision.
//!
//! * ONE HELD STREAM per member AND caller binding: its `GET`, its `endpoint` event, the message
//!   address, the `initialize` handshake and correlation by JSON-RPC id are the plane's.
//! * The connector holds the connection; the stream is read on the instance's ONE driver ticket
//!   ([`drive`]). Each pending operation retains its handle and its own read buffers across ticks;
//!   completed handles are recycled only after negotiated host retirement confirms their receipt.
//! * A call POSTs its own request on its own ticket, its id registered BEFORE the POST leaves, and
//!   waits for the driver to hand it the answer under that id.
//! * A reply whose id no call waits for is dropped and counted: the next answer on that link
//!   carries one rejected `mcp_upstream.reply` audit row per reply, at most
//!   [`MAX_DROPPED_AUDITED`].
//! * The server's own messages are routed as the other rungs route them (`ping` answered, an ask
//!   refused, an unknown request `-32601`, each reply POSTed on the driver ticket); a resource
//!   update is announced, and a call's progress and the stream's log records ride its answer.
//! * The stream dropping fails every waiting call with [`STREAM_CLOSED`]'s words.
//! * BOUNDED: at most [`MAX_LINKS`] live streams (past it an idle one is let go; with none idle the
//!   call is refused), and a stream unused for [`IDLE_NS`] is closed.

include!("door_legacy_impl.rs");
