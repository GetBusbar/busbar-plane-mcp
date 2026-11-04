// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Incremental parsing of the stdio MCP child message stream.
use serde_json::Value;
/// The exchange SDK's reply bound.
pub(crate) const MESSAGE_MAX: usize = busbar_contract::abi::sdk::exchange::REPLY_MAX;

/// One message a child wrote: a JSON value, or bytes that are none (returned as an answer, never
/// judged here: the JSON-RPC reader owns that complaint).
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A JSON value.
    Value(Value),
    /// Not JSON at all.
    NotJson(Vec<u8>),
}

/// THE CHILD'S MESSAGES, out of its frames however the host's buffer cut them: whole JSON values,
/// back to back (the stdio framer hands each line without its newline). Each byte is scanned ONCE
/// for where a value ends (its nesting depth, outside strings) and a value is parsed only once it is
/// whole, so a message read in many pieces costs its size, never its size per piece: bounded work
/// on the worker.
#[derive(Debug, Default)]
pub struct Frames {
    buf: Vec<u8>,
    /// How far `buf` is scanned.
    seen: usize,
    /// Where the value being read starts in `buf`, once its first byte came.
    start: Option<usize>,
    depth: usize,
    in_string: bool,
    escaped: bool,
    overgrown: bool,
}

impl Frames {
    /// Take `bytes`; every message they complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Message> {
        if self.overgrown {
            return Vec::new();
        }
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut used = 0;
        while let Some(&b) = self.buf.get(self.seen) {
            let at = self.seen;
            self.seen += 1;
            let Some(start) = self.start else {
                match b {
                    b' ' | b'\t' | b'\r' | b'\n' => used = self.seen,
                    b'{' | b'[' => {
                        self.start = Some(at);
                        self.depth = 1;
                    }
                    _ => {
                        let rest = self.buf.split_off(at);
                        if rest.len() > MESSAGE_MAX {
                            self.overgrown = true;
                            self.buf.clear();
                            return Vec::new();
                        }
                        *self = Frames::default();
                        out.push(Message::NotJson(rest));
                        return out;
                    }
                }
                continue;
            };

            if self.seen - start > MESSAGE_MAX {
                self.overgrown = true;
                self.buf.clear();
                return Vec::new();
            }
            if self.in_string {
                match b {
                    _ if self.escaped => self.escaped = false,
                    b'\\' => self.escaped = true,
                    b'"' => self.in_string = false,
                    _ => {}
                }
                continue;
            }
            match b {
                b'"' => self.in_string = true,
                b'{' | b'[' => self.depth += 1,
                b'}' | b']' => {
                    self.depth -= 1;
                    if self.depth == 0 {
                        let whole = &self.buf[start..self.seen];
                        out.push(match serde_json::from_slice(whole) {
                            Ok(value) => Message::Value(value),
                            Err(_) => Message::NotJson(whole.to_vec()),
                        });
                        self.start = None;
                        used = self.seen;
                    }
                }
                _ => {}
            }
        }
        self.buf.drain(..used);
        self.seen -= used;
        self.start = self.start.map(|s| s - used);
        out
    }

    /// Whether a message exceeded [`MESSAGE_MAX`], including its completing piece.
    #[must_use]
    pub fn overgrown(&self) -> bool {
        self.overgrown || self.buf.len() > MESSAGE_MAX
    }
}
