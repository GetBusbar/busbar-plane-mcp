// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTING KEY: `{server}_{tool}`, a pair that renders, never a string that is parsed. A
//! server id may not contain `_`, so the rendering splits one way and one `mcp_tool` grant names
//! one tool.

use std::fmt;

/// Why a server id or tool name was refused. Both arms are construction-time refusals: a malformed
/// identity must never reach the point where it is compared against a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameError {
    /// A server id was empty, or a tool name was.
    Empty {
        /// Which name was empty: `server id` or `tool name`.
        what: &'static str,
    },
    /// A server id contained `_`, which would make `{server}_{tool}` ambiguous. See the module
    /// header: this is the separator-as-confused-deputy case, refused at the door.
    ServerIdHasSeparator(String),
    /// A name carried a character that is not `[A-Za-z0-9_.-]`. Tool and server names travel in
    /// scope-grant values, header values and audit resources; a name carrying whitespace, a quote,
    /// a control character or a `/` is a name that renders differently depending on which of those
    /// it is being written into, and a value compared for equality must have exactly one spelling.
    IllegalCharacter {
        /// Which name was refused: `server id` or `tool name`.
        what: &'static str,
        /// The refused name, verbatim.
        name: String,
    },
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::Empty { what } => write!(f, "an MCP {what} may not be empty"),
            NameError::ServerIdHasSeparator(id) => write!(
                f,
                "MCP server id `{id}` contains `_`, which is the `{{server}}_{{tool}}` separator. \
                 A server id containing the separator makes the namespaced tool name ambiguous, \
                 and that name is the value of an `mcp_tool` scope grant — so the ambiguity would \
                 be a grant for one tool admitting another. Use `-` instead."
            ),
            NameError::IllegalCharacter { what, name } => write!(
                f,
                "MCP {what} `{name}` contains a character outside `[A-Za-z0-9_.-]`. This name is \
                 compared for exact equality as a scope-grant value and written into headers and \
                 audit rows, so it must have exactly one spelling."
            ),
        }
    }
}

/// The `{server}_{tool}` separator, named once so the rendering, the parse and the refusal above
/// cannot disagree about what it is.
const SEP: char = '_';

/// `name` (a `what`) refused when empty or carrying a character outside `[A-Za-z0-9_.-]`.
fn legal(what: &'static str, name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty { what });
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
    {
        return Err(NameError::IllegalCharacter {
            what,
            name: name.to_string(),
        });
    }
    Ok(())
}

/// A registered upstream MCP server's id. Validated at construction, so every later use is a
/// comparison rather than a re-check.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerId(String);

impl ServerId {
    /// Validate `id` as a server id: non-empty, only `[A-Za-z0-9_.-]`, and no `_` separator.
    pub fn new(id: &str) -> Result<Self, NameError> {
        legal("server id", id)?;
        if id.contains(SEP) {
            return Err(NameError::ServerIdHasSeparator(id.to_string()));
        }
        Ok(Self(id.to_string()))
    }
}

impl fmt::Display for ServerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// THE ROUTING KEY. A `(server, tool)` pair that RENDERS as `{server}_{tool}`.
///
/// It is deliberately a pair and not a string: equality is structural, so two different tools can
/// never compare equal because their renderings collided, and the rendering is derived rather than
/// stored so there is no second copy to drift.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ToolKey {
    server: ServerId,
    tool: String,
}

impl ToolKey {
    /// Pair a validated server id with a tool name, refusing an empty or illegal tool name.
    pub fn new(server: ServerId, tool: &str) -> Result<Self, NameError> {
        legal("tool name", tool)?;
        Ok(Self {
            server,
            tool: tool.to_string(),
        })
    }

    /// The tool half of the key, as the upstream names it.
    pub fn tool(&self) -> &str {
        &self.tool
    }
}

impl fmt::Display for ToolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{SEP}{}", self.server.0, self.tool)
    }
}

#[cfg(test)]
#[path = "tests/identity_tests.rs"]
mod identity_tests;
