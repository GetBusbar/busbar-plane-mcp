// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `{server}_{tool}` as the routing key: the separator ambiguity, and the round trip.

use crate::identity::{NameError, ServerId, ToolKey};

#[test]
fn a_server_id_containing_the_separator_is_refused() {
    let err = ServerId::new("file_system").expect_err("`_` in a server id must be refused");
    assert_eq!(err, NameError::ServerIdHasSeparator("file_system".into()));
    // The message has to say WHY, because an operator who reads "invalid" renames it to
    // `file__system` and reintroduces the ambiguity.
    let msg = err.to_string();
    assert!(
        msg.contains("mcp_tool"),
        "message must name the grant kind the ambiguity would corrupt: {msg}"
    );
    assert!(
        msg.contains("Use `-`"),
        "message must say what to type instead: {msg}"
    );
}

#[test]
fn a_tool_name_may_contain_the_separator_because_real_tools_do() {
    let k = ToolKey::new(ServerId::new("filesystem").unwrap(), "read_file").unwrap();
    assert_eq!(k.to_string(), "filesystem_read_file");
}

#[test]
fn names_outside_the_legal_set_are_refused_on_both_axes() {
    for bad in ["fs server", "fs/server", "fs\"x", "fs\nx", "fs:x"] {
        assert!(
            matches!(ServerId::new(bad), Err(NameError::IllegalCharacter { .. })),
            "server id `{bad}` must be refused"
        );
    }
    let ok = ServerId::new("fs").unwrap();
    for bad in ["read file", "read/file", "read\"x"] {
        assert!(
            matches!(
                ToolKey::new(ok.clone(), bad),
                Err(NameError::IllegalCharacter { .. })
            ),
            "tool name `{bad}` must be refused"
        );
    }
}

#[test]
fn empty_names_are_refused() {
    assert_eq!(
        ServerId::new(""),
        Err(NameError::Empty { what: "server id" })
    );
    assert_eq!(
        ToolKey::new(ServerId::new("fs").unwrap(), ""),
        Err(NameError::Empty { what: "tool name" })
    );
}
