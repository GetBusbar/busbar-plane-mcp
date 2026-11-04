// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Local-program roots through the production settings reader. A root names the configured
//! absolute command path, byte for byte, and requires an explicit absolute working
//! directory.

use serde_json::{json, Value};

use crate::tools_config::{ChildEnvValue, ToolsCfg};

const PROGRAM: &str = if cfg!(windows) {
    r"C:\Windows\System32\cmd.exe"
} else {
    "/bin/true"
};

const WORKDIR: &str = if cfg!(windows) { r"C:\Windows" } else { "/tmp" };

const OTHER_SPELLING: &str = if cfg!(windows) {
    r"C:\Windows\System32\.\cmd.exe"
} else {
    "/bin/./true"
};

const ENV_SECRET_MARKER: &str = "local-program-grammar-env-secret-marker";

/// A literal section, sent through the reader used by validate, open and refresh.
fn read(section: &Value) -> Result<ToolsCfg, String> {
    crate::statement::test_support::read_tools_section(
        &serde_json::to_vec(section).expect("a test section serialises"),
    )
}

/// No process is spawned by this document: the grammar judges the configured intent alone.
fn local_section() -> Value {
    json!({
        "local": {
            "transport": "stdio",
            "command": PROGRAM,
            "args": ["--literal", "a b", "", "--token=$UNCHANGED"],
            "env": {
                "TOKEN": ENV_SECRET_MARKER,
                "FROM_SECRET": { "env": "BUSBAR_LOCAL_PROGRAM_TOKEN" }
            },
            "cwd": WORKDIR,
            "pin": { "mechanism": "local_program", "key": PROGRAM },
            "tools_allow": { "read": {} }
        }
    })
}

/// A refusal must come from the production reader and must keep child environment bytes private.
fn refuses(section: &Value) -> String {
    let error = read(section).expect_err("the malformed local-program registration must refuse");
    assert!(
        !error.contains(ENV_SECRET_MARKER),
        "a grammar diagnostic disclosed a child environment value"
    );
    error
}

/// This is the positive control for every refusal family. Before local_program is
/// implemented, it fails at the production enum's unsupported-mechanism reading, rather
/// than proving a mirror.
fn accepts_local_program() -> ToolsCfg {
    read(&local_section()).expect("stdio local_program with matching command/key and absolute cwd")
}

#[test]
fn local_program_reads_exact_command_key_args_env_and_cwd() {
    let cfg = accepts_local_program();
    let def = &cfg.servers["local"];
    assert_eq!(def.pin.mechanism.token(), "local_program");
    assert_eq!(def.pin.key.as_deref(), Some(PROGRAM));
    assert_eq!(def.command.as_deref(), Some(PROGRAM));
    assert_eq!(def.cwd.as_deref(), Some(WORKDIR));
    assert_eq!(def.args, ["--literal", "a b", "", "--token=$UNCHANGED"]);
    assert_eq!(def.env.len(), 2);
    let literal: ChildEnvValue =
        serde_json::from_value(json!(ENV_SECRET_MARKER)).expect("an environment literal");
    let reference: ChildEnvValue =
        serde_json::from_value(json!({ "env": "BUSBAR_LOCAL_PROGRAM_TOKEN" }))
            .expect("an environment reference");
    assert_eq!(def.env["TOKEN"], literal);
    assert_eq!(def.env["FROM_SECRET"], reference);
    assert!(def.tools_allow.contains_key("read"));
}

#[test]
fn local_program_requires_a_nonblank_key_equal_to_the_exact_command_bytes() {
    accepts_local_program();
    for key in [
        Value::Null,
        json!(""),
        json!("   "),
        json!("true"),
        json!(OTHER_SPELLING),
        json!(format!(" {PROGRAM}")),
        json!(format!("{PROGRAM} ")),
        json!("sha256:7f83b1657ff1fc53b92dc18148a1d65dfa13514d"),
    ] {
        let mut section = local_section();
        section["local"]["pin"]["key"] = key;
        refuses(&section);
    }
    let mut section = local_section();
    section["local"]["pin"]
        .as_object_mut()
        .unwrap()
        .remove("key");
    refuses(&section);
}

#[test]
fn local_program_requires_explicit_absolute_command_and_working_directory() {
    accepts_local_program();
    for command in ["", "   ", "true", "bin/true", "./true"] {
        let mut section = local_section();
        section["local"]["command"] = json!(command);
        section["local"]["pin"]["key"] = json!(command);
        refuses(&section);
    }
    for field in ["command", "cwd"] {
        let mut section = local_section();
        section["local"].as_object_mut().unwrap().remove(field);
        refuses(&section);
    }
    for cwd in [
        Value::Null,
        json!(""),
        json!(" "),
        json!("tmp"),
        json!("./tmp"),
    ] {
        let mut section = local_section();
        section["local"]["cwd"] = cwd;
        refuses(&section);
    }
}

#[test]
fn local_program_refuses_network_transports_and_stdio_network_fields() {
    accepts_local_program();
    for url in ["http://mcp.example/rpc", "https://mcp.example/rpc"] {
        for explicit_transport in [false, true] {
            let mut section = json!({
                "local": { "url": url, "pin": { "mechanism": "local_program", "key": PROGRAM } }
            });
            if explicit_transport {
                section["local"]["transport"] = json!("streamable_http");
            }
            refuses(&section);
        }
        let mut section = local_section();
        section["local"]["url"] = json!(url);
        refuses(&section);
    }
    let mut section = local_section();
    section["local"]["client_identity"] = json!({
        "cert": { "env": "BUSBAR_LOCAL_CERT" },
        "key": { "env": "BUSBAR_LOCAL_KEY" }
    });
    refuses(&section);
}

#[test]
fn local_program_refuses_malformed_types_and_public_descriptor_hash_fields() {
    accepts_local_program();
    for (field, value) in [
        ("transport", json!(false)),
        ("transport", json!("http")),
        ("command", json!([PROGRAM])),
        ("command", json!(42)),
        ("cwd", json!([WORKDIR])),
        ("cwd", json!(42)),
        ("args", json!("--literal")),
        ("args", json!([42])),
        ("env", json!(["TOKEN"])),
        ("env", json!({ "TOKEN": 42 })),
        ("pin", json!("local_program")),
    ] {
        let mut section = local_section();
        section["local"][field] = value;
        refuses(&section);
    }
    for key in [
        json!(42),
        json!(false),
        json!([PROGRAM]),
        json!({ "path": PROGRAM }),
    ] {
        let mut section = local_section();
        section["local"]["pin"]["key"] = key;
        refuses(&section);
    }
    for mechanism in [Value::Null, json!(42), json!(["local_program"])] {
        let mut section = local_section();
        section["local"]["pin"]["mechanism"] = mechanism;
        refuses(&section);
    }
    for field in ["descriptor_sha256", "executable_sha256", "env_hash"] {
        let mut section = local_section();
        section["local"]["pin"][field] = json!("sha256:public-descriptor-is-not-a-root");
        refuses(&section);
        let mut section = local_section();
        section["local"][field] = json!("sha256:public-descriptor-is-not-a-root");
        refuses(&section);
    }
}

#[test]
fn local_program_does_not_change_existing_network_pin_grammar_or_pubkey_refusal() {
    accepts_local_program();
    read(&json!({
        "tls": {
            "url": "https://mcp.example/rpc",
            "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" }
        },
        "mutual": {
            "url": "https://mcp.example/mutual",
            "pin": { "mechanism": "mtls", "key": "sha256/PIN==" },
            "client_identity": {
                "cert": { "env": "BUSBAR_CLIENT_CERT" },
                "key": { "env": "BUSBAR_CLIENT_KEY" }
            }
        },
        "dev": { "url": "http://mcp.example/dev", "pin": { "mechanism": "unpinned" } }
    }))
    .expect("the existing network pin grammar still reads");
    let error = refuses(&json!({
        "issuer": {
            "url": "https://mcp.example/rpc",
            "pin": { "mechanism": "pinned_pubkey", "key": "issuer-key" }
        }
    }));
    assert!(error.contains("pinned_pubkey"), "{error}");
    assert!(error.contains("authenticates nothing"), "{error}");
}

#[test]
fn stdio_cannot_claim_a_tls_identity_without_a_tls_connection() {
    let mut dev = local_section();
    dev["local"]["pin"] = json!({ "mechanism": "unpinned" });
    read(&dev).expect("an explicitly unpinned stdio fixture remains registrable");
    for mechanism in ["cert_spki", "mtls"] {
        let mut section = dev.clone();
        section["local"]["pin"] = json!({ "mechanism": mechanism, "key": "sha256/PIN==" });
        if mechanism == "mtls" {
            section["local"]["client_identity"] = json!({
                "cert": { "env": "BUSBAR_LOCAL_CERT" },
                "key": { "env": "BUSBAR_LOCAL_KEY" }
            });
        }
        let error = refuses(&section);
        assert!(error.contains("stdio"), "{error}");
        assert!(error.contains("TLS"), "{error}");
    }
}
