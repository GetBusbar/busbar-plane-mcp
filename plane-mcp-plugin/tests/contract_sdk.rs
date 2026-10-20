// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DROPPED-IN IMAGE CARRIES THE SDK A BUSBAR BUILD LINKS (THE DESIGN, "compiled in or dropped
//! in ... nothing changes about the plugin itself"; "no allocation and no blocking on the hot path").
//!
//! The cdylib's `export_door!` trampolines and the SDK's `Out` and `Safe` code are compiled from the
//! busbar-contract this repo pins, while a busbar build links the same door against its own contract.
//! These tests read the SDK source the image is built from and require the two hot-path fixes the
//! linked door has: an entry on an instance with nothing parked takes no shared lock, and a READY
//! arrival's route entry is named from the instance's kept table, not a fresh heap text under the
//! instance-wide mutex.

use std::path::PathBuf;
use std::process::Command;

/// One file of the SDK (`src/abi/sdk/<file>`) of the busbar-contract this workspace builds against.
fn contract_sdk(file: &str) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked", "--offline"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("metadata is JSON");
    let manifest = meta["packages"]
        .as_array()
        .expect("metadata lists packages")
        .iter()
        .find(|p| p["name"] == "busbar-contract")
        .and_then(|p| p["manifest_path"].as_str())
        .expect("busbar-contract is a package of this workspace");
    let dir = PathBuf::from(manifest)
        .parent()
        .expect("the manifest has a directory")
        .to_path_buf();
    std::fs::read_to_string(dir.join("src/abi/sdk").join(file)).expect("the SDK source reads")
}

#[test]
fn the_images_sdk_forgets_without_the_shared_lock_when_nothing_is_parked() {
    let safe = contract_sdk("safe.rs");
    assert!(
        safe.contains("parked_len: AtomicUsize"),
        "the image's contract SDK takes the parked-table mutex every worker shares on every entry: \
         its busbar pin predates the fast path the linked door has"
    );
}

#[test]
fn the_images_sdk_names_a_kept_route_without_the_heap() {
    let out = contract_sdk("out.rs");
    assert!(
        out.contains(".name(entry)"),
        "the image's contract SDK allocates a route text under the instance-wide mutex on every \
         READY arrival: its busbar pin predates the kept route table the linked door has"
    );
}
