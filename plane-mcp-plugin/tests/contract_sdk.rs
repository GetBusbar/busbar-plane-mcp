// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DROPPED-IN IMAGE CARRIES THE SDK A BUSBAR BUILD LINKS (THE DESIGN, "compiled in or
//! dropped in ... nothing changes about the plugin itself"; "no allocation and no blocking on the
//! hot path").
//!
//! The cdylib's `export_door!` trampolines and the SDK's `Out` and `Safe` code are compiled from
//! the busbar-contract this repo pins, while a busbar build links the same door against its own
//! contract.
//! These tests read the SDK source the image is built from and require the two hot-path fixes the
//! linked door has: an entry on an instance with nothing parked takes no shared lock, and a READY
//! arrival's route entry is named from the instance's kept table, not a fresh heap text under the
//! instance-wide mutex.

use std::path::PathBuf;

/// The commit of GetBusbar/busbar this workspace's lock takes busbar-contract from.
fn contract_rev() -> String {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.lock"))
        .expect("the workspace lock reads");
    let block = lock
        .split("\n\n")
        .find(|b| b.lines().any(|l| l.trim() == "name = \"busbar-contract\""))
        .expect("the lock holds busbar-contract");
    let source = block
        .lines()
        .find_map(|l| l.trim().strip_prefix("source = \""))
        .expect("busbar-contract is locked from a source");
    let (_, rev) = source
        .trim_end_matches('"')
        .rsplit_once('#')
        .expect("a git source names its commit");
    rev.to_string()
}

/// One file of the SDK (`src/abi/sdk/<file>`) of the busbar-contract this workspace builds against:
/// read from cargo's checkout of the locked commit (`$CARGO_HOME/git/checkouts/<repo>/<short id>`),
/// which the build that compiled this test made.
fn contract_sdk(file: &str) -> String {
    let rev = contract_rev();
    let short = rev.get(..7).expect("a commit id is longer than 7");
    let home = std::env::var_os("CARGO_HOME").map_or_else(
        || PathBuf::from(std::env::var_os("HOME").expect("a home directory")).join(".cargo"),
        PathBuf::from,
    );
    let checkouts = home.join("git").join("checkouts");
    let tail = PathBuf::from(short)
        .join("crates/busbar-contract/src/abi/sdk")
        .join(file);
    let found = std::fs::read_dir(&checkouts)
        .expect("cargo's git checkouts read")
        .filter_map(Result::ok)
        .map(|e| e.path().join(&tail))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("no checkout of busbar {rev} under {}", checkouts.display()));
    std::fs::read_to_string(found).expect("the SDK source reads")
}

#[test]
fn the_images_sdk_forgets_without_the_shared_lock_when_nothing_is_parked() {
    // The parked table is lock-free slots claimed by compare-and-swap on the ticket (busbar
    // d2b31edb7e, which replaced the `parked_len` fast path): a ticket with nothing parked is
    // found absent by atomic loads alone and takes no lock.
    let safe = contract_sdk("safe.rs");
    assert!(
        safe.contains("slots claimed by compare-and-swap on the ticket")
            && safe.contains("Nothing parked on `ticket` takes no lock at all."),
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
