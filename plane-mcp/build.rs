// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT CELLS' ADDRESS (this crate's `links` row, busbar #1006): the composition root compiles
//! this plane's own root cells (`tests/root/mod.rs`) from the path stated here, reading it as
//! `DEP_BUSBAR_DOOR_CELLS_<CRATE>_CELLS`, and its black-box cases (`tests/blackbox/`) as
//! `DEP_BUSBAR_DOOR_CELLS_<CRATE>_BLACKBOX`. Nothing is built or linked.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    println!(
        "cargo::metadata=cells={}",
        std::path::Path::new(&dir)
            .join("tests/root/mod.rs")
            .display()
    );
    // THE BLACK-BOX CASES (`blackbox/1`): the directory busbar's plane-agnostic runner
    // (`crates/busbar/tests/plane_blackbox.rs`) reads every `*.json` case of, as
    // `DEP_BUSBAR_DOOR_CELLS_<CRATE>_BLACKBOX`.
    println!(
        "cargo::metadata=blackbox={}",
        std::path::Path::new(&dir).join("tests/blackbox").display()
    );
}
