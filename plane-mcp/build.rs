// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT CELLS' ADDRESS (this crate's `links` row): the composition root compiles this plane's
//! own root cells from the path printed here, reading it as `DEP_BUSBAR_DOOR_CELLS_<CRATE>_CELLS`,
//! and its black-box cases (`tests/blackbox/`, every `*.json` case busbar's plane-agnostic runner
//! `crates/busbar/tests/plane_blackbox.rs` reads) as `DEP_BUSBAR_DOOR_CELLS_<CRATE>_BLACKBOX` (the
//! same for a path dependency and a pinned one). Nothing is generated and nothing is linked.

use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=build.rs");
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    println!(
        "cargo::metadata=cells={}",
        dir.join("tests/root/mod.rs").display()
    );
    println!(
        "cargo::metadata=blackbox={}",
        dir.join("tests/blackbox").display()
    );
    Ok(())
}
