// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SOURCE SCANS' SHARED READERS (`tests/invariance.rs`, `tests/purity.rs`): the crate's source
//! directory, its sibling plane crates, and a walk over the source a shipped build compiles.

use std::path::{Path, PathBuf};

/// The crate's own source directory.
pub fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The dash-spelled directory name of every OTHER `busbar-plane-*` crate in the workspace.
///
/// Read from the tree rather than typed out one instance at a time: a purity check that hand-lists
/// its sibling planes is itself an instance-naming leak (and a stale one, the day a new plane is
/// added and this list is not). Deriving the set from `crates/`'s own directory listing makes the
/// check exhaustive over every sibling plane there is, present or future, without this crate's own
/// source spelling a single one of their names.
pub fn sibling_plane_crates() -> Vec<String> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/<this crate> has a parent");
    let mut out: Vec<String> = std::fs::read_dir(crates_dir)
        .expect("the crates directory is readable")
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| name.starts_with("busbar-plane-") && name != env!("CARGO_PKG_NAME"))
        .collect();
    out.sort();
    out
}

/// Walk every source file on the SURFACE, the code a shipped build compiles: every one under `dir`
/// less the test-module directories (`src/tests/`, and each module's own `tests/`). A test module is
/// compiled only when the tests are and the kernel never sees it; the suites that moved in from
/// `tests/` when the crate's only public item became `door` read files, the environment and a
/// clock, as they did out there.
pub fn walk_surface(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    for entry in std::fs::read_dir(dir)
        .expect("the source directory is readable")
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            walk_surface(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file is readable");
            f(&path, &text);
        }
    }
}
