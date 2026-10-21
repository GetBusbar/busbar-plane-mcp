// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate-level test modules: the suites that moved in from `tests/` when this crate's only
//! public item became `door` (BUSBAR-1.6.0.md l.3567, Crate shape), because they read the plane's
//! own tables and functions, which only the crate itself can see. Each kept its name, its tests and
//! its assertions. (The per-module unit tests beside them in this directory are wired from their
//! own modules.)

/// The one counting allocator the crate's allocation gate reads, and the only `#[global_allocator]`
/// (a test-only module; a shipped build keeps `forbid(unsafe_code)`).
#[allow(unsafe_code)]
mod alloc_counter;

/// What reading a stdio child's message may allocate (`tests/alloc_gate.rs`).
mod alloc_gate_tests;
/// The plane's own declarations agree with each other (`tests/declarations_agree.rs`).
mod declarations_agree_tests;
/// The approval digest, pinned (`tests/digest_pin.rs`).
mod digest_pin_tests;
/// The door's audit rows, driven over the plane ABI (`tests/door_audit.rs`).
mod door_audit_tests;
/// The door's clock and sealed asks (`tests/door_clock.rs`).
mod door_clock_tests;
/// The vocabulary against the battery and the linked door's transcript (the plugin crate's
/// `tests/door_witness.rs`; its linked-against-dropped-in comparison stays there).
mod door_witness_tests;
/// The stdio client leg against busbar's method inventory (`tests/method_inventory.rs`).
mod method_inventory_tests;
/// The stdio servers' exchange (`tests/program.rs`).
mod program_tests;
/// The sanitiser's complexity guards (`tests/sanitize_complexity.rs`).
mod sanitize_complexity_tests;
/// The session revisions through the door (`tests/sessions.rs`).
mod sessions_door_tests;
/// The tasks extension through the door (`tests/tasks.rs`).
mod tasks_door_tests;
