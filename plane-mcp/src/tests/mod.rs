// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate-level test modules: the suites that moved in from `tests/` when this crate's only
//! public item became `door` (BUSBAR-1.6.0.md l.3567, Crate shape), because they read the plane's
//! own tables and functions, which only the crate itself can see. Each kept its name, its tests and
//! its assertions. None holds `unsafe`: the crate forbids it (ARCHITECT addendum 2026-10-21 08:30Z).
//! (The per-module unit tests beside them in this directory are wired from their own modules.)
//!
//! NOT WIRED, and so not compiled or run: `alloc_gate_tests` (until busbar-contract's
//! `alloc-counter` feature is at the pin), and `door_clock_tests`, `program_tests` and
//! `door_witness_unwired`, which need the crate's internals and `unsafe` both.

/// The plane's vocabulary against the conformance battery (the plugin crate's `tests/door_witness.rs`).
mod battery_vocabulary_tests;
/// The plane's own declarations agree with each other (`tests/declarations_agree.rs`).
mod declarations_agree_tests;
/// The approval digest, pinned (`tests/digest_pin.rs`).
mod digest_pin_tests;
/// The facts the door-only suites spell, pinned to the crate's own, and their pure checks.
mod door_facts_tests;
/// The stdio client leg against busbar's method inventory (`tests/method_inventory.rs`).
mod method_inventory_tests;
/// The sanitiser's complexity guards (`tests/sanitize_complexity.rs`).
mod sanitize_complexity_tests;
