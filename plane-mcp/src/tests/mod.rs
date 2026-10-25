// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate-level test modules: the suites that moved in from `tests/` when this crate's only
//! public item became `door` (BUSBAR-1.6.0.md l.3567, Crate shape), because they read the plane's
//! own tables and functions, which only the crate itself can see. Each kept its name, its tests and
//! its assertions. None holds `unsafe`: the crate forbids it (ARCHITECT addendum 2026-10-21 08:30Z).
//! The suites that drive the door over its C ABI are integration tests (`tests/*.rs`), reaching the
//! crate through `door` alone. (The per-module unit tests beside these in this directory are wired
//! from their own modules.)

/// A grant check that admits every grant: the unit suites' stand-in for a caller entitled to all.
pub(crate) fn everyone(_: &str, _: &str) -> bool {
    true
}

/// The crate's one `#[global_allocator]`, every allocation gate's count: busbar-contract's
/// test-only `alloc-counter` (a dev-dependency feature), so this crate holds no `unsafe`.
#[global_allocator]
static A: busbar_contract::alloc_counter::Counting =
    busbar_contract::alloc_counter::Counting::new();

/// What reading a stdio child's message may allocate (`tests/alloc_gate.rs`).
mod alloc_gate_tests;
/// The plane's vocabulary against the conformance battery (the plugin crate's `tests/door_witness.rs`).
mod battery_vocabulary_tests;
/// The plane's own declarations agree with each other (`tests/declarations_agree.rs`).
mod declarations_agree_tests;
/// The approval digest, pinned (`tests/digest_pin.rs`).
mod digest_pin_tests;
/// A sealed state's window judged at the host clock's time: a clock that fails refuses
/// (`decide_ask`, `seal_relayed` over a host that is a value).
mod door_clock_tests;
/// The door's facts the door-driven tests restate (`tests/support/door_facts.rs`), held to the
/// crate's own items, and those tests' pure checks.
mod door_facts_tests;
/// The stdio client leg against busbar's method inventory (`tests/method_inventory.rs`).
mod method_inventory_tests;
/// The door's own exchanges with a stdio child (`ProgramExchange` over a child that is a value).
mod program_tests;
/// The relayed call is the request and the answer the plane's own builders say (the linked door
/// driven through the loader).
mod relayed_call_tests;
/// The sanitiser's complexity guards (`tests/sanitize_complexity.rs`).
mod sanitize_complexity_tests;
