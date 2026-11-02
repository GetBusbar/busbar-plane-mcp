// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate-level test modules: the suites that moved in from `tests/` when this crate's only

/// A grant check that admits every grant: the unit suites' stand-in for a caller entitled to all.
pub(crate) fn everyone(_: &str, _: &str) -> bool {
    true
}

/// The plane's vocabulary against the conformance battery (the plugin crate's `tests/both_ways.rs`).
mod battery_vocabulary_tests;
/// The plane's own declarations agree with each other (`tests/declarations_agree.rs`).
mod digest_pin_tests;
/// A sealed state's window judged at the host clock's time: a clock that fails refuses
mod door_clock_tests;
/// The door's facts the door-driven tests restate (`tests/support/door_facts.rs`), held to the
pub(crate) mod door_facts_tests;
/// The stdio client leg against busbar's method inventory (`tests/method_inventory.rs`).
mod method_inventory_tests;
/// The door's own exchanges with a stdio child (`ProgramExchange` over a child that is a value).
mod program_tests;
/// The sanitiser's complexity guards (`tests/sanitize_complexity.rs`).
mod sanitize_complexity_tests;

/// Configured host-launch authentication for stdio registrations.
mod local_program_trust_tests;

/// Launch receipts must precede every actual stdio exchange write.
mod program_receipt_exchange_tests;
