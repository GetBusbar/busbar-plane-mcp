// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SANITISER'S COMPLEXITY GUARDS — the half of markup-normalisation that is measured in time.

use crate::sanitize::normalise;

/// AN UNTERMINATED `<` MUST NOT COST MORE THAN THE BYTES IT ARRIVED IN.
#[test]
fn unterminated_tags_are_kept_verbatim_without_rescanning_the_tail() {
    let hostile = "<a".repeat(100_000);
    let started = std::time::Instant::now();
    let out = normalise(&hostile);
    let elapsed = started.elapsed();
    assert_eq!(
        out, hostile,
        "with no `>` anywhere in the input, every `<` is a dangling `<`, i.e. ordinary text"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "normalising {} bytes of `>`-less input took {elapsed:?}: the tag scan is re-reading the \
         tail for every `<` instead of remembering that no `>` remains",
        hostile.len()
    );
}

/// NOR MAY THE RECONSTITUTION CHECK, WHICH IS THE OTHER SHAPE AN UPSTREAM GETS TO CHOOSE.
#[test]
fn deep_reconstitution_nesting_does_not_reprocess_the_string_per_level() {
    let depth = 100_000;

    let hostile = format!("{}a{}>", "<".repeat(depth), ">a".repeat(depth - 1));
    let started = std::time::Instant::now();
    let out = normalise(&hostile);
    let elapsed = started.elapsed();

    let _ = &out;
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "normalising {} bytes of {depth}-deep nesting took {elapsed:?}: the seam check is \
         re-running the whole scan once per nesting level",
        hostile.len()
    );
}
