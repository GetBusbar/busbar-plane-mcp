//! The `--help` lines.

/// The `--help` lines this plane owns open with the flag it declares, in the help's own two-column
/// shape, and end without a newline — the root splices them between two lines it owns.
#[test]
fn the_help_flags_open_with_the_declared_flag() {
    let first = super::HELP_FLAGS
        .lines()
        .next()
        .expect("the help lines are not empty");
    assert!(first.starts_with("    --mcp-stdio "), "{first}");
    assert!(!super::HELP_FLAGS.ends_with('\n'));
}
