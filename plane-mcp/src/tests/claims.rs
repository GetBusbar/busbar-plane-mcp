//! Tests for `claims.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{DEFAULT_METADATA, DEFAULT_MOUNT};

/// The default mount is the codec's own, and the discovery path is composed from it by the
/// codec's own composer.
///
/// Both are read as VALUES. This asked the same two questions of the server half's SOURCE once,
/// with `include_str!` over `../../busbar-mcp/src/…`, which coupled this crate to a sibling its
/// manifest does not name — so the plane could be neither built nor deleted on its own, and the
/// strong-form deletion gate could not see it. The mount and the composer are the codec's now,
/// and both halves call the one composer, so a served route and this claim cannot be two
/// different strings.
#[test]
fn the_default_mount_is_the_codecs_own() {
    assert_eq!(DEFAULT_MOUNT, "/mcp");

    assert_eq!(
        DEFAULT_METADATA,
        crate::codec::protected_resource_metadata_path(DEFAULT_MOUNT)
    );
}

/// The discovery path is a FUNCTION OF THE MOUNT, and this is the assertion that says the note
/// in the module header is still live.
///
/// The protected-resource metadata rule inserts the well-known segment between the origin and
/// the resource's own path,
/// so an operator who moves the mount moves the discovery document with it. If that composition
/// ever collapses into a constant — if the answer stops depending on its argument — this goes
/// red, and the note stops being true and should be deleted. A note that quietly outlives its
/// cause is worse than no note at all.
#[test]
fn the_mount_is_still_configured() {
    let moved = crate::codec::protected_resource_metadata_path("/elsewhere");
    assert_ne!(moved, DEFAULT_METADATA);
    assert!(moved.ends_with("/elsewhere"));
}
