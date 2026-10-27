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

/// The discovery path is a FUNCTION OF THE MOUNT: the protected-resource metadata rule inserts the
/// well-known segment between the origin and the resource's own path, so the fixed discovery claim
/// is the one composed from the fixed mount, and another mount would compose another.
#[test]
fn the_discovery_path_is_composed_from_the_mount() {
    let moved = crate::codec::protected_resource_metadata_path("/elsewhere");
    assert_ne!(moved, DEFAULT_METADATA);
    assert!(moved.ends_with("/elsewhere"));
}
