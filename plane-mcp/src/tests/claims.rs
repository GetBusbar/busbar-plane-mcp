//! Tests for `claims.rs`. Lifted out of the implementation file so its line count

use super::{DEFAULT_METADATA, DEFAULT_MOUNT};

/// The default mount is the codec's own, and the discovery path is composed from it by the
#[test]
fn the_default_mount_is_the_codecs_own() {
    assert_eq!(DEFAULT_MOUNT, "/mcp");

    assert_eq!(
        DEFAULT_METADATA,
        crate::codec::protected_resource_metadata_path(DEFAULT_MOUNT)
    );
}

/// The discovery path is a FUNCTION OF THE MOUNT: the protected-resource metadata rule inserts the
#[test]
fn the_discovery_path_is_composed_from_the_mount() {
    let moved = crate::codec::protected_resource_metadata_path("/elsewhere");
    assert_ne!(moved, DEFAULT_METADATA);
    assert!(moved.ends_with("/elsewhere"));
}
