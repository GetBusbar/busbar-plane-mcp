//! Tests for `records.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{KIND_CALL, KIND_DEMOTION, RECORD_SCHEMAS, SCHEMA_CALL, SCHEMA_DEMOTION};

/// The two durable schemas carry the codec's own record kind names.
///
/// If the codec renames a kind, this goes red rather than the plane quietly writing records
/// under a name nothing reads back.
#[test]
fn the_durable_schemas_are_the_codecs_own_kinds() {
    assert_eq!(SCHEMA_CALL.as_str(), KIND_CALL);
    assert_eq!(SCHEMA_DEMOTION.as_str(), KIND_DEMOTION);
}

// THE OPERATION TABLE IS GONE, with the four tests that read it: production never read it (it was
// compiled under test alone), so those tests certified a table, not the plane. The call log's
// append-only property is the record chain the door declares, pinned in `tests/door.rs`
// (`the_call_log_is_the_one_chain_the_host_keeps`); an approval is spent through the host's one-time
// `records.claim`.

/// No schema name is repeated.
#[test]
fn no_schema_is_declared_twice() {
    for (i, schema) in RECORD_SCHEMAS.iter().enumerate() {
        assert!(
            !RECORD_SCHEMAS[..i].iter().any(|s| s == schema),
            "{schema} is declared twice"
        );
    }
}
