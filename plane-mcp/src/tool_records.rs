//! The plane's durable state, as record schemas the kernel holds (a plane holds no store): the call
//! and demotion schemas take the codec's own record kinds; the others name state it re-derives.

use busbar_contract::ids::RecordSchemaId;

/// The `call` kind — the per-call log record's tag on the store seam.
pub const KIND_CALL: &str = "call";

/// The `demotion` kind — the upstream-demotion record's tag on the store seam.
pub const KIND_DEMOTION: &str = "demotion";

/// The `approval` kind — a completed ask exchange's one-time claim on the host's ledger.
pub const KIND_APPROVAL: &str = "approval";

/// The `task` kind — a long-running task's work handle (`work.open`) and its result, in chunks
/// ([`crate::tool_tasks`]).
pub const KIND_TASK: &str = "task";

/// The call log: what each caller asked for, and what they got.
pub const SCHEMA_CALL: RecordSchemaId = RecordSchemaId::new(KIND_CALL);

/// The quarantine rows: which servers are not being advertised, and why.
pub const SCHEMA_DEMOTION: RecordSchemaId = RecordSchemaId::new(KIND_DEMOTION);

/// The record schemas this plane keeps kernel-held durable records under: the call log, the
/// quarantine rows, the observed catalogue, the one-time approvals, each server's applied settings
/// and the long-running tasks.
pub const RECORD_SCHEMAS: &[RecordSchemaId] = &[
    SCHEMA_CALL,
    SCHEMA_DEMOTION,
    RecordSchemaId::new("catalogue"),
    RecordSchemaId::new(KIND_APPROVAL),
    RecordSchemaId::new("settings"),
    RecordSchemaId::new(KIND_TASK),
];

#[cfg(test)]
#[path = "tests/records.rs"]
mod tests;
