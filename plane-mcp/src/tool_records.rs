//! The plane's durable state, as record schemas the kernel holds (a plane holds no store): the call
//! and demotion schemas take the codec's own record kinds; the others name state it re-derives.

/// The `call` kind — the per-call log record's tag on the store seam.
pub const KIND_CALL: &str = "call";

/// The `demotion` kind — the upstream-demotion record's tag on the store seam.
pub const KIND_DEMOTION: &str = "demotion";

/// The `approval` kind — a completed ask exchange's one-time claim on the host's ledger.
pub const KIND_APPROVAL: &str = "approval";

/// The `task` kind — a long-running task's work handle (`work.open`) and its result, in chunks
/// ([`crate::tool_tasks`]).
pub const KIND_TASK: &str = "task";
