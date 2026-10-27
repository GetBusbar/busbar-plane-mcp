//! The plane's durable state, expressed as record legs rather than as a store this crate holds.
//!
//! A plane performs no input and no output. Everything it needs to remember across units is a
//! KERNEL-HELD record, reached only through a leg of the route plan, verified by the trust unit and
//! journaled like any other reach. So this module declares the schemas and the operations, and the
//! routing method turns each of the codec's present-day reaches into one of them.
//!
//! ## The conversion table
//!
//! The existing codec reaches state in eleven places. Written out in full, because "the store reads
//! became legs" is the kind of sentence that is true of most of them and not all.
//!
//! | what the codec does today | what it becomes |
//! |---|---|
//! | reads the demotion rows at boot to un-advertise a quarantined tool | a `demotion` leg, operation `scan` |
//! | records a demotion, or clears one, when a server is re-contacted | a `demotion` leg, operation `put` or `delete` |
//! | reads the call log back for one caller | a `call` leg, operation `scan` |
//! | appends a call record for what a caller asked for and got | a `call` leg, operation `append` |
//! | spends a one-time approval, exactly once, so a retry cannot re-spend it | an `approval` leg, operation `redeem` |
//! | builds the tool catalogue from configuration on every apply | a `catalogue` leg, operation `scan`, so the catalogue survives a restart with the approvals it was approved under |
//! | resolves one tool, prompt or resource through the catalogue | a `catalogue` leg, operation `get` |
//! | reads a server's registration to decide how to reach it | a `settings` leg, operation `get` |
//! | keeps the per-caller roots generation in memory, so a restart forgets it | a `settings` leg, operation `put` |
//! | keeps the long-running tasks in a process-local map | a `task` leg, so a restart no longer loses a task a caller is waiting on |
//! | keeps a subscription's cursor in memory for the life of one stream | stays in memory: a subscription IS the life of one stream, and a stream does not survive a restart |
//!
//! And the reaches that are NOT records, because they were never this plane's to hold:
//!
//! | what the codec does today | where it goes |
//! |---|---|
//! | charges a meter, once per round | the metering step's locators |
//! | writes an audit row | the audit step's facts |
//! | asks a breaker whether to proceed, and settles it | the breaker unit |
//! | asks governance whether the caller may spend | the admission unit |
//! | fires a gate hook, or a rewrite hook | the hook seats |
//! | resolves a credential for an outbound hop | the egress-auth unit; the plane names the scheme and never sees the secret |
//!
//! ## Two of the schemas are the codec's own names
//!
//! The call and demotion schemas take their identifiers from the codec's own record kinds, so there
//! is one answer to "what is this record called" rather than two that agree today. The other four
//! name state the codec keeps in memory or derives from configuration, and therefore forgets on
//! restart; declaring them here is what makes that forgetting visible.

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

/// The tool catalogue: what each registered server was observed to offer.
pub const SCHEMA_CATALOGUE: RecordSchemaId = RecordSchemaId::new("catalogue");

/// The approvals: the one-time grants a retry must not be able to re-spend.
pub const SCHEMA_APPROVAL: RecordSchemaId = RecordSchemaId::new(KIND_APPROVAL);

/// The settings: each registered server's own configuration as it was applied.
pub const SCHEMA_SETTINGS: RecordSchemaId = RecordSchemaId::new("settings");

/// The long-running tasks a caller may come back for.
pub const SCHEMA_TASK: RecordSchemaId = RecordSchemaId::new(KIND_TASK);

/// The record schemas this plane keeps kernel-held durable records under.
pub const RECORD_SCHEMAS: &[RecordSchemaId] = &[
    SCHEMA_CALL,
    SCHEMA_DEMOTION,
    SCHEMA_CATALOGUE,
    SCHEMA_APPROVAL,
    SCHEMA_SETTINGS,
    SCHEMA_TASK,
];

#[cfg(test)]
#[path = "tests/records.rs"]
mod tests;
