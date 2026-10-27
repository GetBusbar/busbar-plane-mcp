//! The fact keys this plane writes. A fact is evidence: never an amount, a decision or a credential.

/// Which registered server the unit is for.
pub const FACT_SERVER: &str = "server";

/// The session fact keys: the caller's protocol revision and the server (a session that changed
/// either mid-flight would be a different priced thing).
pub const SESSION_FACTS: &[&str] = &["protocol_version", FACT_SERVER];

/// The content fact keys: what the answer was FOR and how it ended (its discriminator, subject,
/// server, tool-error flag and protocol error code), never the tool's output itself.
pub const CONTENT_FACTS: &[&str] = &[
    "result_type",
    "subject",
    FACT_SERVER,
    "is_error",
    "error_code",
];
