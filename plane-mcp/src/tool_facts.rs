//! The fact keys this plane writes. A fact is evidence: never an amount, a decision or a credential.

/// Which revision of the protocol the caller asked to be answered under.
pub const FACT_PROTOCOL_VERSION: &str = "protocol_version";

/// Which registered server the unit is for.
pub const FACT_SERVER: &str = "server";

/// Which tool, prompt or resource the request named.
pub const FACT_SUBJECT: &str = "subject";

/// Which discriminator the answer carried.
pub const FACT_RESULT_TYPE: &str = "result_type";

/// Whether the answer said the tool itself failed.
pub const FACT_IS_ERROR: &str = "is_error";

/// The protocol-level error code the answer carried, where it carried one.
pub const FACT_ERROR_CODE: &str = "error_code";

/// The session fact keys this plane writes.
///
/// The revision and the server are session facts because a session that changed either mid-flight
/// would be a different priced thing, and the kernel needs to see that from the outside rather than
/// infer it.
pub const SESSION_FACTS: &[&str] = &[FACT_PROTOCOL_VERSION, FACT_SERVER];

/// The content fact keys this plane produces.
///
/// This is what the record and the export path receive: what the answer was FOR and how it ended.
/// Never the tool's output itself, and never anything the caller presented as authority.
pub const CONTENT_FACTS: &[&str] = &[
    FACT_RESULT_TYPE,
    FACT_SUBJECT,
    FACT_SERVER,
    FACT_IS_ERROR,
    FACT_ERROR_CODE,
];
