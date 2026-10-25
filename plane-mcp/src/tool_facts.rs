//! The fact keys this plane writes.
//!
//! A fact is evidence. It is never an amount, never a decision and never a credential. Everything
//! here is something the plane READ off the bytes, reported under a key it declared up front so the
//! kernel's fact maps can be sized before the first frame arrives.

/// Which revision of the protocol the caller asked to be answered under.
#[cfg(test)]
pub const FACT_PROTOCOL_VERSION: &str = "protocol_version";

/// Which registered server the unit is for.
#[cfg(test)]
pub const FACT_SERVER: &str = "server";

/// Which tool, prompt or resource the request named.
#[cfg(test)]
pub const FACT_SUBJECT: &str = "subject";

/// Which discriminator the answer carried.
#[cfg(test)]
pub const FACT_RESULT_TYPE: &str = "result_type";

/// Whether the answer said the tool itself failed.
#[cfg(test)]
pub const FACT_IS_ERROR: &str = "is_error";

/// The protocol-level error code the answer carried, where it carried one.
#[cfg(test)]
pub const FACT_ERROR_CODE: &str = "error_code";

/// The session fact keys this plane writes.
///
/// The revision and the server are session facts because a session that changed either mid-flight
/// would be a different priced thing, and the kernel needs to see that from the outside rather than
/// infer it.
#[cfg(test)]
pub const SESSION_FACTS: &[&str] = &[FACT_PROTOCOL_VERSION, FACT_SERVER];

/// The content fact keys this plane produces.
///
/// This is what the record and the export path receive: what the answer was FOR and how it ended.
/// Never the tool's output itself, and never anything the caller presented as authority.
#[cfg(test)]
pub const CONTENT_FACTS: &[&str] = &[
    FACT_RESULT_TYPE,
    FACT_SUBJECT,
    FACT_SERVER,
    FACT_IS_ERROR,
    FACT_ERROR_CODE,
];

// THE TWO `_meta` KEYS ARE THE DIALECT'S, AND THERE IS ONE OF EACH. Same reasoning as the error
// codes in `jsonrpc`: restated here while the dialect lived one crate away, re-exported now that it
// does not. A key spelled twice in one crate is a key that can come to differ in one of them.
#[cfg(test)]
pub use crate::codec::{META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION};

/// The metadata key naming a token progress should be reported under.
#[cfg(test)]
pub const META_PROGRESS_TOKEN: &str = "progressToken";
