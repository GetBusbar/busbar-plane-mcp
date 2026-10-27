//! The operation vocabulary: which method name is which priced operation.
//!
//! This protocol names its operation in the BODY rather than in the path, so the table below is the
//! whole of how a request becomes a unit. One row per method, one class per row, and the class is
//! what the draft declares and what the unit is priced at.
//!
//! ## Why the table is written here rather than read from the codec
//!
//! The codec crate holds this list too, in the constant its dispatch is checked against. That
//! constant is visible to its own crate only, and this crate may not widen it. So the table is
//! written once more here and then PINNED — the tests read the codec's own source and the
//! conformance battery's own suites and assert that neither of them names a method this table does
//! not. A copy that is checked is not a second opinion; a copy that is not checked is.
//!
//! ## Three kinds of row
//!
//! A CLIENT method is one a caller sends and this node answers. A PROVIDER method is one an upstream
//! sends BACK during a call — asking for a completion, for a list of roots, or for something from
//! the caller — which opens a unit of the upstream's own and runs all seven steps over it. A
//! NOTIFICATION is neither: it carries no identifier, obliges no answer, and the specification
//! forbids replying to one.

use busbar_contract::ids::OpClassId;

/// Ask the server what it is and what it supports.
pub const OP_DISCOVER: OpClassId = OpClassId::new("discover");

/// List the tools this caller may use.
pub const OP_TOOLS_LIST: OpClassId = OpClassId::new("tools_list");

/// Call one tool. This is the operation the whole plane exists for, and the one that is priced.
pub const OP_TOOL_CALL: OpClassId = OpClassId::new("tool_call");

/// List the prompts this caller may use.
pub const OP_PROMPTS_LIST: OpClassId = OpClassId::new("prompts_list");

/// Render one prompt.
pub const OP_PROMPT_GET: OpClassId = OpClassId::new("prompt_get");

/// List the resources this caller may read.
pub const OP_RESOURCES_LIST: OpClassId = OpClassId::new("resources_list");

/// List the resource templates this caller may fill in.
pub const OP_RESOURCE_TEMPLATES_LIST: OpClassId = OpClassId::new("resource_templates_list");

/// Read one resource.
pub const OP_RESOURCE_READ: OpClassId = OpClassId::new("resource_read");

/// Complete a partially written argument.
pub const OP_COMPLETION: OpClassId = OpClassId::new("completion");

/// Read one long-running task back.
pub const OP_TASK_GET: OpClassId = OpClassId::new("task_get");

/// Hand a long-running task what it asked for.
pub const OP_TASK_UPDATE: OpClassId = OpClassId::new("task_update");

/// Ask for one long-running task to stop.
pub const OP_TASK_CANCEL: OpClassId = OpClassId::new("task_cancel");

/// Hold open a stream of catalogue changes.
pub const OP_SUBSCRIPTIONS_LISTEN: OpClassId = OpClassId::new("subscriptions_listen");

/// An upstream asking the caller for a completion, mid-call.
///
/// This is provider-initiated: the upstream sends it and busbar relays it to the caller, who answers
/// it or not. busbar runs no completion for it and opens no unit of another plane (Law 11).
pub const OP_SAMPLING: OpClassId = OpClassId::new("sampling");

/// An upstream asking which roots it may work under, mid-call.
pub const OP_ROOTS_LIST: OpClassId = OpClassId::new("roots_list");

/// An upstream asking the caller for something, mid-call.
pub const OP_ELICITATION: OpClassId = OpClassId::new("elicitation");

/// A message that obliges no answer.
pub const OP_NOTIFICATION: OpClassId = OpClassId::new("notification");

/// Every operation class this plane's units can be, in declaration order.
pub const OP_CLASSES: &[OpClassId] = &[
    OP_DISCOVER,
    OP_TOOLS_LIST,
    OP_TOOL_CALL,
    OP_PROMPTS_LIST,
    OP_PROMPT_GET,
    OP_RESOURCES_LIST,
    OP_RESOURCE_TEMPLATES_LIST,
    OP_RESOURCE_READ,
    OP_COMPLETION,
    OP_TASK_GET,
    OP_TASK_UPDATE,
    OP_TASK_CANCEL,
    OP_SUBSCRIPTIONS_LISTEN,
    OP_SAMPLING,
    OP_ROOTS_LIST,
    OP_ELICITATION,
    OP_NOTIFICATION,
];

/// Who sends a method, and whether it obliges an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    /// A caller sends it and this node answers.
    Client,
    /// An upstream sends it back mid-call, opening a unit of its own.
    Provider,
}

/// One row of the vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcMethodRow {
    /// The method name exactly as it appears on the wire.
    pub method: &'static str,
    /// Which operation class a unit carrying it is.
    pub op: OpClassId,
    /// Who sends it.
    pub sender: Sender,
}

/// Every method name this plane reads.
///
/// A name absent from here is a method this plane does not carry, and the decode step says so rather
/// than guessing.
pub const METHODS: &[RpcMethodRow] = &[
    RpcMethodRow {
        method: "server/discover",
        op: OP_DISCOVER,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "tools/list",
        op: OP_TOOLS_LIST,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "tools/call",
        op: OP_TOOL_CALL,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "prompts/list",
        op: OP_PROMPTS_LIST,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "prompts/get",
        op: OP_PROMPT_GET,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "resources/list",
        op: OP_RESOURCES_LIST,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "resources/templates/list",
        op: OP_RESOURCE_TEMPLATES_LIST,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "resources/read",
        op: OP_RESOURCE_READ,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "completion/complete",
        op: OP_COMPLETION,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "tasks/get",
        op: OP_TASK_GET,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "tasks/update",
        op: OP_TASK_UPDATE,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "tasks/cancel",
        op: OP_TASK_CANCEL,
        sender: Sender::Client,
    },
    RpcMethodRow {
        method: "subscriptions/listen",
        op: OP_SUBSCRIPTIONS_LISTEN,
        sender: Sender::Client,
    },
    // The three an upstream sends BACK, mid-call.
    RpcMethodRow {
        method: "sampling/createMessage",
        op: OP_SAMPLING,
        sender: Sender::Provider,
    },
    RpcMethodRow {
        method: "roots/list",
        op: OP_ROOTS_LIST,
        sender: Sender::Provider,
    },
    RpcMethodRow {
        method: "elicitation/create",
        op: OP_ELICITATION,
        sender: Sender::Provider,
    },
];

/// The row for one method name, if this plane carries that method at all.
#[must_use]
pub fn method_row_for(method: &str) -> Option<&'static RpcMethodRow> {
    METHODS.iter().find(|r| r.method == method)
}

#[cfg(test)]
#[path = "tests/ops.rs"]
mod tests;
