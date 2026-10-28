// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tools:` SECTION: the MCP plane's config grammar, and the one place its values are judged.
//! Which plane an entry is on is decided by the map it is written in; `hooks` and
//! `upstream_credentials` are reserved at the section level as on every plane. A published wire
//! name resolves to exactly one `(server, tool)`, enforced by [`validate_published_names`].

use busbar_contract::{config::UpstreamCreds, section::split_section};

use serde::{Deserialize, Serialize};

/// The separator between a server id and a tool name in the `{server}_{tool}` namespaced routing
/// key. Stated once because it is the ROUTING KEY: the catalogue builds it, the scope
/// grant `mcp_tool` names it, and dispatch parses nothing back out of it.
pub const NAMESPACE_SEP: &str = "_";

/// `{server}_{tool}`: the routing key. One function, so the catalogue, the grant value and every
/// operator-facing rendering are the same string by construction.
pub fn namespaced(server: &str, capability: &str) -> String {
    format!("{server}{NAMESPACE_SEP}{capability}")
}

/// The config section this plane owns: `tools:`.
pub const SECTION: &str = "tools";

/// The singular noun for one registration in the section, as refusals name it.
pub const SUBJECT_NOUN: &str = "MCP server";

/// `elicitation/create`: an ask for the caller's input.
pub const ASK_ELICITATION: &str = "elicitation/create";

/// `sampling/createMessage`: an ask for a completion.
pub const ASK_SAMPLING: &str = "sampling/createMessage";

/// `roots/list`: an ask for the roots the caller exposes.
pub const ASK_ROOTS: &str = "roots/list";

/// THE CLOSED SET of methods a `tools_allow.<tool>.ask_caller` round may name. Boot refuses any
/// other: dispatch would silently drop it and the confirmation gate with it.
pub const ASK_METHODS: &[&str] = &[ASK_ELICITATION, ASK_SAMPLING, ASK_ROOTS];

/// `tools.<server>.pin.mechanism`: which authenticity root this registration has. The `Mcp` prefix
/// keeps the config-schema fingerprint's flat ident map from clashing with a sibling plane's.
/// `cert_spki` and `mtls` pin the FAR END'S KEY: the host seals it into the registration's member
/// route and the connector refuses every connection whose server presents another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpPinMechanism {
    /// A signed tool manifest's operator-supplied, out-of-band issuer public key. It is a root (it
    /// carries key material, and makes the registration approvable), not a pin of the far end's
    /// key: the connector does not compare it with the server's certificate, and this build
    /// verifies no MCP-native manifest signature under it.
    PinnedPubkey,
    /// The endpoint's certificate key, pinned: the host seals it into the registration's member
    /// route and the connector refuses, before a request byte is written, a connection whose
    /// server presents another key (and any connection that is not secured). Not
    /// trust-on-first-use: the key is the operator's, written before the first contact.
    CertSpki,
    /// A client-certificate-authenticated (mutual TLS) binding: the far end's key is pinned as under
    /// `cert_spki`, and busbar presents the registration's `client_identity:` in the handshake.
    /// The operator's config word for it is fixed by the explicit rename below.
    #[serde(rename = "mtls")]
    ClientCertBinding,
    /// NO authenticity root. Registrable, never approvable — low-risk dev use has to be spelled out
    /// loud rather than inferred from an absent field.
    Unpinned,
}

impl McpPinMechanism {
    /// The config token, for diagnostics. Deliberately the same string `serde` accepts.
    pub fn token(self) -> &'static str {
        match self {
            McpPinMechanism::PinnedPubkey => "pinned_pubkey",
            McpPinMechanism::CertSpki => "cert_spki",
            McpPinMechanism::ClientCertBinding => "mtls",
            McpPinMechanism::Unpinned => "unpinned",
        }
    }
}

/// `tools.<server>.pin` — the out-of-band operator-supplied trust root.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPinCfg {
    /// Which root this is. REQUIRED: a pin whose mechanism is inferred is a pin whose meaning
    /// changes when the code that infers it changes.
    pub mechanism: McpPinMechanism,
    /// The operator-supplied material. Under `cert_spki` and `mtls`, the far end's key pin: the
    /// SHA-256 of its certificate's SubjectPublicKeyInfo in standard base64
    /// (`busbar_contract::transport::trust::key_pin`'s spelling, the string the connector compares
    /// the observed key against). Under `pinned_pubkey`, a manifest issuer's public key. Absent
    /// only for `unpinned`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// `tools.<server>.client_identity` — THE CERTIFICATE BUSBAR PRESENTS to this server's endpoint.
///
/// A SIBLING of `pin:`, not a field inside it: `pin:` says how busbar knows the server is the one
/// the operator meant, this says how the server knows the connection is busbar's. The host reads
/// it at the http need's `trust_from` path ([`crate::door::CLIENT_IDENTITY_FROM`]), resolves both
/// references once, and the connector presents the certificate on every connection to the server.
///
/// Both fields are SECRET REFERENCES (`{env: ..}`, `{file: ..}` or a `kind: secret` module), the
/// spelling busbar's own inbound `tls:` uses: there is no way to write PEM bytes here, so a private
/// key never sits in a config dump, a `--validate` output or an admin read.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientIdentityCfg {
    /// PEM certificate chain busbar presents, leaf first.
    pub cert: busbar_contract::secret_ref::SecretRef,
    /// PEM private key for `cert:` (PKCS#8, PKCS#1 or SEC1).
    pub key: busbar_contract::secret_ref::SecretRef,
}

/// `Eq` is asserted rather than derived because [`busbar_contract::secret_ref::SecretRef`] derives
/// only `PartialEq`; every field compares structurally and none is a float, and the registration
/// this rides in must be comparable so a config apply can be recognised as a no-op.
impl Eq for ClientIdentityCfg {}

/// `tools.<server>.tools_allow.<tool>` — one approved tool, and the slot its approved schema hash
/// lives in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAllowCfg {
    /// The APPROVED schema/description hash; empty = pending, which does not serve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_hash: Option<String>,
    /// The description busbar publishes; never an input to routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The tool's JSON Schema, echoed verbatim in `tools/list`. Opaque to busbar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    /// The tool's OUTPUT JSON Schema, published as `outputSchema`; the operator's, never the
    /// upstream's, and never checked against results. Absent = none published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// The wire name busbar publishes (and `mcp_tool:` grants name); absent = `{server}_{tool}`.
    /// Uniqueness is [`validate_published_names`]'s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_as: Option<String>,
    /// The input BUSBAR asks its own caller for before it dispatches this tool. ABSENT ⇒ no ask,
    /// which is deny-by-default and is every deployment that has not opted in. See [`AskEntryCfg`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask_caller: Vec<AskRoundCfg>,
    /// SEP-2663: whether a `tools/call` may, or must, be answered with a task. See [`TaskSupport`].
    #[serde(default, skip_serializing_if = "TaskSupport::is_none")]
    pub task_support: TaskSupport,
    /// The input busbar asks its caller for from INSIDE the task (SEP-2663 `inputRequests`); requires
    /// [`task_support`](Self::task_support) other than `none`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub task_ask_caller: Vec<AskRoundCfg>,
}

/// `tools.<server>.tools_allow.<tool>.task_support`: SEP-2663's registration-time declaration.
/// `required` refuses a caller that did not declare the extension with `-32021`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskSupport {
    /// Answered synchronously, always. The default, so nothing changes for a config that says
    /// nothing.
    #[default]
    None,
    /// A task when the caller declared the extension; a synchronous result when it did not.
    Optional,
    /// A task always, and `-32021` for a caller that cannot receive one.
    Required,
}

impl TaskSupport {
    /// Serde skip predicate — `none` is the default, so writing it back out would put a key into
    /// every serialised tool that no operator typed.
    pub fn is_none(&self) -> bool {
        matches!(self, TaskSupport::None)
    }

    /// Whether a `tools/call` on this tool creates a task, given what the caller declared.
    ///
    /// The caller's declaration is read from the ONE place this revision puts it —
    /// `params._meta['io.modelcontextprotocol/clientCapabilities']` — so a session-level
    /// declaration and SEP-2575's per-request override are literally the same field and cannot
    /// disagree.
    pub fn creates_task(&self, client_declared: bool) -> bool {
        match self {
            TaskSupport::None => false,
            TaskSupport::Optional | TaskSupport::Required => client_declared,
        }
    }
}

/// `tools.<server>.prompts_allow.<name>`: one exposed prompt, markup-normalised on the way out.
/// `template:` (one text message) or `messages:` (typed), never both.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromptAllowCfg {
    /// The description busbar publishes for the prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The prompt TEMPLATE returned by `prompts/get`. Templates sit in the sanitization set
    /// alongside tool output, because a template is exactly as injectable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// The input BUSBAR asks its own caller for before it renders this prompt. Same grammar and
    /// same deny-by-default-by-absence as `tools_allow`'s — one grammar, two paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask_caller: Vec<AskRoundCfg>,
    /// The TYPED form: the `PromptMessage` list `prompts/get` returns verbatim. Absent ⇒ the
    /// `template:` form. Every text field in it is markup-normalised on the way out, exactly as
    /// `template:` is — a second way to put text into a model's context must not be a second way
    /// past the strip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<PromptMessageCfg>,
}

/// ONE ROUND of `ask_caller`: the `inputRequests` key to the request busbar makes.
pub type AskRoundCfg = indexmap::IndexMap<String, AskEntryCfg>;

/// `tools.<server>.{tools,prompts}_allow.<name>.ask_caller[<round>].<key>`: ONE request busbar
/// makes of its own caller, composed only from the operator's literal bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AskEntryCfg {
    /// `elicitation/create`, `sampling/createMessage` or `roots/list` — the closed set
    /// `mrtr.mdx:184-192` names. Anything else is never sent: it names no capability a caller could
    /// have declared, and `mrtr.mdx:246` forbids sending an ask the caller has not declared.
    pub method: String,
    /// The request `params`, EXACTLY as the operator wrote them. Opaque to busbar and never
    /// inspected; what validates them is the caller's own schema check on receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// `tools.<server>.prompts_allow.<name>.messages[]` — ONE typed message.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromptMessageCfg {
    /// The message's role, `user` or `assistant` (default `user`).
    #[serde(default = "default_prompt_role")]
    pub role: String,
    /// The message's content.
    pub content: PromptContentCfg,
}

fn default_prompt_role() -> String {
    "user".to_string()
}

/// One content block, internally tagged by `type` (serde allows no `deny_unknown_fields` here).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PromptContentCfg {
    /// Plain text. The same thing `template:` produces, available inside the typed form so a prompt
    /// that carries an image can also carry the sentence that asks about it.
    Text {
        /// The text.
        text: String,
    },
    /// Base64 image data. `mime_type` is REQUIRED: a client cannot render bytes it has not been told
    /// the type of, and guessing one from the payload would be busbar deciding what the operator
    /// meant.
    Image {
        /// The base64 image bytes.
        data: String,
        /// The image's media type.
        mime_type: String,
    },
    /// Base64 audio data, same rule.
    Audio {
        /// The base64 audio bytes.
        data: String,
        /// The audio's media type.
        mime_type: String,
    },
    /// An EMBEDDED RESOURCE — content carried inline in the prompt rather than fetched.
    Resource {
        /// The embedded resource.
        resource: PromptResourceCfg,
    },
}

/// The resource a `type: resource` content block embeds; its `uri` is an identifier, not a promise.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromptResourceCfg {
    /// The resource's URI.
    pub uri: String,
    /// The resource's media type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// The resource's text content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Base64, and mutually exclusive with `text` for the same reason [`ResourceAllowCfg`]'s pair is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

/// `tools.<server>.resources_allow.<uri>` — one exposed resource, markup-normalised on the way out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAllowCfg {
    /// The name busbar publishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The description busbar publishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The media type busbar publishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// The content `resources/read` returns. In the sanitization set for the same reason as prompt
    /// templates: it re-enters model context verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The BASE64 content `resources/read` returns: exclusive with `text:`, never markup-normalised,
    /// checked to decode at boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

/// `tools.<server>.resource_templates_allow.<uri-template>`: one exposed RESOURCE TEMPLATE (RFC
/// 6570 level 1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceTemplateAllowCfg {
    /// The name busbar publishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The description busbar publishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The media type busbar publishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// The content, its `{param}` placeholders substituted from the URI asked for. No `blob:`: a blob
    /// cannot carry a substitution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// `tools.<server>.sampling_bounds`: the size bounds on a relayed `sampling/createMessage` ask
/// ; past any bound it is refused by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SamplingBoundsCfg {
    /// The most `messages` one ask may carry. Default 64; zero is refused.
    pub max_messages: u32,
    /// The most bytes the system prompt plus every message's content (a text part's text, any other
    /// part as serialised) may total. Default 65536; zero is refused.
    pub max_prompt_bytes: u32,
    /// The most `stopSequences` one ask may name. Default 8.
    pub max_stop_sequences: u32,
    /// The most bytes any one stop sequence may be. Default 64.
    pub max_stop_sequence_bytes: u32,
    /// The lowest `temperature` an ask may name, in thousandths. Default 0.
    pub temperature_min_milli: u32,
    /// The highest `temperature` an ask may name, in thousandths. Default 2000 (`2.0`).
    pub temperature_max_milli: u32,
    /// The most serialised bytes the caller's reply to an ask (its `inputResponses`, with the
    /// `requestState` it carries) may total before it is forwarded to the upstream. Default
    /// 1048576; zero is refused.
    pub max_input_response_bytes: u32,
}

impl Default for SamplingBoundsCfg {
    fn default() -> Self {
        Self {
            max_messages: 64,
            max_prompt_bytes: 64 * 1024,
            max_stop_sequences: 8,
            max_stop_sequence_bytes: 64,
            temperature_min_milli: 0,
            temperature_max_milli: 2000,
            max_input_response_bytes: 1024 * 1024,
        }
    }
}

impl SamplingBoundsCfg {
    /// Whether every bound is at its default (so a serialised definition omits the block).
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The bounds well-formed, or the offending key named.
    pub fn validate(&self, at: &str) -> Result<(), String> {
        if self.max_messages == 0 {
            return Err(format!(
                "{at}: `sampling_bounds.max_messages: 0` would refuse every sampling ask. Set a \
                 positive count (default 64), or leave \
                 `grants.sampling` unset to refuse the ask kind outright."
            ));
        }
        if self.max_prompt_bytes == 0 {
            return Err(format!(
                "{at}: `sampling_bounds.max_prompt_bytes: 0` would refuse every sampling ask. Set \
                 a positive byte count (default 65536), or leave \
                 `grants.sampling` unset to refuse the ask kind outright."
            ));
        }
        if self.max_input_response_bytes == 0 {
            return Err(format!(
                "{at}: `sampling_bounds.max_input_response_bytes: 0` (the key \
                 `tools.<server>.sampling_bounds.max_input_response_bytes`) would refuse every \
                 reply to an ask, so no ask could be answered. Set a positive byte count (default \
                 1048576), or leave the grants unset to refuse the ask \
                 kinds outright."
            ));
        }
        if self.temperature_min_milli > self.temperature_max_milli {
            return Err(format!(
                "{at}: `sampling_bounds.temperature_min_milli: {}` is greater than \
                 `sampling_bounds.temperature_max_milli: {}`; the range (in thousandths) is \
                 empty and every ask naming a temperature would be refused.",
                self.temperature_min_milli, self.temperature_max_milli
            ));
        }
        Ok(())
    }
}

/// The DEFAULT cap on input-required rounds per logical dispatch: a hard cap.
pub const DEFAULT_MAX_INPUT_REQUIRED_ROUNDS: u32 = 3;

/// The DEFAULT cap on rounds busbar may ask its own caller for, per capability.
pub const DEFAULT_MAX_CALLER_ASK_ROUNDS: u32 = 3;

/// The registration key holding its tool approvals (`tools_allow:`), declared to the kernel as its
/// item-approvals trust key.
pub const TOOL_APPROVALS_KEY: &str = "tools_allow";
/// The field of each `tools_allow` entry holding the digest the operator approved the tool at.
pub const TOOL_APPROVAL_FIELD: &str = "schema_hash";

/// The longest an observation is reused before verify-on-call re-fetches, when no `verify_ttl:` is set.
pub const DEFAULT_MCP_VERIFY_TTL: &str = "5s";

/// THE DEFAULT BUDGET of a fetch this door makes of a server that writes no `timeout:` (30 s,
/// `docs/mcp.md`'s `timeout` row).
pub const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 30_000;

/// One entry in the top-level `tools:` map: one registered external MCP server (operator intent only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)] // a typo'd key must fail boot, not silently un-pin a server.
pub struct McpServerDefCfg {
    /// The remote MCP endpoint. Required for `streamable_http`, refused for `stdio` (see [`validate_server`]).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// `transport: stdio` only: the absolute path of the binary busbar spawns (no `PATH`, no shell).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// `transport: stdio` only: the child's argument vector, verbatim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// `transport: stdio` only: the child's WHOLE environment (it is spawned with a cleared one).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub env: std::collections::BTreeMap<String, ChildEnvValue>,
    /// `transport: stdio` only: the child's working directory, absolute. Absent = busbar's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The out-of-band trust root. Required, even when `unpinned`.
    pub pin: ServerPinCfg,
    /// busbar's client certificate for this server ([`ClientIdentityCfg`]). REQUIRED under
    /// `pin.mechanism: mtls`, optional under the other mechanisms, refused on an `http://` url and
    /// on `transport: stdio` (neither has a TLS handshake to present it in).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity: Option<ClientIdentityCfg>,
    /// `<n><s|m|h|d>`: the longest an observation is reused before verify-on-call re-fetches. Absent =
    /// [`DEFAULT_MCP_VERIFY_TTL`]; `0` = every call. Judged by the kernel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_ttl: Option<String>,
    /// `<n><s|m|h|d>`: the budget of one outbound leg to this server. Kernel-owned; this door reads it
    /// only for its own fetches ([`Self::timeout_ms`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// The approved tools, as a MAP so each carries its approved schema hash.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub tools_allow: indexmap::IndexMap<String, ToolAllowCfg>,
    /// The exposed prompts — MCP-specific superset, not one of the locked core keys.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub prompts_allow: indexmap::IndexMap<String, PromptAllowCfg>,
    /// The exposed resources, keyed by URI — MCP-specific superset, likewise.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub resources_allow: indexmap::IndexMap<String, ResourceAllowCfg>,
    /// The exposed resource TEMPLATES, keyed by URI template.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub resource_templates_allow: indexmap::IndexMap<String, ResourceTemplateAllowCfg>,
    /// The transport this registration speaks; absent = streamable HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<ServerTransport>,
    /// The RFC 8707 audience of an OUTBOUND token for this server (not busbar's own audience).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// The server-initiated request grants. Absent ⇒ all denied.
    #[serde(default)]
    pub grants: crate::client::jsonrpc::ServerRequestGrants,
    /// Whether this upstream may live on a private / loopback / CGNAT address. Metadata stays refused.
    #[serde(default)]
    pub allow_private: bool,
    /// RFC 8693 token exchange for this upstream; absent = no credential. The scope is derived per call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_exchange: Option<TokenExchangeCfg>,
    /// The cap on input-required rounds per logical dispatch. Absent ⇒
    /// [`DEFAULT_MAX_INPUT_REQUIRED_ROUNDS`]. `0` is legal and means "never relay one".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_required_rounds: Option<u32>,
    /// The cap on rounds busbar may ask its own caller for, per capability. Absent =
    /// [`DEFAULT_MAX_CALLER_ASK_ROUNDS`]; `0` disables every `ask_caller` on this server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_caller_ask_rounds: Option<u32>,
    /// How large one relayed `sampling/createMessage` ask may be; absent = the defaults.
    #[serde(default, skip_serializing_if = "SamplingBoundsCfg::is_default")]
    pub sampling_bounds: SamplingBoundsCfg,
    /// The outbound credential mode; overrides the section-level default (SCALAR = OVERRIDE).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_credentials: Option<busbar_contract::config::UpstreamCreds>,
    /// Hooks attached to this server by bare name; adds to the section-level `tools.hooks:`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<String>,
}

/// `tools.<server>.token_exchange`: the RFC 8693 exchange busbar performs before it calls this
/// upstream. No `scope:`: it is derived from the caller's grant.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenExchangeCfg {
    /// The operator's authorization server token endpoint (https, vetted at boot).
    pub token_url: String,
    /// BUSBAR'S OWN token, the subject of the exchange, never the caller's.
    pub subject_token: busbar_contract::secret_ref::SecretRef,
    /// RFC 8693 section 2.1 `subject_token_type`; defaults to an access token.
    #[serde(default = "default_subject_token_type")]
    pub subject_token_type: String,
}

/// `Eq` asserted: `SecretRef` derives only `PartialEq`, and no field is a float.
impl Eq for TokenExchangeCfg {}

fn default_subject_token_type() -> String {
    "urn:ietf:params:oauth:token-type:access_token".to_string()
}

/// `tools.<server>.transport` — the MCP transport generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerTransport {
    /// Streamable HTTP, the `2026-07-28` stateless shape. The only one busbar speaks.
    StreamableHttp,
    /// A locally spawned child process, newline-delimited JSON-RPC on its stdin and stdout.
    Stdio,
}

impl ServerTransport {
    /// Whether a registration on this transport is reached by spawning a child (the one question
    /// the grammar asks of the transport: the `structure-lint` gate bans branching on it).
    pub fn spawns_child(self) -> bool {
        match self {
            ServerTransport::StreamableHttp => false,
            ServerTransport::Stdio => true,
        }
    }
}

/// ONE VALUE in a stdio child's environment: a literal, or a secret reference resolved at spawn.
/// A literal is a `Cred`, sealed as it is read: the plane holds no child secret as text.
#[derive(Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum ChildEnvValue {
    /// A literal value; first, so a scalar is never read as a reference.
    Plain(busbar_contract::abi::sdk::cred::Cred),
    /// A secret reference (`{ env: K }` / `{ file: P }`), resolved by the built-in resolver at spawn.
    Secret(busbar_contract::secret_ref::SecretRef),
}

/// `Eq` asserted: `SecretRef` derives only `PartialEq`, and no field is a float.
impl Eq for ChildEnvValue {}

/// A reference is written back as written; a sealed literal is not written back at all.
impl Serialize for ChildEnvValue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            ChildEnvValue::Plain(_) => Err(serde::ser::Error::custom(
                "a stdio child's `env:` literal is sealed and is not written back",
            )),
            ChildEnvValue::Secret(r) => r.serialize(s),
        }
    }
}

/// `Debug` by hand: a literal has no bytes to show; a reference names where the value lives.
impl std::fmt::Debug for ChildEnvValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChildEnvValue::Plain(_) => f.write_str("Plain(<redacted>)"),
            ChildEnvValue::Secret(r) => f.debug_tuple("Secret").field(r).finish(),
        }
    }
}

/// A URL as a refusal may echo it: the userinfo replaced by `***`, every other byte as written.
pub(crate) fn url_for_display(url: &str) -> std::borrow::Cow<'_, str> {
    let start = match url.find("://") {
        Some(i)
            if url[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
        {
            i + 3
        }
        _ => 0,
    };
    let rest = &url[start..];
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    match rest[..end].rfind('@') {
        Some(at) => std::borrow::Cow::Owned(format!("{}***{}", &url[..start], &rest[at..])),
        None => std::borrow::Cow::Borrowed(url),
    }
}

/// The top-level `tools:` map, carrying the two `RESERVED_SECTION_KEYS`
/// alongside the servers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolsCfg {
    /// The ALL-MCP attach list (the reserved `tools.hooks:` key). LIST ⇒ ADDITIVE.
    pub all_server_hooks: Vec<String>,
    /// The ALL-MCP `upstream_credentials:` default. SCALAR ⇒ OVERRIDE.
    pub all_server_upstream_credentials: Option<busbar_contract::config::UpstreamCreds>,
    /// The registrations. Insertion-ordered, so catalogue construction and every operator-facing
    /// listing are deterministic rather than hash-ordered.
    pub servers: indexmap::IndexMap<String, McpServerDefCfg>,
}

impl ToolsCfg {
    /// The effective upstream-credential mode for one server (SCALAR ⇒ OVERRIDE).
    pub fn effective_upstream_credentials(&self, server: &str) -> Option<UpstreamCreds> {
        self.servers
            .get(server)
            .and_then(|d| d.upstream_credentials)
            .or(self.all_server_upstream_credentials)
    }
}

impl<'de> Deserialize<'de> for ToolsCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // The neutral section split, with this plane's value rules (`validate_server`).
        let section = split_section::<D, McpServerDefCfg>(
            deserializer,
            SECTION,
            SUBJECT_NOUN,
            validate_server,
        )?;

        Ok(ToolsCfg {
            all_server_hooks: section.hooks,
            all_server_upstream_credentials: section.upstream_credentials,
            servers: section.entries,
        })
    }
}

/// Which endpoint keys this registration may carry: the two transports take disjoint halves of the
/// grammar, and everything spawn-related is checked here at boot.
fn validate_endpoint(at: &str, def: &McpServerDefCfg) -> Result<(), String> {
    // The transport answers the one question the grammar has of it (`structure-lint`).
    if !def.transport.is_some_and(ServerTransport::spawns_child) {
        for (key, present) in [
            ("command:", def.command.is_some()),
            ("args:", !def.args.is_empty()),
            ("env:", !def.env.is_empty()),
            ("cwd:", def.cwd.is_some()),
        ] {
            if present {
                return Err(format!(
                    "{at}: `{key}` describes a child process to spawn, and this registration is \
                     reached over the network. Set `transport: stdio` if busbar should launch this \
                     server, or drop the key."
                ));
            }
        }
        if def.url.trim().is_empty() {
            return Err(format!("{at}: `url:` must name the MCP server's endpoint"));
        }
        // Scheme is checked here rather than at dispatch so the failure lands on the operator who
        // wrote it, at boot, rather than on a tool call an hour later.
        if !(def.url.starts_with("https://") || def.url.starts_with("http://")) {
            return Err(format!(
                "{at}: `url:` must be an http:// or https:// endpoint, got `{}`",
                url_for_display(&def.url)
            ));
        }
        return Ok(());
    }

    if !def.url.trim().is_empty() {
        return Err(format!(
            "{at}: `transport: stdio` reaches no address, so `url:` cannot be honoured. A \
             registration carrying both has named two different servers; drop one."
        ));
    }
    let Some(program) = def
        .command
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    else {
        return Err(format!(
            "{at}: `transport: stdio` needs `command:` — the absolute path of the binary busbar \
             spawns as this server. There is no default and busbar will not guess one."
        ));
    };
    // ABSOLUTE (`Path::is_absolute`): a bare name is resolved through `PATH`, a relative one against
    // the working directory, so the environment would choose the binary.
    if !std::path::Path::new(program).is_absolute() {
        return Err(format!(
            "{at}: `command: {program}` must be an ABSOLUTE path. A bare name is resolved through \
             `PATH`, which would let whoever controls busbar's environment choose the binary that \
             runs instead of you."
        ));
    }
    if let Some(dir) = def.cwd.as_deref().map(str::trim) {
        if !std::path::Path::new(dir).is_absolute() {
            return Err(format!(
                "{at}: `cwd: {dir}` must be an ABSOLUTE path. A relative one is resolved against \
                 whatever directory busbar was started in, which is not a thing this file can see."
            ));
        }
    }
    for name in def.env.keys() {
        // An empty name, or one containing `=` or NUL, is not a variable an exec can carry.
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(format!(
                "{at}: `env:` name `{name}` is not a usable environment variable name — it must be \
                 non-empty and contain neither `=` nor a NUL byte."
            ));
        }
    }
    // The network keys are refused rather than ignored: a pipe has no header to carry a
    // credential, and no address for `allow_private:` to widen.
    for (set, why) in [
        (
            def.token_exchange.is_some(),
            "`token_exchange:` has no carrier on `transport: stdio` — a pipe has no header \
             block to put a bearer token in. Give the child its credential through `env:`, which is \
             the channel a child process actually reads one from.",
        ),
        (
            def.aud.is_some(),
            "`aud:` is the RFC 8707 resource indicator for an OUTBOUND token, and \
             `transport: stdio` mints none. Drop it.",
        ),
        (
            def.upstream_credentials.is_some(),
            "`upstream_credentials:` selects how busbar credentials a NETWORK hop, and \
             `transport: stdio` makes none. A child process's credential belongs in `env:`.",
        ),
        (
            def.allow_private,
            "`allow_private:` widens the addressing check for a network hop, and \
             `transport: stdio` makes none. Drop it.",
        ),
    ] {
        if set {
            return Err(format!("{at}: {why}"));
        }
    }
    if def.client_identity.is_some() {
        return Err(format!(
            "{at}: `client_identity:` is a TLS client certificate, and `transport: stdio` makes no \
             handshake to present it in. Drop it."
        ));
    }
    Ok(())
}

/// THE CLIENT IDENTITY, matched against the pin's mechanism and the url's scheme.
///
/// `mtls` means the server is served behind mutual TLS: a registration that says so and names no
/// certificate is refused at the server's handshake (`CertificateRequired`), on the first call,
/// rather than here where the operator is. And a client certificate is a TLS-handshake object:
/// over `http://` there is no handshake to present it in, so one written there would read as a
/// protection that is not applied.
fn validate_client_identity(at: &str, def: &McpServerDefCfg) -> Result<(), String> {
    if def.pin.mechanism == McpPinMechanism::ClientCertBinding && def.client_identity.is_none() {
        return Err(format!(
            "{at}: `pin.mechanism: mtls` needs `client_identity:` — the `cert:` and `key:` \
             references to the certificate busbar PRESENTS to this server. `mtls` means the server \
             is served behind mutual TLS, and a client with nothing to present is refused at the \
             handshake with `CertificateRequired`, not at the pin."
        ));
    }
    if def.client_identity.is_some() && def.url.starts_with("http://") {
        return Err(format!(
            "{at}: `client_identity:` is a TLS client certificate and `url:` is `http://`, which \
             has no handshake to present it in. Name an `https://` endpoint, or drop the identity."
        ));
    }
    Ok(())
}

/// Refuse an ask method outside [`ASK_METHODS`]: dispatch would drop it, and the gate with it.
fn refuse_unknown_ask_methods(
    at: &str,
    family: &str,
    capability: &str,
    field: &str,
    rounds: &[AskRoundCfg],
) -> Result<(), String> {
    for (round, entries) in rounds.iter().enumerate() {
        for (key, entry) in entries {
            if !ASK_METHODS.contains(&entry.method.as_str()) {
                return Err(format!(
                    "{at}: `{family}.{capability}.{field}[{round}].{key}.method` is `{}`, which is \
                     not one of the three client-side methods an ask may name ({}). A method \
                     outside that set names no capability a caller could declare, so it would be \
                     dropped at dispatch and this confirmation gate would never be shown.",
                    entry.method,
                    ASK_METHODS.join(", ")
                ));
            }
        }
    }
    Ok(())
}

impl McpServerDefCfg {
    /// The budget of one fetch this door makes of the server, milliseconds: its `timeout:` as the
    /// kernel judged it (the one reading, `busbar_contract::section::entry_timeout_ms`), else
    /// [`DEFAULT_UPSTREAM_TIMEOUT_MS`].
    #[must_use]
    pub fn timeout_ms(&self) -> u64 {
        self.timeout
            .as_deref()
            .and_then(|t| busbar_contract::section::entry_timeout_ms(t).ok())
            .unwrap_or(DEFAULT_UPSTREAM_TIMEOUT_MS)
    }
}

/// THE VALUE-LEVEL RULES for one `tools:` entry, run at boot and by the admin write path alike.
pub fn validate_server(name: &str, def: &McpServerDefCfg) -> Result<(), String> {
    let at = format!("`tools.{name}`");

    // The server id may not contain the separator, so `{server}_{tool}` splits exactly one way.
    if name.contains(NAMESPACE_SEP) {
        return Err(format!(
            "{at}: an MCP server id may not contain `{NAMESPACE_SEP}`. The id is the first half of \
             the `{{server}}{NAMESPACE_SEP}{{tool}}` namespaced routing key; with a \
             separator inside it, two different (server, tool) pairs render the SAME key and one \
             `mcp_tool` scope grant silently names both. Tool names may contain `{NAMESPACE_SEP}` \
             (the canonical `read_file` does) — only the id may not. Rename the server, e.g. \
             `{}`.",
            name.replace(NAMESPACE_SEP, "-")
        ));
    }
    // The routing key's spelling ([`crate::identity::ToolKey`]), refused here in its words.
    let id = crate::identity::ServerId::new(name).map_err(|e| format!("{at}: {e}"))?;

    validate_endpoint(&at, def)?;
    def.sampling_bounds.validate(&at)?;
    validate_client_identity(&at, def)?;

    // The pin, `verify_ttl:` and `timeout:` are the kernel's keys, judged before this validator.

    // THE DEADLINE (`timeout:`) is not judged here either: it is the kernel's reserved per-entry key
    // (`busbar_contract::section::ENTRY_TIMEOUT_KEY`), judged by the kernel before the section
    // reaches this validator, and read through the one reading it judged ([`McpServerDefCfg::timeout_ms`]).

    for (tool, allow) in &def.tools_allow {
        validate_capability_name(&at, "tools_allow", tool)?;
        crate::identity::ToolKey::new(id.clone(), tool)
            .map_err(|e| format!("{at}: `tools_allow.{tool}`: {e}"))?;
        for (field, rounds) in [
            ("ask_caller", &allow.ask_caller),
            ("task_ask_caller", &allow.task_ask_caller),
        ] {
            refuse_unknown_ask_methods(&at, "tools_allow", tool, field, rounds)?;
        }
        // A task-scoped ask on a tool that never creates a task would never be emitted.
        if !allow.task_ask_caller.is_empty() && allow.task_support.is_none() {
            return Err(format!(
                "{at}: `tools_allow.{tool}.task_ask_caller:` is the input busbar asks its caller for \
                 from INSIDE a task, and `task_support:` is absent or `none`, so this tool never \
                 creates one. The ask would never be emitted. Set `task_support: optional` (or \
                 `required`), or move the rounds to `ask_caller:` for the synchronous exchange."
            ));
        }
        // The shape of an override; its uniqueness is `validate_published_names`'s.
        if let Some(publish_as) = &allow.publish_as {
            if publish_as.trim().is_empty() {
                return Err(format!(
                    "{at}: `tools_allow.{tool}.publish_as:` is empty. It is the wire name busbar \
                     publishes for this tool and the value an `mcp_tool:` grant names; an empty one \
                     can be neither called nor granted. Give it a name, or drop the key to publish \
                     the default `{name}{NAMESPACE_SEP}{tool}`."
                ));
            }
            if publish_as.trim() != publish_as.as_str() {
                return Err(format!(
                    "{at}: `tools_allow.{tool}.publish_as: {publish_as:?}` has leading or trailing \
                     whitespace. The published name is compared byte-for-byte against a caller's \
                     `tools/call` name and against an `mcp_tool:` grant, so padding that an operator \
                     cannot see would make both silently miss. Write it without the spaces."
                ));
            }
        }
    }
    for (prompt, allow) in &def.prompts_allow {
        validate_capability_name(&at, "prompts_allow", prompt)?;
        refuse_unknown_ask_methods(
            &at,
            "prompts_allow",
            prompt,
            "ask_caller",
            &allow.ask_caller,
        )?;
        validate_prompt(&at, prompt, allow)?;
    }
    for (uri, allow) in &def.resources_allow {
        if uri.trim().is_empty() {
            return Err(format!("{at}: `resources_allow:` has an empty URI key"));
        }
        // THE TWO FORMS ARE ALTERNATIVES. See `ResourceAllowCfg::blob`.
        if allow.text.is_some() && allow.blob.is_some() {
            return Err(format!(
                "{at}: `resources_allow.{uri}` declares both `text:` and `blob:`. Those are the two \
                 ALTERNATIVE forms of one resource's contents, and a server that carried both would \
                 be leaving a client to choose which of the operator's two answers to believe. Keep \
                 one."
            ));
        }
        if let Some(blob) = &allow.blob {
            validate_base64(&at, &format!("resources_allow.{uri}.blob"), blob)?;
        }
    }
    for (template, allow) in &def.resource_templates_allow {
        let names = validate_uri_template(&at, template)?;
        // A template whose content names no parameter is a concrete resource behind a wildcard.
        if let Some(text) = &allow.text {
            if !names.iter().any(|n| text.contains(&format!("{{{n}}}"))) {
                return Err(format!(
                    "{at}: `resource_templates_allow.{template}` has `text:` that substitutes none \
                     of its parameters ({names:?}), so every expansion answers identical bytes. That \
                     is a concrete resource behind a URI wildcard, and the wildcard approves a whole \
                     shape for no benefit — declare it in `resources_allow:` instead, or use the \
                     parameter."
                ));
            }
        }
    }

    if let Some(tx) = &def.token_exchange {
        // This endpoint receives busbar's own subject token: https, or http only with `allow_private`.
        let private_ok = def.allow_private && tx.token_url.starts_with("http://");
        if !(tx.token_url.starts_with("https://") || private_ok) {
            return Err(format!(
                "{at}: `token_exchange.token_url:` must be https (it receives busbar's own subject \
                 token); plaintext http is permitted only on a registration that also sets \
                 `allow_private: true`. Got `{}`.",
                url_for_display(&tx.token_url)
            ));
        }
        // An exchange mints busbar's credential; `passthrough` says the caller supplies one.
        if matches!(def.upstream_credentials, Some(UpstreamCreds::Passthrough)) {
            return Err(format!(
                "{at}: `token_exchange:` mints BUSBAR's own down-scoped credential, and \
                 `upstream_credentials: passthrough` says the CALLER supplies one. Set one or the \
                 other."
            ));
        }
        // RFC 8707 is required on an exchange, so the token is audience-bound.
        if def.aud.is_none() {
            return Err(format!(
                "{at}: `token_exchange:` requires `aud:` — the RFC 8707 resource indicator the \
                 exchanged token is audience-bound to. A token minted for one upstream must not be \
                 spendable at another."
            ));
        }
    }

    if let Some(aud) = def.aud.as_deref() {
        if !(aud.starts_with("https://") || aud.starts_with("http://")) {
            return Err(format!(
                "{at}: `aud:` is an RFC 8707 resource indicator and must be an absolute http(s) \
                 URI, got `{aud}`"
            ));
        }
    }

    // A dotted hook reference is refused by the kernel, which sees every section; this validator
    // sees only its own.
    Ok(())
}

/// Where a published wire name CAME FROM, so a collision error can name both sides the way the
/// operator will have to fix them: one of them is a line they typed, the other may be a name nobody
/// typed at all.
struct PublishedName {
    server: String,
    /// The map the capability is declared in: `tools_allow`, `prompts_allow`, `resources_allow`
    /// or `resource_templates_allow`.
    family: &'static str,
    /// The capability's key in that map: a tool or prompt name, a URI or a URI template.
    capability: String,
    /// `true` when the name came from `publish_as:`, `false` when it is the `{server}_{tool}`
    /// default. Carried rather than re-derived, because re-deriving means comparing the name to
    /// `namespaced(server, tool)` and getting the wrong answer for the one config where it matters:
    /// `publish_as:` set to exactly the default.
    overridden: bool,
}

impl PublishedName {
    /// The half of the error message that describes ONE claimant.
    fn describe(&self) -> String {
        let Self {
            server,
            family,
            capability,
            overridden,
        } = self;
        if *overridden {
            format!("`tools.{server}.{family}.{capability}.publish_as:`")
        } else {
            format!(
                "the default `{{server}}{NAMESPACE_SEP}{{tool}}` name of \
                 `tools.{server}.{family}.{capability}`"
            )
        }
    }
}

/// THE UNIQUENESS INVARIANT, once, over the WHOLE registry: one published wire name resolves to
/// exactly one `(server, capability)`.
///
/// EVERY CAPABILITY, not only tools. A prompt, a resource and a resource template are published
/// under `{server}_{name}` too, and each is admitted by an `mcp_tool:` grant on that published name
/// (`catalogue::Catalogue::grants`): a tool published as `bar_greet` on server `foo` and a prompt
/// `greet` on server `bar` would make one `mcp_tool: bar_greet` grant admit both.
///
/// This is the validation that replaces the guarantee `{server}_{tool}` used to give by
/// construction, so it has to be TOTAL in both directions or it is not a replacement:
///
/// 1. It walks EVERY tool of EVERY server, building each one's published name — the `publish_as:`
///    override where there is one, the namespaced default where there is not.
/// 2. It compares against that whole set. **Not overrides against each other.** The collision that
///    a naive check misses is an override against a DEFAULT: `publish_as: foo_bar` on any server
///    collides with server `foo`'s tool `bar`, and nobody typed `foo_bar` on the `foo` side for the
///    naive check to compare it with. An implementation that only compared overrides to overrides
///    would accept that config and look correct doing it.
///
/// A collision is refused rather than resolved. Resolving it — last-writer-wins, or an automatic
/// suffix — would leave one wire name pointing at a `(server, tool)` the operator did not choose,
/// and because the engine's `crate::mcp::catalogue` keys the `mcp_tool` grant on the published name, that
/// silently moves an authorization decision. A boot refusal an operator reads is strictly better
/// than a dispatch an hour later that reaches the wrong upstream.
///
/// Called from core's config resolve, through this section's `validate_registry` (the substrate's
/// plane-section seam) — the ONE point every path converges on: boot,
/// `busbar --validate`, the admin config-apply rebuild and the admin dry-run validate endpoint all
/// run it over the EFFECTIVE registry (file base + applied overlay). Deliberately NOT called from
/// `ToolsCfg`'s `Deserialize`: that sees only the file, so a server added through the API would
/// never be compared against it — a check that looked total and was not.
pub fn validate_published_names(cfg: &ToolsCfg) -> Result<(), String> {
    let mut published: std::collections::BTreeMap<String, PublishedName> =
        std::collections::BTreeMap::new();
    for (server, def) in &cfg.servers {
        // THE SAME LINES `Catalogue::build` runs, through the SAME function, and that is
        // load-bearing rather than tidy: this check is only meaningful if the set it walks is
        // byte-identical to the set that is published. A second local `{server}_{tool}` formula
        // here would validate one set and publish another the day either changed.
        let tools = def.tools_allow.iter().map(|(tool, allow)| {
            let name = allow
                .publish_as
                .clone()
                .unwrap_or_else(|| namespaced(server, tool));
            (name, TOOL_APPROVALS_KEY, tool, allow.publish_as.is_some())
        });
        let prompts = def
            .prompts_allow
            .keys()
            .map(|k| (namespaced(server, k), "prompts_allow", k, false));
        let resources = def
            .resources_allow
            .keys()
            .map(|k| (namespaced(server, k), "resources_allow", k, false));
        let templates = def
            .resource_templates_allow
            .keys()
            .map(|k| (namespaced(server, k), "resource_templates_allow", k, false));
        for (name, family, capability, overridden) in
            tools.chain(prompts).chain(resources).chain(templates)
        {
            let claim = PublishedName {
                server: server.clone(),
                family,
                capability: capability.clone(),
                overridden,
            };
            if let Some(prior) = published.get(&name) {
                return Err(format!(
                    "`tools`: two capabilities would both be published as `{name}` — {} and {}. \
                     A published name is the wire name busbar's listings emit, the name a call or \
                     read dispatches on, AND the value an `mcp_tool:` grant names, so one name \
                     meaning two (server, capability) pairs would make one grant silently \
                     authorize both. busbar refuses to boot rather than pick one. Change or remove \
                     a `publish_as:`, or rename one capability.",
                    prior.describe(),
                    claim.describe(),
                ));
            }
            published.insert(name, claim);
        }
    }
    Ok(())
}

/// A capability name must be non-empty (it may contain the separator).
fn validate_capability_name(at: &str, field: &str, name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err(format!("{at}: `{field}:` has an empty name key"));
    }
    Ok(())
}

/// The VALUE rules for one `prompts_allow` entry: one form, a legal role, and decodable media.
fn validate_prompt(at: &str, name: &str, allow: &PromptAllowCfg) -> Result<(), String> {
    if allow.template.is_some() && !allow.messages.is_empty() {
        return Err(format!(
            "{at}: `prompts_allow.{name}` declares both `template:` and `messages:`. Those are the \
             two ALTERNATIVE spellings of what one prompt says — `template:` is the single-text \
             form, `messages:` is the typed form — and honouring one silently would make the answer \
             depend on which branch runs first. Keep one."
        ));
    }
    for (i, message) in allow.messages.iter().enumerate() {
        // The schema names exactly two roles.
        if !matches!(message.role.as_str(), "user" | "assistant") {
            return Err(format!(
                "{at}: `prompts_allow.{name}.messages[{i}].role` is `{}`; a PromptMessage role is \
                 `user` or `assistant`.",
                message.role
            ));
        }
        let field = format!("prompts_allow.{name}.messages[{i}]");
        match &message.content {
            PromptContentCfg::Text { .. } => {}
            PromptContentCfg::Image { data, .. } | PromptContentCfg::Audio { data, .. } => {
                validate_base64(at, &format!("{field}.data"), data)?;
            }
            PromptContentCfg::Resource { resource } => {
                if resource.uri.trim().is_empty() {
                    return Err(format!("{at}: `{field}.resource.uri` must not be empty"));
                }
                if resource.text.is_some() && resource.blob.is_some() {
                    return Err(format!(
                        "{at}: `{field}.resource` declares both `text:` and `blob:`; those are the \
                         two alternative forms of one resource's contents. Keep one."
                    ));
                }
                if let Some(blob) = &resource.blob {
                    validate_base64(at, &format!("{field}.resource.blob"), blob)?;
                }
            }
        }
    }
    Ok(())
}

/// A base64 value that does not decode is refused at boot.
fn validate_base64(at: &str, field: &str, value: &str) -> Result<(), String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| {
            format!(
                "{at}: `{field}` is not valid standard base64 ({e}). A client is told these bytes \
                 are media of a declared type; bytes that do not decode are not media."
            )
        })?;
    Ok(())
}

/// THE URI-TEMPLATE RULES: RFC 6570 level 1 (`{name}`) only, since the higher levels match
/// differently and a mis-match would serve content under an approval nobody gave. Its parameter names.
fn validate_uri_template<'t>(at: &str, template: &'t str) -> Result<Vec<&'t str>, String> {
    if template.trim().is_empty() {
        return Err(format!(
            "{at}: `resource_templates_allow:` has an empty URI-template key"
        ));
    }
    let mut rest = template;
    let mut names: Vec<&str> = Vec::new();
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Err(format!(
                "{at}: `resource_templates_allow.{template}` has a `{{` with no matching `}}`"
            ));
        };
        let name = &after[..close];
        if name.is_empty() {
            return Err(format!(
                "{at}: `resource_templates_allow.{template}` has an empty `{{}}` parameter"
            ));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        {
            return Err(format!(
                "{at}: `resource_templates_allow.{template}` uses `{{{name}}}`, which is not an RFC \
                 6570 LEVEL 1 parameter. busbar implements level 1 (simple string expansion) only: \
                 an operator (`+`, `#`, `/`, `?`, `&`, `*`) expands AND MATCHES differently, and a \
                 matcher that accepted the syntax without the semantics would resolve some URIs to \
                 the wrong template — which is content served under an approval nobody gave."
            ));
        }
        if names.contains(&name) {
            return Err(format!(
                "{at}: `resource_templates_allow.{template}` names `{{{name}}}` twice. Two \
                 occurrences of one parameter can be expanded with two different values, and this \
                 matcher would then have to decide which one the URI meant."
            ));
        }
        names.push(name);
        rest = &after[close + 1..];
    }
    if names.is_empty() {
        return Err(format!(
            "{at}: `resource_templates_allow.{template}` names no `{{parameter}}`, so it is a \
             concrete URI. Declare it in `resources_allow:`."
        ));
    }
    if rest.contains('}') {
        return Err(format!(
            "{at}: `resource_templates_allow.{template}` has a `}}` with no matching `{{`"
        ));
    }
    Ok(names)
}

#[cfg(test)]
#[path = "tests/tools_grammar.rs"]
mod tools_grammar;
