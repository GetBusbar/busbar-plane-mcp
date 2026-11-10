# Per-user upstream connections: owner boundary and missing dispatch contract

Status: **not implemented**. This records the result of the plugin-only seam qualification against MCP owner `141a42610abec3ea0c5f82cc4bf3f805f6ca4737` and its SDK pin `f0f8155028d63b5cd72125cf679aff1912fcca61`. No core, SDK, authentication plugin or transport changes accompany it. The small regression additions protect current refusals and conversation isolation; they do not implement delegated authorization.

## The user-visible distinction

A Busbar grant already decides whether Bob or Joe may list/call an approved tool. Their upstream conversation sessions are separately keyed. Neither property makes the upstream authenticate Bob as Bob and Joe as Joe: `tools.<server>.token_exchange.subject_token` is explicitly **Busbar's own subject token**, with scopes narrowed using the caller's grants.

The requested behavior needs a separate upstream connection per authenticated principal: authorization for a specific upstream resource, discovery made with that authorization, and calls using that same connection. A missing/expired/revoked connection must not fall back to the operator's account. The inbound Busbar bearer token is not an upstream credential.

The relevant protocol requirements are [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) and [MCP proxy security](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices): resource-bound tokens, PKCE and exact redirect validation, upstream metadata/issuer validation, and consent bound to the downstream client as well as the user. Transparent token passthrough is prohibited. STDIO credentials require a separate design; the HTTP authorization flow does not apply to them.

## What already exists and what is missing

Owner-local source references:

| Existing behavior | Source | Consequence |
| --- | --- | --- |
| Operator subject token and explicit resource audience | `plane-mcp/src/tools_config.rs`, `TokenExchangeCfg`, `McpServerDefCfg::aud` | Scope reduction is implemented; caller identity selection is not. |
| Server + caller session key | `plane-mcp/src/tool_sessions.rs`, `upstream_key`, `UpstreamTable` | A session is not shared across Bob and Joe. Session identity is not proof of credential identity. |
| Discovery cache key `(generation, server)` | `plane-mcp/src/plane_door_impl.rs`, `ListKey`, `list_key` | Correct for the current shared upstream account. Changing it alone would create user-labelled copies of the same account's catalogue. |
| Governed request handoff | `plane-mcp/src/plane_door_impl.rs`, `send_to_member`, `Pending::far` | Main calls go through the selected kernel attempt; the kernel applies its credential binding. |
| Explicit passthrough refusal | `plane-mcp/src/tools_config.rs`, `refuse_passthrough`, `refuse_section_passthrough` | Keep this refusal. It must not become the implementation of delegated authorization. |

SDK/host evidence below is read-only, confirmed at the pinned SDK revision; it is not permission to edit those files:

- `busbar-contract/src/abi/plane/mod.rs::OutField` contains only `name: Span` and `value: Span`. `OnPieceOut` has request body/head, destination-need, usage and verdict outputs, but no opaque credential attachment for a selected attempt.
- `busbar-contract/src/conn.rs::ConnAuth` contains one outbound auth handle, or `per_request: PerRequestHandle`. `handle_now()` takes no caller identity. Its other identity choice is the inbound credential lender for passthrough, which is unsuitable here.
- `busbar-kernel/src/plane_driver/far_end.rs::open_far` selects that existing auth binding, replaces matching plane-supplied fields with the auth result, removes plane-supplied sealed-field/query metadata, and creates sealed metadata from the host's auth result. Adding an ordinary Authorization header is not a custody-preserving extension.
- `busbar-contract/src/abi/sdk/cred/write.rs::SealedWrite::stream_into` refuses material marked `secure_required`. A secure upstream token cannot be exported into arbitrary output spans as a workaround.
- `busbar-contract/src/abi/host/access.rs` allows `AUTH_CALL` to `TransportKind`, not `PlaneKind`; the plane cannot open/select auth bindings through this service.
- `busbar-contract/src/abi/sdk/exchange.rs` does support opaque sealed connector exchanges. Those are suitable building blocks for owner-side authorization/discovery work. Sending every main call through a second connector state machine solely to evade the selected-attempt binding is not the requested integration. It would need a separate proof of route, retry, breaker, accounting, cancellation and authorization semantics.

**The blocking seam is the ordinary selected-attempt credential handoff.** No new MCP-specific kernel concept is necessary. A neutral mechanism is necessary to select or attach owner-held, principal-bound outbound authorization while preserving host custody and the existing attempt.

## Minimum neutral contract requirements

This is a required semantic shape, not a proposed public API spelling:

1. An opaque host-recognized outbound credential attachment, issued under the owning plugin instance and a live authenticated request/work capability. It must be bound to the authenticated principal, declared need/member/destination, upstream resource, connection revision, and authorization expiry. A caller-supplied user name or arbitrary integer handle is not authority.
2. A way for the plane's existing output to reference that attachment for the current selected attempt. The host consumes it through the current protected-field path, enforces its connection-security requirement, and excludes it from ordinary header/debug/record representations. The attachment's relation to configured shared auth must be explicit and exclusive; missing or invalid attachment refuses rather than inheriting shared auth.
3. An atomic validity check at dispatch. Revocation or replacement increments the connection revision; an old pending refresh, discovery, task continuation or queued attempt cannot publish or send under a stale revision. A credential already delivered upstream cannot be recalled; cancellation must not be described as retroactive revocation.
4. The same attachment semantics for the owner's ancillary connector exchanges. Authorization, discovery, initialize, session negotiation, calls and reconnects must consistently use the intended connection. A redirect must never transfer the attachment to another origin/resource.
5. Identical supported behavior through linked and dropped plugin paths. ABI version/layout, handle ownership, cancellation, replay and lifetime tests must cover both. No host branch on an MCP name, protocol, header or configuration key belongs in this mechanism.

MCP owns the OAuth state machine and decides resource/scopes. Generic credential custody and attempt authorization belong to the neutral host. The neutral host must not acquire MCP discovery, consent, Apps, or per-user OAuth vocabulary.

## Owner implementation once the seam exists

The owner keeps a connection record keyed by authenticated principal, upstream registration and downstream client consent binding. Its public state is disconnected, authorizing, connected, refreshing or revoked; secret fields remain opaque `Cred` values in the guarded host-record path. A generated connection ID and monotonic revision prevent replacing an old row from restoring a revoked authorization.

An authorization start binds one-time state, PKCE, exact callback, issuer, upstream resource and downstream client consent. The callback consumes that state once. It validates metadata/issuer and token response before publishing the connection. Tokens with unsuitable audience/resource, a changed upstream/issuer, expired flow, replayed callback or missing consent fail closed. Never capture the incoming Busbar Authorization header as the upstream subject token. Token exchange is another explicitly configured delegated flow, not automatic reuse of that header.

Discovery keys must include registration/config generation, principal and connection revision. A single-flight fetch may be shared only for that exact key. Tools, prompts, resources and templates are discovered with the connection's credential. Display/call authority is the intersection of current Busbar grants, operator approval/drift policy and that connection's discovered catalogue. User-specific schema changes must be reviewed under that connection identity; they cannot mutate another user's approval. Store an entire discovery atomically and reject a completion whose revision changed while in flight.

A call resolves the connection from verified caller context, rechecks grants and approval, and attaches its credential to the existing selected attempt. Session keys add connection revision; Bob's new authorization must not reuse Bob's old account session. Discovery and session expiry are separate from token expiry. A transient discovery failure must not expose a previous account's catalogue.

Refresh is single-flight per connection revision and may install results only if the row is still live at the revision it started from. Refresh failure leaves no usable expired credential. Revocation removes discovery/session access and invalidates outstanding attachments before acknowledging completion; retained audit metadata must contain no tokens. Deletion, expiry, issuer/resource reconfiguration and user replacement follow the same invalidation rule. Credential absence or insufficient upstream scope returns a reconnect/reauthorize condition, not operator-account fallback.

Do not turn on per-user discovery or submit public API settings before the complete path exists. Current server-scoped discovery stays unchanged because it presently describes a shared operator account.

## Qualification owed

The two new owner tests exercise unsupported per-user settings refusing without credential echoes, and conversation forgetting/renewal preserving other callers and request-id monotonicity. Existing passthrough, grant-downscope and session-owner tests remain applicable. None demonstrates upstream user credentials on the wire.

Before claiming implementation, a real upstream fixture must observe distinct Bob/Joe credentials and distinct catalogues through both linked and dropped MCP images. Required adversarial cases include cross-user connection IDs; changed grants; stale discovery; callback replay; wrong issuer/resource; refresh racing revoke; queued calls and tasks across replacement; expired/revoked credentials; redirect handling; retry/reconnect auth; unavailable host/store; and canaries absent from errors, logs, traces, snapshots and public records. Retain both success and refusal controls. Run focused tests locally; full suites belong in CI.

## MCP Apps is a separate next gap

The owner currently has ordinary tools/resources, not a qualified Apps gateway. Apps work requires declared client-capability negotiation, preserving Apps metadata, correct resource MIME/URI handling and namespace isolation, and separating app-only tools from model-visible tools. It needs paired app-capable/non-capable client fixtures and aggregated-server collision tests. Nothing in per-user grants, sessions or the proposed credential seam establishes Apps support. It is not included in this change.
