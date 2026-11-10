# Per-user upstream connections

Review checkpoint: implementation is unfinished. The focused protocol tests pass,
but the real TLS owner cell last failed during callback dispatch with
`credential_unavailable`. A core qualified-member matching fix passed its targeted
regression afterward; the TLS cell has not been rerun against that fix. This draft
also requires the new host custody SDK; its repository SDK pin is still pending
fleet integration. The behavior below describes the implementation intent, not a
release-qualified feature.

Set `tools.<server>.upstream_credentials: connection` and configure `oauth` with
`issuer`, `resource`, `client_id`, `redirect_uri`, `authorization_endpoint`,
`token_endpoint`, and `scopes`. The MCP and authorization endpoints must use HTTPS;
a registered loopback HTTP redirect is allowed. These are public-client PKCE
registrations with operator-pinned endpoints. This implementation does not perform
authorization-server metadata discovery, dynamic client registration, confidential
client authentication, or upstream token revocation.

The authenticated caller uses these JSON-RPC methods with `params.server`:

- `connections/authorize`, with explicit `consent: true`, returns the authorization
  URL and consent binding. The browser follows that URL.
- `connections/callback` takes `state`, `iss`, and `code` from the authorization
  response. State is single use and the exchange requires S256 PKCE.
- `connections/discover` refreshes this caller's upstream tool discovery.
- `connections/refresh` exchanges the host-retained refresh request body.
- `connections/revoke` withdraws local consent and fences host-held access and
  refresh custody before acknowledging success.

Normal `tools/list` remains grant-filtered. Calls and discovery are partitioned by
verified host caller identity, member, enrollment, and revision. Client-supplied
`user`, `client_id`, or `clientInfo` does not establish identity. Two downstream
applications sharing the same Busbar credential share the same connection; use
separate authenticated credentials for separate application consent. A connection
never falls back to configured shared credentials or forwards the inbound token.

MCP owns OAuth fields, form construction, PKCE, response validation, and consent
state. The host owns credentials and the encoded refresh body. MCP transfers each
sealed response credential/body once; later operations select only a public
connection identity and revision. Host dispatch checks the authenticated owner,
plugin incarnation, declared need, member, exact URL, expiry, and secure transport.
No OAuth interpretation is added to core. Refresh rotation and revoke invalidate
previous bindings, discovery caches, and session partitions. Already dispatched
network operations cannot be recalled.

All connection state is process-local. Tokens are held in zeroizing allocations,
never persisted as plaintext plane records. Restart requires enrollment again.
Authorization exchanges have a five-minute deadline; access uses the returned
expiry and refresh custody has a thirty-day local ceiling renewed when a new
refresh token is returned. Provider revocation or a shorter provider expiry still
causes refresh to fail. The protocol table has 4096 caller/member rows. Host
custody has 4096 entries across plugin instances and callers, including tombstones;
an access credential and refresh body use separate entries. Revoked identities
remain tombstoned for the process lifetime. New consent mints a new identity;
exhaustion refuses enrollment until restart. This is deliberately bounded,
process-local custody, not durable credential storage.
