<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-plane-mcp

First-party signed kind:plane plugin cdylib: the mcp plane, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `plane` | `mcp` | `busbar-plane-mcp-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-plane-mcp/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-plane-mcp/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-plane-mcp` is busbar's `kind: plane` plugin for the Model Context Protocol. It serves
busbar's MCP endpoint (`POST /mcp`, its protected-resource metadata document, and the task-run
route) to MCP clients speaking revisions `2026-07-28` (stateless), `2025-11-25`, `2025-06-18` and
`2024-11-05` (event stream), and relays each admitted `tools/call` to the MCP server the operator
registered, over HTTP or a `transport: stdio` child. Each call is held to the operator's approvals
and the caller's grants; the server's tool list is re-verified before a call (verify-on-call).

## Config

Off by default: a document that writes neither section below never uses the plane.

- `tools:` (the section the plane declares): one entry per registered MCP server, keyed by its id,
  and two reserved keys.
  - `<id>.url` or `<id>.transport: stdio` with `command`, `args`, `env`, `cwd`: where the server is.
  - `<id>.pin`: `cert_spki` or `mtls` authenticates the server's certificate key.
    `local_program` identifies a host-launched stdio program as described below. `unpinned`
    declares no authenticity root and cannot approve tools. `pinned_pubkey` is refused because
    this build verifies no MCP manifest signature.
  - `<id>.client_identity`: busbar's client certificate and key for that server (secret references).
  - `<id>.tls.ca_cert_pem`: an optional public PEM certificate bundle added to the trust roots for
    this HTTPS server only. The host validates it before boot or reload publishes the registration.
    It does not replace public roots, certificate-chain/name/validity checks, `pin`, or mTLS.
    Plaintext HTTP and stdio reject `tls:` rather than silently ignoring it. An absent `tls:` keeps
    existing trust unchanged. `client_identity` stays at its existing sibling location; there is no
    nested `tls.client_identity` spelling.
    The bundle does not widen `allow_private` or another server's trust. Changing it on reload
    changes new connections; retained work keeps its previous generation's scoped trust until it ends.
  - `<id>.tools_allow`, `prompts_allow`, `resources_allow`, `resource_templates_allow`: what it may
    publish.
  - `<id>.verify_ttl`, `timeout`, `aud`, `grants`, `allow_private`, `token_exchange`,
    `max_input_required_rounds`, `max_caller_ask_rounds`, `sampling_bounds`,
    `upstream_credentials`, `hooks`: the per-server rules.
  - `tools.hooks`: hooks attached to every server; `tools.upstream_credentials: own`: the default
    credential mode. `passthrough` is refused both here and per server: upstream access must use
    the server's own credential or its configured token exchange.
- `mcp:` (owned beside it, and it selects the plane on its own): the endpoint block.
  - `canonical_uri`: the endpoint's RFC 8707 resource URI (its path is `/mcp`).
  - `authorization_servers`: the issuers that may mint tokens for it (at least one).
  - `scopes_supported`: advisory scopes for the metadata document.
  - `allowed_origins`: browser origins admitted beyond loopback.

An unknown key in either section is refused. `validate` judges both; a reload judges `mcp:` again
and refuses a malformed one, but keeps the endpoint `open` read.


### Host-launched stdio identity

A `transport: stdio` server can use `pin.mechanism: local_program`. Its `pin.key` must equal
its configured absolute `command` path exactly, and it must configure an explicit absolute
`cwd`. This mechanism is confined to the host-owned program need; an HTTP registration cannot
use it. Stdio refuses `cert_spki` and `mtls` because no TLS handshake authenticates their keys.
The host runs the command directly with the admitted arguments and a cleared environment,
resolves only its admitted environment references, and applies the admitted working directory.

The host supplies the first successful lease head only after it has observed a live program
handle from a successful spawn under that same ticket and checked supplier grant. The plane
requires one canonical `generation`, `program-instance`, and base64 `program-identity` field
from that head before sending a greeting or observing tools. A governed call or child reply
opens with the expected checked incarnation and generation; the host compares them against the
current live program before flushing any request body. A replacement or respawn refuses that
open instead of receiving bytes owed to the earlier child. The plane also validates the actual
call lease head before accepting its response. The identity
contains only the configured command path. The private grant binds arguments, environment,
and working directory; no public recipe hash or secret fingerprint is emitted. Missing,
duplicate, unsuccessful, noncanonical, mismatched, repeated, or retired receipts refuse the
exchange. Program incarnations are nonzero and never reused within a live host process; changing the launch recipe creates
a new incarnation, so greeting and request caches cannot reuse an earlier recipe's generation.
A rooted child reply additionally requires the originating plane's locally owned live work handle;
a durable work row or a sealed numeric pair cannot transfer child custody to a fresh plane or
host process.

This authenticates the operator's configured launch under the host grant. It assumes the selected
stdio carrier preserves the host's framing semantics. It does not attest executable bytes, an
inode, signatures, script contents, or arbitrary malicious carrier payloads. Keep the executable
and its inputs under the operator's control. Tool content still requires the usual observation
and approval; a valid launch receipt grants no tool approval on its own.

## Input and resource limits

Malformed endpoint URIs, protocol headers and tool parameter-header annotations are refused before
dispatch. The destination policy checks both tool arguments and URL-bearing replies to relayed
asks. Schema references must resolve inside the registered schema; an exhausted inspection budget
refuses the request rather than inspecting only part of it.

Stdio servers must return a valid initialization result for a supported session revision or,
after an initialization error, valid discovery advertising the supported modern revision before
receiving tool requests. Negotiation currently tries initialization first to preserve supported
session servers that do not answer requests before initialization. This differs from the modern
specification's discovery-first recommendation; a modern server that does not answer initialization
cannot be negotiated by this path. A partial host write is resumed from its remaining bytes.

Local rendered responses are limited to 64 MiB, with bounded normalization work. Task-record
listings retain at most 16 MiB and 16,384 rows per lookup. The local approval replay ledger holds
65,536 live nonces; when full it refuses new approvals until entries expire, without forgetting
previously spent approvals.

## Diagnostics

| code | slug | when |
|---|---|---|
| 7108 | `mcp-legacy-stream-ungoverned` | a `2024-11-05` event stream opened while the deployment runs the ungoverned chain (sessions unisolated); raised once per instance, and audited by the host |

## Build

```bash
cargo build --release -p busbar-plane-mcp-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
