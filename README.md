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
  - `<id>.pin`: the server's authenticity root (`pinned_pubkey`, `cert_spki`, `mtls` or `unpinned`).
  - `<id>.client_identity`: busbar's client certificate and key for that server (secret references).
  - `<id>.tools_allow`, `prompts_allow`, `resources_allow`, `resource_templates_allow`: what it may
    publish.
  - `<id>.verify_ttl`, `timeout`, `aud`, `grants`, `allow_private`, `token_exchange`,
    `max_input_required_rounds`, `max_caller_ask_rounds`, `sampling_bounds`,
    `upstream_credentials`, `hooks`: the per-server rules.
  - `tools.hooks`: hooks attached to every server; `tools.upstream_credentials`: the default
    credential mode (`own` or `passthrough`).
- `mcp:` (owned beside it, and it selects the plane on its own): the endpoint block.
  - `canonical_uri`: the endpoint's RFC 8707 resource URI (its path is `/mcp`).
  - `authorization_servers`: the issuers that may mint tokens for it (at least one).
  - `scopes_supported`: advisory scopes for the metadata document.
  - `allowed_origins`: browser origins admitted beyond loopback.

An unknown key in either section is refused. `validate` judges both; a reload judges `mcp:` again
and refuses a malformed one, but keeps the endpoint `open` read.

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
