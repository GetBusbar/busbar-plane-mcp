# Reference control composition

The control has three explicitly different implementations:

- Server: the unchanged official Python `mcp==2.2.0` SDK and `control_server.py`.
- Client: the same SDK, pinned to protocol `2026-07-28`, with an inbound stdio adapter in `control_client.py`. The adapter discards forbidden server-initiated requests before the legacy SDK dispatcher can emit a JSON-RPC response. It does not alter the peer transcript or any harness assertion. Responses, notifications and parsing errors remain SDK inputs. Each RPC has a three-second read timeout and the workload has a twelve-second deadline.
- Host seam: `control_host.mjs`, an independent, deliberately small reference host. It is **not** an official SDK host or the product. Its client driver presents an ephemeral bearer credential over real loopback HTTP; the server authenticates it and records a hash-only witness. The host creates fresh upstream IDs and headers, invokes two separate HTTP fake peers, exposes distinct names for their tools, supplies host-owned descriptions, ignores forbidden upstream requests and returns terminal tool errors when an upstream fails. The existing fake peer supplies the hostile bytes and writes the observer transcript unchanged.

This validates the battery against the declared reference composition. It cannot establish that the unmodified Python client conforms or that the product passed. The original Python client deviation remains in `control-baseline.json` under `resolvedDeviations`; it is not allowed as a failure for this repaired composition. No conformance assertion was weakened.

Run `scripts/setup-control.sh` using the native frozen Python dependency closure, or set `MCP_CONTROL_VENV` to an already prepared pinned environment. Node's built-in modules provide the host fixture; no new npm or Python dependency is introduced.

Targeted validation:

```sh
node --test scripts/control-host-auth.test.mjs
MCP_CONTROL_VENV=/absolute/control-venv bash scripts/run-control.sh push,pr --role client,seam --only 'CLI.NO-RESPONSES-SENT,CLI.HOSTILE.SERVER-INITIATED-REQUEST-IS-NOT-ANSWERED,CLI.HOSTILE.STALLING-SERVER-DOES-NOT-HANG-FOREVER,SEAM.'
```

The native host / CI runs the affected control as a whole:

```sh
MCP_CONTROL_VENV=/absolute/control-venv bash scripts/run-control.sh all
```

The report identity names all three components. The front witness is retained in `reports/control-<tier>-front.jsonl`, and each case's upstream transcript path is supplied by the battery. The generated bearer file is removed at runner exit. Upstream bridges are terminated at host shutdown. The host intentionally supports the battery's configured fake-peer command only and reports an error for other commands. This fixture's loopback HTTP authentication is a control boundary, not an OAuth authorization-server implementation.
