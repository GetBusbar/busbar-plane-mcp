<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
# busbar-plane-mcp

First-party signed kind:plane plugin cdylib: the mcp plane, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `plane` | `mcp` | `busbar-plane-mcp-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-plane-mcp/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-plane-mcp/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-plane-mcp` is a `kind: plane` busbar plugin.

## Config

Configured under the `mcp` module name.

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
