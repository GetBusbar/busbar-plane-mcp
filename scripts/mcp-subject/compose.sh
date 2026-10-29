#!/usr/bin/env bash
# THE SUBJECT'S COMPOSITION: which busbar package the `mcp` suite builds, with this checkout's plane in it.
#
#   compose.sh <busbar checkout> <this plane's crate dir> <stage dir>
#
# Prints the manifest path of the package to build (`cargo build --release --manifest-path <it>
# --bin busbar`, this plane patched in by a run-time --config). Nothing is written to the checkout.
# Held by scripts/mcp-subject/compose-selftest.sh, which mcp.sh runs before the subject build.
set -euo pipefail
checkout="${1:?busbar checkout}"; plane="${2:?plane crate dir}"; stage="${3:?stage dir}"
: "$plane" "$stage"
printf '%s\n' "$checkout/crates/busbar/Cargo.toml"
