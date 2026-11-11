#!/usr/bin/env bash
# Functional conformance builds the full staged distribution without release LTO.
# Release artifact qualification keeps its own release profile and evidence.
set -euo pipefail
manifest="${1:?staged distribution manifest}"
log="${2:?subject build log}"
target="${CARGO_TARGET_DIR:-$(dirname "$manifest")/target}"
# Stream compiler progress into the retained suite stderr as well as the local log:
# a suite-budget termination must not hide the last completed compilation step.
if CARGO_PROFILE_DEV_DEBUG=0 cargo build --manifest-path "$manifest" --bin busbar \
    --target-dir "$target" 2>&1 | tee "$log" >&2; then
  bin="$target/debug/busbar"
  [ -x "$bin" ] || { printf 'mcp: built binary missing at %s\n' "$bin" >&2; exit 1; }
  printf '%s\n' "$bin"
else
  exit "$?"
fi
