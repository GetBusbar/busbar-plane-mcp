#!/usr/bin/env bash
# Stage the unchanged MCP harness beside its evidence; the candidate stays read-only.
set -euo pipefail
source_root="${1:?candidate checkout}"
output="${2:?conformance output}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
work="$(mktemp -d "$output/harness.XXXXXXXX")"
tar -C "$source_root" --exclude=testing/mcp-conformance/reports \
  --exclude=__pycache__ --exclude=node_modules --exclude=.venv \
  -cf - testing/mcp-conformance testing/conformance/mcp-tools | tar -C "$work" -xf -
chmod -R u+w "$work"
printf '%s\n' "$work"
