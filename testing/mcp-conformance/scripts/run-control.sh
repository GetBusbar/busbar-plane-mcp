#!/usr/bin/env bash
# Run the battery against explicitly named reference components: official
# Python SDK server, adapted modern Python client, independent HTTP host fixture.
#
# WHAT THIS JOB PROVES: observations about this explicit reference composition.
# It does not test a product. A red result can reveal a control implementation
# defect, fixture/configuration failure, harness error, or spec interpretation.
# See control/REFERENCE.md for the boundaries and the original SDK deviation.
#
# Usage: scripts/run-control.sh [tier]     tier defaults to push,pr
set -euo pipefail
cd "$(dirname "$0")/.."

TIER="${1:-push,pr}"
VENV="${MCP_CONTROL_VENV:-.venv-control}"
PY="$VENV/bin/python"

if [ ! -x "$PY" ]; then
  echo "control not installed. Run scripts/setup-control.sh first." >&2
  exit 2
fi

mkdir -p reports
# Credentials belong to the front-door client. They are generated for this run,
# checked by the host, and observed as hashes; they are never upstream headers.
CONTROL_STATE="$(mktemp -d "${TMPDIR:-/tmp}/mcp-control.XXXXXX")"
trap 'rm -rf "$CONTROL_STATE"' EXIT
export MCP_SEAM_BEARER_FILE="$CONTROL_STATE/bearer"
export MCP_SEAM_FRONT_TRANSCRIPT="$(pwd)/reports/control-${TIER//,/-}-front.jsonl"
node -e 'require("node:fs").writeFileSync(process.argv[1], require("node:crypto").randomBytes(32).toString("hex"), {mode: 0o600})' "$MCP_SEAM_BEARER_FILE"
export MCP_SUBJECT_UPSTREAM_CONFIG_CMD="node $(pwd)/control/control_host.mjs"
node bin/mcp-battery.mjs run \
  --name "reference-python2.2-server-modern-client-independent-host" \
  --server-cmd "$PY $(pwd)/control/control_server.py" \
  --client-cmd "$PY $(pwd)/control/control_client.py" \
  --failing-tool always_fails \
  --tier "$TIER" \
  --expected-failures control/control-baseline.json \
  --out "reports/control-${TIER//,/-}.json" "${@:2}"
