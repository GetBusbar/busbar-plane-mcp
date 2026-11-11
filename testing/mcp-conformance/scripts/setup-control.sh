#!/usr/bin/env bash
# Check the pinned CONTROL implementation staged by the controller.
#
# The pin lives in control/requirements.txt and is EXACT. A control upgrade
# changes what "conformant" means for the whole battery, so it must be a
# deliberate, reviewed commit, never a floating range.
set -euo pipefail
cd "$(dirname "$0")/.."

# The controller has already assembled the exact wheel closure outside this checkout.
source ../conformance/mcp-tools/runtime.sh
VENV="$MCP_CONTROL_VENV"
[ -x "$VENV/bin/python" ] || { echo "frozen control interpreter missing" >&2; exit 1; }

echo "control interpreter : $VENV/bin/python"
"$VENV/bin/python" - <<'PY'
import importlib.metadata as md
assert md.version("mcp") == "2.2.0", "incorrect frozen MCP control"
print("control package     : mcp", md.version("mcp"))
from mcp_types.version import MODERN_PROTOCOL_VERSIONS, KNOWN_PROTOCOL_VERSIONS
print("modern revisions    :", ", ".join(MODERN_PROTOCOL_VERSIONS))
print("all known revisions :", ", ".join(KNOWN_PROTOCOL_VERSIONS))
PY
