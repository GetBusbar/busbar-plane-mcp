#!/usr/bin/env bash
# Source only: the controller mounts this public dependency closure read-only.
_mcp_tools=/opt/busbar-conformance/mcp-tools
if [ "$(node --version 2>/dev/null)" != v22.23.3 ]; then
  echo 'MCP requires the controller-provided Node 22.23.3' >&2
  return 1
fi
if ! python3 -I - "$_mcp_tools/identity.json" <<'PY'
import json, sys
expected = {
    "schema": "busbar.mcp-public-tools/1",
    "platform": "linux-x86_64", "python": "3.11", "node": "22.23.3",
    "pnpm": "10.26.1", "conformance": "0.2.0-alpha.11", "mcp": "2.2.0",
    "sdk": "cc4b41617ce3601b1290d67216ea0b194a3cd9ac",
}
try:
    assert json.load(open(sys.argv[1])) == expected, "incorrect tool identity"
except (OSError, ValueError, AssertionError) as error:
    raise SystemExit("frozen MCP public tools unavailable: " + str(error))
PY
then
  return 1
fi
export MCP_OFFICIAL_CLI="$_mcp_tools/official-suite/node_modules/@modelcontextprotocol/conformance/dist/index.js"
export MCP_SDK_FIXTURE="$_mcp_tools/everythingServer.cjs"
export MCP_CONTROL_VENV="$_mcp_tools/python"
for _mcp_file in "$MCP_OFFICIAL_CLI" "$MCP_SDK_FIXTURE" "$MCP_CONTROL_VENV/bin/python"; do
  [ -f "$_mcp_file" ] || { echo "frozen MCP tool missing: $_mcp_file" >&2; return 1; }
done
unset _mcp_file _mcp_tools
