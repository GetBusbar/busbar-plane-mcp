#!/usr/bin/env bash
# The `mcp` conformance suite: official, independent, and real billing scenarios.
#
#   official control   the pinned official suite against a pinned third-party peer (testing/mcp-conformance/mcp-conformance.sh)
#   battery control    the in-house battery against python `mcp` (the pinned SDK), run always
#   negative control   the battery against deliberately broken peers: every one must grade red
#   official subject  the pinned official suite against busbar (this plane in busbar at the pin)
#   battery subject    the in-house battery against the same busbar
#
# Run by testing/conformance/run.sh with CONFORMANCE_OUT, BUSBAR_CHECKOUT, CARGO_TARGET_DIR set.
# The subject is busbar built from $BUSBAR_CHECKOUT with THIS checkout's plane-mcp patched in by a
# run-time cargo --config (nothing is written to a manifest), booted on loopback by
# testing/mcp-conformance/mcp-subject/boot.sh. MCP_NO_SKIPS=1 holds on every subject leg: a skip is red.
# `pass` only when every leg passed; a subject that cannot be built is `fail`, armed, with the reason.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$here" || exit 2
: "${CONFORMANCE_OUT:?}" "${BUSBAR_CHECKOUT:?}"
out="$CONFORMANCE_OUT"; mkdir -p "$out"
SPEC_VERSION="@modelcontextprotocol/conformance@0.2.0-alpha.11"

say() { printf 'mcp: %s\n' "$*" >&2; }
failed=""

verdict() { # <status> <reason>
  python3 -I - "$out/verdict.json" "$1" "$2" "$SPEC_VERSION" <<'PY'
import json, sys
path, status, reason, spec = sys.argv[1:5]
json.dump({"suite": "mcp", "status": status, "armed": True, "standard": "Model Context Protocol",
           "plan": "official suite + in-house battery rev 2026-07-28", "spec_version": spec,
           "reason": reason}, open(path, "w"))
PY
}

# Public tools were built and hashed by the controller before candidate execution.
# Missing inputs are a required failure, never permission to install from the network.
if ! source testing/conformance/mcp-tools/runtime.sh; then
  verdict fail "the pinned offline MCP public tool bundle is unavailable or invalid"
  exit 1
fi

leg() { # <name> <command...>: run, tee to $out/<name>.log, record failure
  local name="$1"; shift
  say "== $name"
  if "$@" >"$out/$name.log" 2>&1; then say "$name: pass"; else
    say "$name: FAIL (tail of $name.log follows)"; tail -40 "$out/$name.log" >&2; failed="$failed $name"; fi
}

leg official-control bash testing/mcp-conformance/mcp-conformance.sh --official-control
leg battery-control  bash testing/mcp-conformance/mcp-conformance.sh --battery-control
leg negative-control bash testing/mcp-conformance/scripts/negative-control.sh

# The subject: busbar at the pin, this checkout's plane patched in, default features (plane-mcp is one).
# compose.sh assembles the subject; the compiler and served protocol legs judge it.
bin=""
if [ -n "${CARGO_TARGET_DIR:-}" ]; then export CARGO_TARGET_DIR; fi
stage="$out/subject-src"
say "== compose subject (busbar at ${BUSBAR_PIN:-?} with this plane)"
manifest="$(bash testing/mcp-conformance/mcp-subject/compose.sh "$BUSBAR_CHECKOUT" "$here/plane-mcp" "$stage")"
say "== build subject ($manifest)"
if cargo build --release --manifest-path "$manifest" --bin busbar \
      --config "patch.\"https://github.com/GetBusbar/busbar-plane-mcp\".busbar-plane-mcp.path=\"$here/plane-mcp\"" \
      >"$out/subject-build.log" 2>&1; then
  bin="${CARGO_TARGET_DIR:-$(dirname "$manifest")/target}/release/busbar"
  [ -x "$bin" ] || { say "built binary missing at $bin"; bin=""; }
fi
if [ -z "$bin" ]; then
  tail -40 "$out/subject-build.log" >&2
  verdict fail "the subject (busbar at the pin with this plane) did not build; legs failed before:${failed:- none}"
  exit 1
fi
export MCP_SUBJECT_BUSBAR_BIN="$bin" MCP_NO_SKIPS=1
for rig in testing/mcp-conformance/mcp-subject/h2-*.sh; do
  case "$rig" in */h2-lib.sh) continue ;; esac
  leg "$(basename "$rig" .sh)" bash "$rig"
done
# Bootstrap connects consume the real admin mutation window. Reserve a fresh
# existing window so the official live mutations are admitted before their timers.
leg official-subject env MCP_OPERATOR_FRESH_WINDOW=1 MCP_SIGNED_EXTRA_RECEIPT="$out/signed-extra-input.json" bash testing/mcp-conformance/mcp-conformance.sh --official-subject
leg battery-subject  bash testing/mcp-conformance/mcp-conformance.sh --battery-subject

if [ -z "$failed" ]; then
  verdict pass "all MCP legs passed"; exit 0
fi
verdict fail "legs failed:$failed (logs in the check output)"; exit 1
