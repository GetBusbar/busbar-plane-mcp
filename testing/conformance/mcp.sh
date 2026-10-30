#!/usr/bin/env bash
# The `mcp` conformance suite: one command, four judged legs, one verdict.
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

# pnpm builds the control peer (the typescript-sdk fixture; its package.json pins pnpm@10.26.1).
# corepack ships in the node 22 tarball; npm at the same pinned version is the fallback.
if ! command -v pnpm >/dev/null 2>&1; then
  mkdir -p "$out/bin"
  if command -v corepack >/dev/null 2>&1 && corepack enable --install-directory "$out/bin" pnpm >&2; then
    :
  else
    say "corepack unavailable; installing pnpm@10.26.1 with npm"
    npm install --silent --no-audit --no-fund --prefix "$out/pnpm" pnpm@10.26.1 >&2 && ln -sf "$out/pnpm/node_modules/.bin/pnpm" "$out/bin/pnpm"
  fi
  PATH="$out/bin:$PATH"; export PATH
  command -v pnpm >/dev/null 2>&1 || say "pnpm is not available; the official control leg will fail"
fi

# The battery's control (python `mcp`) needs python >= 3.10; ModernCI compute has older. Fetch the
# pinned python-build-standalone 3.12.16 (sha256 checked) when python3 is too old.
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
  case "$(uname -m)" in
    x86_64|amd64) pyasset="cpython-3.12.16+20261026-x86_64-unknown-linux-gnu-install_only.tar.gz"
                  pysha=6a79e922e50006b601f29e688407659da1c2b86ebcd4e9c7254cf234be8b89de ;;
    aarch64|arm64) pyasset="cpython-3.12.16+20261026-aarch64-unknown-linux-gnu-install_only.tar.gz"
                  pysha=a945427411dc6851a1393533b74a4a1ac434321ae397f2ec69897a9b4fde032b ;;
    *) pyasset="" ;;
  esac
  pycache="${MODERNCI_CACHE_DIR:-$HOME/.cache}/conformance-tools"
  if [ -n "$pyasset" ] && [ "$(uname -s)" = Linux ]; then
    mkdir -p "$pycache"
    tgz="$pycache/$pyasset"
    if [ ! -x "$pycache/python-3.12.16-$(uname -m)/python/bin/python3" ]; then
      curl -fsSL --retry 3 -o "$tgz" "https://github.com/astral-sh/python-build-standalone/releases/download/20261026/${pyasset//+/%2B}" \
        && [ "$(sha256sum "$tgz" | cut -d' ' -f1)" = "$pysha" ] \
        && mkdir -p "$pycache/python-3.12.16-$(uname -m)" && tar -xzf "$tgz" -C "$pycache/python-3.12.16-$(uname -m)" \
        || say "could not provision the pinned python"
    fi
    if [ -x "$pycache/python-3.12.16-$(uname -m)/python/bin/python3" ]; then
      export PYTHON="$pycache/python-3.12.16-$(uname -m)/python/bin/python3"
      say "python: pinned 3.12.16 at $PYTHON"
    fi
  fi
fi

# a venv left by an earlier run may have been made with an older python
rm -rf testing/mcp-conformance/.venv-control

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
# compose.sh names the package; compose-selftest.sh holds its rows to this plane before the build.
bin=""
if [ -n "${CARGO_TARGET_DIR:-}" ]; then export CARGO_TARGET_DIR; fi
stage="$out/subject-src"
say "== compose subject (busbar at ${BUSBAR_PIN:-?} with this plane)"
if ! bash testing/mcp-conformance/mcp-subject/compose-selftest.sh "$BUSBAR_CHECKOUT" "$stage" >"$out/subject-compose.log" 2>&1; then
  cat "$out/subject-compose.log" >&2
  verdict fail "the subject's composition does not link this plane (subject-compose.log); legs failed before:${failed:- none}"
  exit 1
fi
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
leg official-subject bash testing/mcp-conformance/mcp-conformance.sh --official-subject
leg battery-subject  bash testing/mcp-conformance/mcp-conformance.sh --battery-subject

if [ -z "$failed" ]; then
  verdict pass "all five legs passed"; exit 0
fi
verdict fail "legs failed:$failed (logs in the check output)"; exit 1
