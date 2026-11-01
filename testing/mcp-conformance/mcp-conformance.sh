#!/usr/bin/env bash
# MCP CONFORMANCE GATE — the official suite, and the in-house battery, run from busbar's own CI.
#
# WHY THIS RUNS HERE AND NOT WHERE THE BATTERIES LIVE.
#
# A conformance battery is a statement ABOUT BUSBAR, so it belongs where busbar is built and where a
# red blocks the release it is about. A previous attempt ran these in the private design repo, on a
# Gitea instance with no registered runners: eight jobs failed to schedule and stayed permanently
# red, and the only two that reported success ("negative control", "harness self-test") had executed
# nothing. That is the exact defect the batteries exist to catch, one level up — a gate reporting a
# state it never reached — and it is why every mode below ends with an ANTI-VACUITY assertion rather
# than with an exit code.
#
# THE TWO-LEG RULE, which is the whole design of this script.
#
#   CONTROL legs run ALWAYS. A battery that cannot judge a known-good third-party peer cannot be
#   trusted to judge ours. If the control leg is red, the finding is about the harness, the pin or
#   the environment — never about busbar — and it must be visible before any subject verdict is
#   believed.
#
#   SUBJECT legs are ARMED OR RED. They used to skip, and the reasoning for that was sound while
#   busbar answered no MCP method at all: a job red for a reason that is not a defect teaches
#   everyone to read red as noise. It stopped being sound the moment the release claim became "MCP
#   works". A disarmed subject leg proves the SUITE works and proves NOTHING about busbar, and it
#   renders as the same green tick as a leg that judged busbar and passed. So `NOT ARMED, SO NOT
#   RUN` is now a RED STATE — see `require_armed`.
#
#   The ARMED GUARD survives underneath: once armed, a run that produces fewer than the revision's
#   FULL required scenario set is a hard failure. Set equality, never a floor — a floor of 30 is
#   satisfied by any 30 of 37, which is precisely the defect the rule exists to prevent.
#
# MODES
#   --official-control   the official suite against a PINNED third-party SDK, in server mode
#   --official-subject   the official suite against busbar. ARMED OR RED.
#   --battery-control    the in-house adversarial/seam battery against its pinned python control
#   --battery-subject    the in-house battery against busbar. ARMED OR RED.
#   --help
#
# ARMING
#   MCP_SUBJECT_BUSBAR_BIN        THE PRIMARY ARM for the official-suite subject leg: a busbar
#                                 binary built from THIS COMMIT. The leg boots it on loopback,
#                                 gives the suite a real audience-bound credential for it, and
#                                 proves the plane boundary is still intact before believing any
#                                 verdict. See testing/mcp-conformance/mcp-subject/boot.sh.
#   MCP_CONFORMANCE_SUBJECT_URL   an EXTERNAL, already-deployed busbar endpoint. Kept as an optional
#                                 extra leg; it is deliberately no longer the primary arm, because a
#                                 release gate that depends on somebody's deployment being up
#                                 answers a question about that deployment, not about this commit.
#                                 IT ALSO ARMS THE IN-HOUSE BATTERY leg, which boots the same
#                                 binary and reaches it through the stdio→HTTP transport adapter in
#                                 testing/mcp-conformance/scripts/stdio-http-bridge.mjs. That leg
#                                 used to want a stdio launch command NOBODY COULD WRITE — busbar
#                                 has no stdio MCP surface — so it was never once armed.
#   MCP_SUBJECT_SERVER_CMD        a command that starts an MCP server on stdio. Still honoured, and
#                                 it takes precedence, for judging something that is not this build.
#   MCP_SUBJECT_CLIENT_CMD        ... or as an MCP client. Also still honoured and still takes
#                                 precedence, and it is likewise no longer how the release gate gets
#                                 armed: `--battery-subject` builds this command itself out of the
#                                 busbar it just booted (see `client-arm.sh`), because the fourteen
#                                 CLI.* scenarios skipped on `hasClientRole` for as long as nobody
#                                 set it — i.e. always — while the headline number read as a verdict
#                                 on both roles and was one about the server role only.
#   MCP_BATTERY_DIR               the in-house battery. Defaults to testing/mcp-conformance IN THIS
#                                 REPOSITORY and is not expected to be set: the battery was moved
#                                 here (DECISION 2) precisely so no leg depends on a private host.
#
# PINS, and why each is exact:
#   CONFORMANCE_PIN  the suite version. A silent upgrade can never LOOSEN what a gate accepts, so it
#                    is pinned exactly, the same reasoning the plugin trust root uses for keys.
#   SDK_REF          the control peer's commit. An unpinned control leg goes red the day somebody
#                    else's main branch breaks, which trains everyone to ignore this workflow.
#   REVISION         the one MCP protocol revision busbar implements. Running the suite for a
#                    revision we do not implement would produce a failure list that is a to-do,
#                    not a defect.

set -euo pipefail
cd "$(dirname "$0")/../.."

CONFORMANCE_PIN="@modelcontextprotocol/conformance@0.2.0-alpha.11"
REVISION="2026-07-28"

# The in-house adversarial/seam battery. IN THIS REPOSITORY, and that is the whole of DECISION 2:
# it used to be fetched from a private repository on an internal Gitea host with no route
# from a GitHub-hosted runner. Reaching it needed a SECRET and a reachable private host, and the
# moment a control leg depends on a secret, "control legs run ALWAYS" is aspirational. A battery
# that contains no product knowledge by construction loses nothing by being readable, and gains a
# gate that cannot silently stop running. The A2A workflow settled this the same way first.
DEFAULT_BATTERY_DIR="testing/mcp-conformance"

say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# THE SUITE'S NODE. @modelcontextprotocol/conformance imports fs.globSync, which exists from Node 22;
# on Node 20 the suite dies at import, enumerates zero scenarios, and every row it owes reads as a
# failure. The suite needs Node 22, so this script provisions the same major itself rather than
# relying on whatever the runner image ships: a pinned release from nodejs.org, checked against a
# sha256 this file commits, unpacked under target/ and put first on PATH. A runner that already has
# Node >= 22 is left alone. The hash is checked BEFORE the archive is unpacked, and a mismatch, a
# platform with no pin, or a failed download is a refusal, never a fall-back to the old node.
NODE_PIN_VERSION="v22.23.3"
node_pin_sha256() {  # $1 = <os>-<arch> as nodejs.org names them
  case "$1" in
    linux-x64)    echo "1084aa36196bba4c3a5e69a1ee388a6e4ff729dad09445fbcd434b28fe3c24af" ;;
    linux-arm64)  echo "5ced2d48d1d7198739b7f86804de0171aefb6823b684b12341d3321afc3cb0b2" ;;
    darwin-x64)   echo "8a677b0219178efd6eb0e475457c4afb452b521a92f6e67845a73bd85727f2a8" ;;
    darwin-arm64) echo "23b25245dcfb9af7262f8ff142e9e2e0af025368117329e7a7458a51e5922f53" ;;
    *) return 1 ;;
  esac
}
ensure_node22() {
  local have os arch plat want dir tgz got
  have="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  if [ "$have" -ge 22 ] 2>/dev/null; then return 0; fi
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) die "no pinned Node for $(uname -s)" ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) die "no pinned Node for $(uname -m)" ;; esac
  plat="$os-$arch"
  want="$(node_pin_sha256 "$plat")" || die "no pinned Node for $plat"
  dir="$PWD/target/node-pin/node-$NODE_PIN_VERSION-$plat"
  if [ ! -x "$dir/bin/node" ]; then
    mkdir -p "$PWD/target/node-pin"
    tgz="$PWD/target/node-pin/node-$NODE_PIN_VERSION-$plat.tar.gz"
    curl -fsSL --retry 3 -o "$tgz" "https://nodejs.org/dist/$NODE_PIN_VERSION/node-$NODE_PIN_VERSION-$plat.tar.gz" \
      || die "could not download Node $NODE_PIN_VERSION ($plat)"
    if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$tgz" | cut -d' ' -f1)"; else got="$(shasum -a 256 "$tgz" | cut -d' ' -f1)"; fi
    [ "$got" = "$want" ] || { rm -f "$tgz"; die "Node $NODE_PIN_VERSION ($plat) sha256 $got is not the pinned $want"; }
    tar -xzf "$tgz" -C "$PWD/target/node-pin" || die "could not unpack $tgz"
  fi
  export PATH="$dir/bin:$PATH"
  have="$(node -p 'process.versions.node' 2>/dev/null || echo none)"
  case "$have" in "${NODE_PIN_VERSION#v}") ;; *) die "provisioned node reports $have, wanted ${NODE_PIN_VERSION#v}" ;; esac
  say "node: provisioned $NODE_PIN_VERSION ($plat), sha256 verified"
}

# The subject-boot harness: build-from-this-commit, boot on loopback, obtain a real audience-bound
# credential, and PROVE the plane boundary is intact before any verdict is believed. Sourced rather
# than inlined because it is a substantial piece of reasoning of its own; sourced AFTER `say`/`die`
# because it uses both.
# shellcheck source=testing/mcp-conformance/mcp-subject/boot.sh
. "$(dirname "$0")/mcp-subject/boot.sh"

# ONE REAPER, INSTALLED BEFORE ANYTHING IS SPAWNED, and it reads its list when it FIRES rather than
# when it is installed.
#
# The two defects this shape exists to refuse. First, `boot_busbar_subject` spawns three processes
# (the diagnostic upstream, busbar, the credential shim) and only its CALLER used to install the
# trap, so a boot that died partway — a config busbar refuses, a shim that will not start — left
# whatever had already started running with nothing arranged to kill it. Those orphans hold their
# loopback ports, and a busbar left over from an earlier commit is a subject a LATER run can be
# pointed at and judged against: a verdict about a binary that is not the one under test.
#
# Second, a trap installed per-site with the pid EXPANDED AT INSTALL TIME is a trap that overwrites
# whatever the previous site installed. `trap` is process-global, so the subject leg's trap replaced
# the control leg's and the control peer stopped being reaped at all. The list below is ADDITIVE and
# `$SUBJECT_PIDS` is read at fire time, so a boot that sets it after the trap is armed is still
# covered.
REAP_PIDS=""
SUBJECT_PIDS=""
reap_all() {
  local p started=$SECONDS live
  for p in $REAP_PIDS ${SUBJECT_PIDS:-}; do kill "$p" 2>/dev/null || true; done
  while :; do
    live=""
    for p in $REAP_PIDS ${SUBJECT_PIDS:-}; do
      kill -0 "$p" 2>/dev/null && live="$live $p"
    done
    [ -n "$live" ] || break
    [ "$((SECONDS-started))" -lt 2 ] || break
    sleep 0.1
  done
  for p in $live; do kill -KILL "$p" 2>/dev/null || true; done
  for p in $REAP_PIDS ${SUBJECT_PIDS:-}; do wait "$p" 2>/dev/null || true; done
}
reap_add() { REAP_PIDS="$REAP_PIDS $*"; }
trap reap_all EXIT

usage() { awk 'NR == 1 {next} /^#/ {sub(/^# ?/, ""); print; next} NF {exit}' "$0"; }

# ARMED OR RED, in one place so it can be tested in one place.
#
# `require_armed <label> <VAR> [VAR...]` succeeds if ANY named variable is non-empty, and dies
# otherwise. The death is the point: it is what turns `NOT ARMED, SO NOT RUN` from a green tick
# into a failure.
require_armed() {
  local label="$1"; shift
  local v
  for v in "$@"; do
    if [ -n "${!v:-}" ]; then
      say "   armed by $v"
      return 0
    fi
  done
  printf '%s\n' "" >&2
  printf 'FAIL: %s\n' "NOT ARMED, SO NOT RUN — and that is RED." >&2
  cat >&2 <<'BANNER'

  This leg judges BUSBAR. Disarmed, it judges nothing, and it reports the same
  green tick as a leg that judged busbar and passed. That is the false green
  this whole gate exists to refuse, so an unarmed subject leg FAILS.

  Arm it with any ONE of:
BANNER
  for v in "$@"; do printf '      %s=...\n' "$v" >&2; done
  cat >&2 <<'BANNER'

  In CI these are repository VARIABLES, never secrets: an endpoint URL is not a
  credential, and putting it in `secrets` would mask it out of the very logs
  someone debugging an armed run has to read.

BANNER
  exit 1
}

# Every scenario the pinned suite says REVISION requires of a server. This is the SET the runs below
# are compared against: "the suite exited 0" is satisfied by a suite that ran nothing.
required_server_scenarios() {
  npx --yes "$CONFORMANCE_PIN" list --server --requirements "$REVISION" 2>/dev/null \
    | awk '/^Server scenarios/{f=1;next} /^[A-Za-z]/{f=0} f && /^  - /{sub(/^  - /,""); sub(/ .*$/,""); print}'
}

# The scenarios a run actually EXECUTED, read off the results directory the suite writes. A run that
# reports success having produced no scenario directory executed nothing, and this is the only place
# that distinction is visible.
executed_scenarios() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  # The suite names each directory `server-<scenario>-<ISO-8601 stamp>`. The stamp is stripped by
  # its EXACT shape rather than by a loose character class: a class of `[0-9T:.Z-]` is greedy and
  # would eat the numeric tail of a scenario named `sep-2164`, silently reporting a scenario that
  # ran as one that did not — which turns this anti-vacuity check into a source of false reds.
  find "$dir" -maxdepth 1 -type d -name 'server-*' -print 2>/dev/null \
    | sed -E -e 's|.*/server-||' \
             -e 's/-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{3}Z$//' \
    | sort -u
}

# THE ANTI-VACUITY ASSERTION. Two halves, and both are needed:
#   (1) a FLOOR, so a run that produced nothing cannot pass;
#   (2) SET EQUALITY against what the revision requires, so a run that quietly stopped covering half
#       the surface cannot pass either. A floor alone is satisfied by any 30 of 37.
assert_covered() {
  local dir="$1" label="$2"
  local req exe
  local missing count
  req=$(required_server_scenarios)
  [ -n "$req" ] || die "$label: the pinned suite listed NO required server scenarios for $REVISION. \
The pin, the revision name, or the suite's own list command is wrong — believing a verdict computed \
against an empty requirement set is how a gate passes without executing."
  count=$(printf '%s\n' "$req" | grep -c . || true)
  exe=$(executed_scenarios "$dir")
  [ -n "$exe" ] || die "$label: the run reported a verdict but produced NO scenario results in \
$dir. Exit code 0 from a suite that executed nothing is a false green."
  missing=$(comm -23 <(printf '%s\n' "$req" | sort -u) <(printf '%s\n' "$exe") || true)
  [ -z "$missing" ] || die "$label: $REVISION requires scenarios that this run never executed:
$missing
A verdict that skipped part of the required set is not a verdict about that set."
  say "  ok: $count required scenarios, all executed"
}

# THE BASELINE IS EVIDENCE, NOT A SWITCH (item 534). `--expected-failures` turns named failures
# into a green exit, so a baseline that is empty, unexplained, names scenarios the revision does not
# require, or excuses the WHOLE required set is a way to make the subject leg green over nothing.
# The house format is the suite's own (`server:` / `client:` lists of `<scenario>` or
# `<scenario>:<check-id>`), one entry per line, and EVERY entry carries its reason as a trailing
# comment:
#     server:
#       - tools-call-error:some-check   # reason: <why this is accepted, and where it is tracked>
assert_baseline() {
  local file="$1"
  python3 - "$file" "$(required_server_scenarios)" <<'PY' || exit 1
import re, sys
path, required = sys.argv[1], set(filter(None, sys.argv[2].split("\n")))
if not required:
    raise SystemExit(f"FAIL: baseline {path}: the required scenario set is empty; nothing to check it against.")
entries, errs, section = [], [], None
for n, line in enumerate(open(path, encoding="utf-8"), 1):
    body = line.rstrip("\n")
    if not body.strip() or body.lstrip().startswith("#"):
        continue
    m = re.fullmatch(r"(server|client):\s*(#.*)?", body)
    if m:
        section = m.group(1); continue
    m = re.fullmatch(r"\s+-\s+([^\s#]+)\s*(?:#\s*(.*))?", body)
    if not m or section is None:
        errs.append(f"line {n}: not a '<section>:' header or a '  - <entry>  # reason' line: {body!r}"); continue
    entry, reason = m.group(1), (m.group(2) or "").strip()
    if not reason:
        errs.append(f"line {n}: '{entry}' carries no reason comment"); continue
    scen = entry.split(":", 1)[0]
    if section == "server" and scen not in required:
        errs.append(f"line {n}: '{scen}' is not a scenario the revision requires of a server")
    entries.append((section, entry))
if not entries and not errs:
    errs.append("the file is present but lists no entries -- delete it, or say what it accepts and why")
whole = {e for s, e in entries if s == "server" and ":" not in e}
if required and whole >= required:
    errs.append(f"it excuses EVERY one of the {len(required)} required scenarios -- that is not a baseline, it is the leg switched off")
if errs:
    raise SystemExit(f"FAIL: baseline {path} is not acceptable evidence:\n  " + "\n  ".join(errs))
print(f"  ok: baseline {path}: {len(entries)} reasoned entr{'y' if len(entries) == 1 else 'ies'}")
PY
}

# EXECUTED IS NOT PASSED (item 534). `assert_covered` proves each required scenario RAN; this proves
# enough of them PASSED, read from each scenario's own `checks.json` rather than from the suite's
# exit code: every required scenario the baseline does not name must have a checks.json with no
# FAILURE check in it.
assert_passed() {
  local dir="$1" label="$2" bl="${3:-}" required
  required=$(required_server_scenarios) || die "$label: could not read the pinned scenario set"
  [ -n "$required" ] || die "$label: the pinned required scenario set is empty"
  python3 - "$dir" "$label" "$required" "$bl" <<'PY' || exit 1
import json, os, re, sys
d, label, required, bl = sys.argv[1], sys.argv[2], sorted(set(filter(None, sys.argv[3].split("\n")))), sys.argv[4]
excused, section = set(), None
if bl:
    for line in open(bl, encoding="utf-8"):
        header = re.fullmatch(r"(server|client):\s*(#.*)?\n?", line)
        if header:
            section = header.group(1)
            continue
        m = re.fullmatch(r"\s+-\s+([^\s#]+).*\n?", line)
        if m and section == "server":
            excused.add(m.group(1))
stamp = re.compile(r"-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{3}Z$")
by_scen = {}
for name in os.listdir(d):
    if name.startswith("server-") and os.path.isdir(os.path.join(d, name)):
        by_scen.setdefault(stamp.sub("", name[len("server-"):]), []).append(os.path.join(d, name))
bad = []
for scen in required:
    dirs = by_scen.get(scen, [])
    if not dirs:
        bad.append(f"{scen}: no result directory")
    for sd in dirs:
        try:
            checks = json.load(open(os.path.join(sd, "checks.json")))
        except (OSError, ValueError):
            checks = None
        if not isinstance(checks, list) or not checks:
            bad.append(f"{scen}: no nonempty readable check list in {sd}")
            continue
        executed = False
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("id"), str) or not check["id"]:
                bad.append(f"{scen}: malformed check evidence in {sd}")
                continue
            status = check.get("status")
            if status not in ("SUCCESS", "FAILURE", "WARNING", "INFO", "SKIPPED"):
                bad.append(f"{scen}:{check['id']}: unknown check status {status!r}")
                continue
            if status in ("SUCCESS", "FAILURE", "WARNING"):
                executed = True
            if status in ("FAILURE", "WARNING") and scen not in excused and f"{scen}:{check['id']}" not in excused:
                bad.append(f"{scen}:{check['id']}: {status} and is not in the baseline")
        if not executed:
            bad.append(f"{scen}: no evaluated checks (only informational, skipped or unrecognised entries) in {sd}")

if bad:
    raise SystemExit(f"FAIL: {label}: required scenarios did not pass, whatever the exit code said:\n  " + "\n  ".join(bad))
print(f"  ok: {len(required)} required scenarios supplied executed checks; failures matched exact server waivers")
PY
}

# The control peer: the spec authors' own TypeScript SDK, running its conformance fixture server.
#
# Driven DIRECTLY rather than through the suite's `sdk` subcommand, and the reason is a defect that
# subcommand has on a cold runner: it rebuilds the SDK (which invalidates tsx's compile cache) and
# then allows the fixture server 15 seconds to become ready. On a fresh runner that boot takes
# longer, so the control leg fails for a reason that is not a finding — the precise failure mode this
# whole script is arranged to avoid. Driving it here means the readiness wait is OURS and generous.
#
# The second, larger benefit: the control leg then runs the EXACT command the subject leg runs
# (`conformance server --url …`). A control that exercises a different code path from the subject
# proves less than it appears to.
#
# This does couple the control leg to a third party's file layout (`test/conformance/src/
# everythingServer.ts`, and its `PORT` environment variable). That coupling is safe precisely because
# the checkout is pinned to a commit: a pinned tree's layout cannot move underneath us, and a
# deliberate pin bump is where a layout change should be discovered.
#
# THE PORT IS ASKED OF THE OS, not taken as the fixture's default 3000, for the same reason
# `subject_free_ports` exists in boot.sh. On a fixed port there is no proof that the thing answering
# is the peer THIS leg started: a fixture left behind by a killed run, or an unrelated dev server on
# a developer's machine, answers the readiness probe and is then judged as the reference. That is a
# control leg reporting on somebody else's process, and if it happens to pass it licenses every
# subject verdict in the run.
SDK_REPO="https://github.com/modelcontextprotocol/typescript-sdk.git"
SDK_REF="cc4b4161"
SDK_FIXTURE="test/conformance/src/everythingServer.ts"
CONTROL_READY_TIMEOUT=240

official_control() {
  say "== OFFICIAL SUITE · CONTROL leg (pinned third-party peer: typescript-sdk@$SDK_REF) =="
  say "   A battery that cannot judge a known-good peer cannot judge ours. This leg runs ALWAYS."
  local dir=.mcp-conformance
  local sdk="$dir/sdk"
  mkdir -p "$dir"
  if [ ! -d "$sdk/.git" ]; then
    git clone --filter=blob:none "$SDK_REPO" "$sdk" >/dev/null 2>&1 \
      || die "could not clone the control peer. A finding about the runner's network, not busbar."
  fi
  # THE BUILD IS SKIPPED ONLY ON PROOF THAT THE TREE IS ALREADY THE PIN, BUILT.
  #
  # The clone was already conditional, but everything after it was not, so a restored cache still
  # paid a fetch, a checkout, an install and a 53-package workspace build — the cache saved the
  # download and nothing else. The stamp below is written ONLY after a build that succeeded, and it
  # records the exact commit that was built; a tree whose HEAD has moved, a tree restored from a
  # cache keyed on a different pin, and a tree whose build died halfway all lack a matching stamp
  # and are rebuilt in full. An absent or stale stamp always means "build", so the fast path can
  # only ever be taken over a tree this script itself finished building at this pin.
  local stamp="$sdk/.busbar-built-ref" head=""
  head="$(git -C "$sdk" rev-parse HEAD 2>/dev/null || true)"
  if [ -n "$head" ] && [ "${head#"$SDK_REF"}" != "$head" ] \
     && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$head" ]; then
    say "   control peer already built at $SDK_REF; reusing the restored tree"
  else
    git -C "$sdk" fetch --quiet origin "$SDK_REF" 2>/dev/null || git -C "$sdk" fetch --quiet origin
    git -C "$sdk" checkout --quiet "$SDK_REF" \
      || die "the pinned control-peer commit $SDK_REF is not reachable. Bump the pin deliberately; \
never float it to a branch, or this leg goes red the day somebody else's main breaks."
    say "   building the control peer at $(git -C "$sdk" rev-parse --short HEAD)"
    rm -f "$stamp"
    ( cd "$sdk" && pnpm install --frozen-lockfile && pnpm run build:all ) >"$dir/build.log" 2>&1 \
      || { tail -40 "$dir/build.log" >&2; die "the control peer would not build. Harness/runner \
finding, not a busbar finding."; }
    git -C "$sdk" rev-parse HEAD >"$stamp"
  fi

  # A free loopback port, asked of the OS immediately before the fixture is told to use it. The
  # window between the probe closing the socket and the fixture binding it is small and the fixture
  # exits loudly if it loses the race ("Port … is already in use"), which the readiness liveness
  # check below turns into a prompt red rather than a four-minute wait.
  local sdk_port
  sdk_port="$(node -e '
    const s = require("net").createServer();
    s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => console.log(p)); });
  ')"
  [ -n "$sdk_port" ] || die "could not obtain a free loopback port for the control peer."
  local SDK_URL="http://localhost:$sdk_port/mcp"
  say "   control peer will listen on 127.0.0.1:$sdk_port"

  ( cd "$sdk" && PORT="$sdk_port" exec node --import tsx "$SDK_FIXTURE" ) >"$dir/control-server.log" 2>&1 &
  local server_pid=$!
  reap_add "$server_pid"

  # READINESS BY OBSERVATION, not by sleeping. The wait ends when the endpoint answers ANYTHING —
  # a 4xx is a perfectly good proof that a server is listening, and waiting for a 2xx would make
  # readiness depend on the very behaviour under test.
  #
  # THE LIVENESS CHECK IS PART OF READINESS. Without it, "something answered" is the whole of the
  # proof, and a peer that died on startup while a different process holds the port reads as ready.
  # The pair — our own port, and our own process still alive on it — is what makes the reference a
  # reference.
  local started=$SECONDS waited=0
  until curl -s -o /dev/null --max-time 5 "$SDK_URL" -X POST -H 'content-type: application/json' -d '{}'; do
    kill -0 "$server_pid" 2>/dev/null || {
      tail -30 "$dir/control-server.log" >&2
      die "the control peer exited during boot; nothing this leg reports would be about it."
    }
    waited=$((SECONDS-started))
    [ "$waited" -lt "$CONTROL_READY_TIMEOUT" ] || {
      tail -30 "$dir/control-server.log" >&2
      die "the control peer did not become ready within ${CONTROL_READY_TIMEOUT}s."
    }
    sleep 2
  done
  say "   control peer ready after ${waited}s"

  rm -rf "$dir/control"
  mkdir -p "$dir/control"
  npx --yes "$CONFORMANCE_PIN" server --url "$SDK_URL" --requirements "$REVISION" \
      -o "$dir/control" \
    || die "the official suite could not judge the pinned reference SDK. This is a finding about \
the harness, the pin or the runner — NOT about busbar. Do not read any subject verdict until it is \
green."
  assert_covered "$dir/control" "official control"
  assert_passed "$dir/control" "official control"
}

official_subject() {
  say "== OFFICIAL SUITE · SUBJECT leg (busbar) =="
  # ARMED BY A BINARY, and only secondarily by a URL. See testing/mcp-conformance/mcp-subject/boot.sh for why the
  # subject is built from this commit and booted in this job rather than being an endpoint somebody
  # deployed: a release gate that depends on a live deployment produces two unreadable verdicts, a
  # green that means "the deployment was fine yesterday" and a red that means "somebody redeployed".
  # `MCP_CONFORMANCE_SUBJECT_URL` is kept as an OPTIONAL EXTRA leg for an operator who also wants a
  # real deployment judged; it is no longer how this gate gets armed.
  require_armed "official subject" MCP_SUBJECT_BUSBAR_BIN MCP_CONFORMANCE_SUBJECT_URL

  local target
  if [ -n "${MCP_SUBJECT_BUSBAR_BIN:-}" ]; then
    # The reaper is already armed and reads SUBJECT_PIDS when it fires, so a boot that dies between
    # its first spawn and its last one leaves nothing behind.
    SUBJECT_PIDS=""
    boot_busbar_subject
    target="$SUBJECT_URL"
  else
    target="$MCP_CONFORMANCE_SUBJECT_URL"
    say "   armed by an EXTERNAL endpoint only: $target"
    say "   NOTE: this judges whatever is deployed there, which may not be this commit."
  fi

  # The results directory is a variable so the OPTIONAL external leg can run in the same job without
  # overwriting the booted subject's evidence. Two runs that both wrote here would leave one verdict
  # standing over the other's artifact, which is exactly the "reading a report from a previous run"
  # defect the battery leg already has a hard error for.
  local out="${MCP_SUBJECT_OUT:-.mcp-conformance/subject}"
  rm -rf "$out"
  mkdir -p "$out"
  local baseline=() bl="${MCP_CONFORMANCE_BASELINE:-qa/mcp-conformance-baseline.yml}"
  if [ -e "$bl" ]; then
    assert_baseline "$bl"
    baseline=(--expected-failures "$bl")
  else
    bl=""
  fi
  local rc=0
  npx --yes "$CONFORMANCE_PIN" server \
      --url "$target" --requirements "$REVISION" \
      ${baseline[@]+"${baseline[@]}"} -o "$out" || rc=$?
  # THE ARMED GUARD, and it runs BEFORE the exit code is honoured. An armed run that executed
  # nothing is the state the skip above would otherwise rot into: configured, green, and vacuous.
  assert_covered "$out" "official subject"
  assert_passed "$out" "official subject" "$bl"
  [ "$rc" -eq 0 ] || die "busbar failed scenarios the $REVISION requirement set demands. If a \
failure is known and accepted, it belongs in qa/mcp-conformance-baseline.yml with a reason — never \
absorbed by loosening the gate."
}

battery_control() {
  say "== IN-HOUSE BATTERY · CONTROL leg (pinned python reference peer) =="
  # NO LONGER SKIPPABLE. The battery is in this repository (DECISION 2), so "not available" can no
  # longer mean "somebody did not set a secret" — it can only mean the tree was gutted. That is a
  # finding, so it is red.
  MCP_BATTERY_DIR="${MCP_BATTERY_DIR:-$DEFAULT_BATTERY_DIR}"
  [ -d "$MCP_BATTERY_DIR" ] || die "the in-house battery is not at $MCP_BATTERY_DIR. It lives in \
this repository so that this leg needs no secret and no reachable private host; if it is missing, \
the tree is wrong and no verdict from this script means anything."
  say "   battery: $MCP_BATTERY_DIR"
  # The battery writes `reports/control-<tier>.json`, with the tier's comma turned into a dash.
  # DELETED FIRST, and there is no fallback to any other report file. An earlier version of this
  # function fell back to `reports/control.json` when the exact name was not found, and on a repo
  # with committed report artifacts that fallback silently read a report from a PREVIOUS run — the
  # gate would have passed on evidence the current run never produced. A missing report is a hard
  # error precisely because the alternative is believing stale evidence.
  local report="$MCP_BATTERY_DIR/reports/control-push-pr.json"
  rm -f "$report"
  ( cd "$MCP_BATTERY_DIR" && ./scripts/setup-control.sh && ./scripts/run-control.sh push,pr ) \
    || die "the in-house battery could not judge its own pinned control peer. A finding about the \
harness, not about busbar."
  assert_battery_report "$report" "control"
}

# THE BATTERY'S ANTI-VACUITY ASSERTION, shared by both battery legs so neither can drift from the
# other. The report must exist (the caller DELETED it before the run, so an existing one is this
# run's), and it must contain actual executed results.
assert_battery_report() {
  local report="$1" label="$2"
  [ -f "$report" ] || die "the $label run did not write $report. It cannot have executed, and no \
other report file is an acceptable substitute — reading one from a previous run is how a gate \
reports a state it never reached."
  python3 - "$report" "$label" <<'PY' || exit 1
import json, sys
path, label = sys.argv[1], sys.argv[2]
try:
    r = json.load(open(path))
except (OSError, ValueError) as e:
    raise SystemExit(f"FAIL: the {label} report {path} is not readable JSON: {e}")
tests = r.get("tests", r.get("results")) if isinstance(r, dict) else None
if not isinstance(tests, list) or any(not isinstance(t, dict) or t.get("verdict", t.get("status")) not in ("PASS", "FAIL", "ERROR", "SKIP", "SKIPPED") for t in tests):
    raise SystemExit(f"FAIL: the {label} report has no valid result list")
ran = [t for t in tests if t.get("verdict", t.get("status")) not in ("SKIP", "SKIPPED")]
if not ran:
    raise SystemExit(f"FAIL: the {label} report contains no executed tests")
print(f"  ok: {len(ran)} {label} tests executed")
PY
}

battery_subject() {
  say "== IN-HOUSE BATTERY · SUBJECT leg (busbar) =="
  MCP_BATTERY_DIR="${MCP_BATTERY_DIR:-$DEFAULT_BATTERY_DIR}"
  [ -d "$MCP_BATTERY_DIR" ] || die "the in-house battery is not at $MCP_BATTERY_DIR."
  MCP_BATTERY_DIR="$(cd "$MCP_BATTERY_DIR" && pwd)"

  # ARMED BY A BINARY, exactly as the official subject leg is, and for the same reason: a gate armed
  # out of `vars.*` is a gate nobody has to arm, and this one nobody did — it spent the whole of
  # 1.5.5 reporting `NOT ARMED, SO NOT RUN`. The two arming variables survive underneath for an
  # operator pointing the battery at something else entirely, which is the harness's whole contract
  # (a target is a launch command and nothing more), but the RELEASE arm is the build.
  #
  # The battery drives a target over STDIO and busbar's MCP plane is HTTP; the transport adapter
  # that joins them is `testing/mcp-conformance/scripts/stdio-http-bridge.mjs`, and its header says
  # what it does and does not do. It is pointed at the SAME booted subject the official leg uses —
  # same boot, same real audience-bound credential, same disproof that the plane boundary is intact
  # before any verdict is believed — so the two legs cannot disagree about which busbar was judged.
  if [ -z "${MCP_SUBJECT_SERVER_CMD:-}${MCP_SUBJECT_CLIENT_CMD:-}" ] \
     && [ -n "${MCP_SUBJECT_BUSBAR_BIN:-}" ]; then
    # A workdir of its own: two legs writing one directory would leave each verdict standing over
    # the other's evidence, which is the defect `MCP_SUBJECT_OUT` exists to prevent on the official
    # leg.
    local workdir="${MCP_SUBJECT_WORKDIR:-.mcp-conformance/battery-subject-run}"

    # ── THE SEAM, ARMED ──────────────────────────────────────────────────────────────────────────
    #
    # The six `SEAM.*` clauses drive busbar's FRONT door and observe busbar's BACK door, so they
    # need a hostile MCP server mounted as one of busbar's upstreams. The battery already owns the
    # hostility — `fakepeer/fake-server.mjs`, twenty-odd named attacks emitting exact bytes no SDK
    # would produce — but it speaks stdio, and busbar's client direction speaks streamable HTTP and
    # deliberately nothing else (`transport: stdio` is refused at config validation; there is no
    # child supervisor in this build). So the peer is reached through
    # `fakepeer/http-fake-server.mjs`, the MIRROR of the `stdio-http-bridge.mjs` the battery already
    # uses to reach busbar's front door: HTTP in, the fake server's stdio out, bytes unchanged in
    # both directions. ONE source of hostility, two transports — a second HTTP-native hostile server
    # would be twenty-odd chances for the two to disagree.
    #
    # THE MODE IS SELECTED BY A CONTROL FILE, NOT AN ENVIRONMENT VARIABLE, and that is what lets ONE
    # long-lived busbar serve every seam test. An env-selected mode would mean a fresh peer process
    # per test, therefore a fresh registration, therefore a fresh busbar per test — and a busbar
    # booted seconds ago with nothing else in flight cannot demonstrate
    # SEAM.ROLE-ISOLATION-UNDER-UPSTREAM-CRASH at all, because "the front door still serves" is only
    # a claim about a process that was ALREADY SERVING when the upstream died.
    #
    # The cost is stated rather than hidden: the seam tests are NOT isolated from each other. That
    # is the correct trade for these six — every one is about what a long-lived gateway does when an
    # upstream misbehaves — and a run in which test N's damage broke test N+1 is a finding this
    # arrangement can see and a per-test boot could not.
    # A DIRECTORY OF ITS OWN, and NOT `$workdir`: `boot_busbar_subject` does `rm -rf` on its workdir
    # before writing the config, which would delete the control file and the log of a peer that is
    # already running — leaving a hostile upstream alive with its evidence unlinked underneath it.
    local seamdir seam_control seam_port
    seamdir=".mcp-conformance/battery-seam"
    rm -rf "$seamdir"; mkdir -p "$seamdir"
    seamdir="$(cd "$seamdir" && pwd)"
    seam_control="$seamdir/seam-control.json"
    printf '%s\n' '{"mode":"honest","transcript":null}' >"$seam_control.tmp"
    mv -f "$seam_control.tmp" "$seam_control"
    seam_port="$(node -e '
      const s = require("net").createServer();
      s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => console.log(p)); });
    ')"
    node "$MCP_BATTERY_DIR/fakepeer/http-fake-server.mjs" "$seam_port" "$seam_control" \
      >"$seamdir/seam-upstream.log" 2>&1 &
    SEAM_PID=$!
    # Reaped even if the boot below dies: a leaked hostile peer would hold a port and outlive the
    # job that started it.
    reap_add "$SEAM_PID"
    say "   hostile seam upstream on 127.0.0.1:$seam_port (control $seam_control, log $seamdir/seam-upstream.log)"

    # EXPORTED BEFORE THE BOOT, because `subject_write_config` reads it: the registration has to
    # exist in the config busbar starts with. A busbar booted first and reconfigured later would be
    # a different test.
    export MCP_SEAM_UPSTREAM_URL="http://127.0.0.1:$seam_port/mcp"

    SUBJECT_PIDS=""
    MCP_SUBJECT_WORKDIR="$workdir" boot_busbar_subject
    MCP_SUBJECT_SERVER_CMD="node \"$MCP_BATTERY_DIR/scripts/stdio-http-bridge.mjs\" $SUBJECT_URL"
    export MCP_SUBJECT_SERVER_CMD

    # THE SEAM LAUNCHER. `src/suites/seam.mjs` substitutes this for the ordinary server launch and
    # hands it `MCP_FAKE_MODE` / `MCP_FAKE_TRANSCRIPT` per test; `seam-arm.sh` writes those into the
    # control file the long-lived hostile peer reads, then execs the SAME bridge above so the front
    # door is the same busbar the rest of the battery has been driving all run.
    MCP_SUBJECT_UPSTREAM_CONFIG_CMD="bash $(pwd)/testing/mcp-conformance/mcp-subject/seam-arm.sh $seam_control $SUBJECT_URL"
    export MCP_SUBJECT_UPSTREAM_CONFIG_CMD

    # ── THE CLIENT ROLE, ARMED ───────────────────────────────────────────────────────────────────
    #
    # THE HOLE THIS CLOSES. `src/suites/client-role.mjs` skips every one of its tests when
    # `ctx.target.hasClientRole` is false, and `src/core/target.mjs` derives that from whether a
    # `clientLaunch` was configured. Nothing configured one, so the fourteen CLI.* scenarios had
    # NEVER been run against busbar — while the whole architectural claim is that busbar is an MCP
    # server AND an MCP client. `187 passed, 0 failed` was a true statement about the SERVER role
    # and silent about the other half, which is the same shape of false green as a disarmed leg.
    #
    # It is armed HERE and not out of `vars.MCP_SUBJECT_CLIENT_CMD` for the settled reason: a
    # release gate that depends on a live deployment produces two unreadable verdicts, a green that
    # means "the deployment was fine yesterday" and a red that means "somebody redeployed". The
    # subject is the busbar booted above, from THIS COMMIT. The repository variable still takes
    # precedence, for an operator judging something that is not this build.
    #
    # SAME PEER, SAME CONTROL FILE, SAME BUSBAR as the seam leg. The battery runs its tests
    # sequentially (`runAll` is a `for` loop), so one control file cannot be armed for two tests at
    # once, and reusing the one long-lived hostile upstream is what keeps a single busbar serving
    # the whole run. See testing/mcp-conformance/mcp-subject/client-arm.sh for what it does and, more importantly,
    # for the half of the suite's contract busbar cannot satisfy and why substituting the HTTP
    # mirror of the same fake server is a fact about the subject rather than a loosened test.
    MCP_SUBJECT_CLIENT_CMD="bash $(pwd)/testing/mcp-conformance/mcp-subject/client-arm.sh $seam_control $SUBJECT_URL"
    export MCP_SUBJECT_CLIENT_CMD

    # THE ADMIN HALF OF THE CLIENT ARM. busbar's client direction sends `tools/list` on exactly one
    # path — the connect/refresh drift check — and that path is an OPERATOR's verb, so the arm
    # script needs the admin surface of the busbar booted above. Through the environment rather
    # than argv, because the suite records and prints launch commands and a credential in argv is a
    # credential in every transcript. See client-arm.sh for what it drives and boot.sh for why the
    # refresh lands on the `probe` registration rather than on `seam`.
    export MCP_SUBJECT_ADMIN_URL="$SUBJECT_ADMIN_URL"
    export MCP_SUBJECT_ADMIN_TOKEN="$SUBJECT_ADMIN_TOKEN"

    # THE SEAM'S VERIFICATION WINDOW, for the arm script to wait out. busbar re-verifies an upstream
    # on the call path only once its last observation is `verify_ttl` old, and it fails closed for
    # that window on a verification that failed. The CLI scenarios run back to back and each arms
    # an attack on the one shared peer, so without the wait a scenario's call was judged on the
    # verdict the PREVIOUS scenario's attack left behind: after `half-answer` broke a verification,
    # the next five scenarios were refused inside one window without a byte reaching the peer, and
    # scored VACUOUS. See client-arm.sh.
    export MCP_SEAM_VERIFY_TTL_S="$SEAM_VERIFY_TTL_S"

    # THE ALWAYS-FAILING TOOL, named here for the same reason `run-control.sh` names
    # `always_fails` for the python control: the harness contains no knowledge of any subject, so the
    # ARMING script is the one place a subject's own tool name may be written. Without it
    # `SRV.TOOLS.EXECUTION-ERROR-IS-RESULT` skips — and under MCP_NO_SKIPS it goes RED — over a
    # surface busbar implements and the official suite's `tools-call-error` scenario already passes.
    # `test_error_handling` is `subject_write_config`'s `test` server plus `error_handling`, the tool
    # `diagnostic-upstream.mjs` answers with `isError: true`.
    export MCP_SUBJECT_FAILING_TOOL="${MCP_SUBJECT_FAILING_TOOL:-test_error_handling}"
  fi

  require_armed "battery subject" MCP_SUBJECT_BUSBAR_BIN MCP_SUBJECT_SERVER_CMD MCP_SUBJECT_CLIENT_CMD
  # THE CALLEE'S EXIT CODE IS NOT THE VERDICT (item 497) — the control leg above has never trusted
  # it, and this leg is the one that judges busbar. The reports are DELETED FIRST, so the checks
  # after the run can only ever read what THIS run wrote: `run-subject.sh` never removes them, and
  # a report from a previous run is exactly the evidence a gate must not believe.
  local subj_report="$MCP_BATTERY_DIR/reports/subject.json"
  local subj_diff="$MCP_BATTERY_DIR/reports/differential.json"
  rm -f "$subj_report" "$subj_diff"
  # MCP_NO_SKIPS: a skipping test is not a passing test. Set HERE and not on the control legs,
  # because on the control legs a skip is the harness telling the truth about a peer it was never
  # pointed at, whereas here it is a green tick over a surface of BUSBAR that nobody touched.
  #
  # It used to make the six `pr`-tier seam tests RED, and that was the correct answer while nothing
  # mounted a peer for busbar to be observed talking to. The MCP CLIENT direction was already built
  # and already worked — what was missing was an HTTP-facing hostile peer, the arming, and a
  # `publish_as: echo` registration for the bare name the suite calls. All three are above. The
  # skip-to-red mechanism is UNCHANGED and still guards every other surface.
  MCP_NO_SKIPS=1 \
  MCP_SUBJECT_SERVER_CMD="${MCP_SUBJECT_SERVER_CMD:-}" \
  MCP_SUBJECT_CLIENT_CMD="${MCP_SUBJECT_CLIENT_CMD:-}" \
    bash -c 'cd "$0" && ./scripts/run-subject.sh' "$MCP_BATTERY_DIR" \
    || case $? in
      # 2 IS "THE COMPARISON DID NOT RUN", not "busbar failed". Distinguished because the two used
      # to arrive here identically, and this message is what a reader believes: a job that had
      # simply never been handed the control report accused busbar of a defect, four lines under
      # `50 pass, 0 fail`. Still fatal — an unrun differential is not a pass — but it must not be
      # reported as a finding about the subject.
      2) die "the differential did not run, so this leg proves nothing. See the reason above; it is not a verdict about busbar." ;;
      *) die "the in-house battery found a defect in busbar." ;;
    esac
  assert_battery_report "$subj_report" "battery subject"
  [ -f "$subj_diff" ] || die "the battery subject run exited 0 but wrote no $subj_diff — the \
differential against the control did not run, so this leg proves nothing."
}

case "${1:---help}" in
  --official-control) ensure_node22; official_control ;;
  --official-subject) ensure_node22; official_subject ;;
  --battery-control)  ensure_node22; battery_control ;;
  --battery-subject)  ensure_node22; battery_subject ;;
  --help|-h)          usage ;;
  *) die "unknown mode: $1 (try --help)" ;;
esac
