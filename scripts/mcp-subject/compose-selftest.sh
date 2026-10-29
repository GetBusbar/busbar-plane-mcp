#!/usr/bin/env bash
# THE SUBJECT'S COMPOSITION, HELD BEFORE IT IS BUILT: the package compose.sh names must link this
# plane, and every row naming the plane must name an item this plane exports. A drift between the
# pinned busbar's rows and this plane's door is then a precise red in seconds, not an E0433 at the
# end of a fat-LTO release build.
#
#   compose-selftest.sh <busbar checkout> <stage dir>     (BUSBAR_CHECKOUT by default)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checkout="${1:-${BUSBAR_CHECKOUT:?busbar checkout}}"
stage="${2:-$(mktemp -d)}"
manifest="$(bash "$here/scripts/mcp-subject/compose.sh" "$checkout" "$here/plane-mcp" "$stage")"
"${PYTHON:-python3}" -I - "$manifest" "$here/plane-mcp" <<'PY'
import os, re, sys
manifest, plane = sys.argv[1:3]
krate, ident = "busbar-plane-mcp", "busbar_plane_mcp"
text = open(manifest).read()
lib = open(os.path.join(plane, "src", "lib.rs")).read()
fails = []

def table(name):
    """The `key = "value"` rows of [name], in order."""
    m = re.search(r"^\[" + re.escape(name) + r"\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if not m:
        return {}
    # read as busbar's row reader reads them (linked_gen.rs): one row per line, quotes trimmed
    return {k: v.strip().strip('"') for k, v in
            re.findall(r'^([A-Za-z0-9_-]+)\s*=\s*("[^\n#]*)', m.group(1), re.M)}

def public_outside_tests(item_re):
    """Is an item matching item_re public and not gated to the crate's own tests?"""
    for m in re.finditer(item_re, lib, re.M):
        before = lib[: m.start()].rstrip().splitlines()[-1:] or [""]
        if "cfg(test)" not in before[0]:
            return True
    return False

deps = re.search(r"^\[dependencies\]\s*$(.*?)(?=^\[)", text, re.M | re.S)
if not deps or not re.search(r"^" + krate + r"\s*=", deps.group(1), re.M):
    fails.append(f"{manifest}: the subject package has no `{krate}` dependency: it links no MCP plane")
default = re.search(r'^default\s*=\s*\[([^\]]*)\]', text, re.M)
if not default or '"plane-mcp"' not in default.group(1):
    fails.append(f"{manifest}: `plane-mcp` is not a default feature of the subject package")

rows = [f for f, c in table("package.metadata.busbar.linked").items() if c == krate]
for row in rows:
    entry = table("package.metadata.busbar.linked-entry").get(row) or \
            table("package.metadata.busbar.linked-entry").get(krate) or f"{ident}::linked"
    if entry == ident:
        if not public_outside_tests(r"^pub use [\w:]*\bdoor;|^pub fn door\b"):
            fails.append(f"linked-entry {row} = {entry!r}: the plane exports no `door` at its root")
    elif entry.startswith(ident + "::"):
        module = entry[len(ident) + 2:]
        if not public_outside_tests(r"^pub mod " + re.escape(module) + r"\b"):
            fails.append(f"linked-entry {row} = {entry!r}: the plane has no public module `{module}`")
    else:
        fails.append(f"linked-entry {row} = {entry!r}: not an item of {ident}")
    declares = table("package.metadata.busbar.linked-declares").get(row)
    if declares is None:
        continue
    m = re.fullmatch(re.escape(ident) + r"::(\w+)", declares)
    inc = re.fullmatch(r'include_str!\("([^"\\]*)"\)', declares)
    if m:
        if not public_outside_tests(r"^pub (const|static) " + m.group(1) + r"\b"):
            fails.append(f"linked-declares {row} = {declares!r}: the plane exports no `{m.group(1)}`")
    elif inc:
        if not os.path.isfile(inc.group(1)):
            fails.append(f"linked-declares {row} = {declares!r}: no such file")
    else:
        fails.append(f"linked-declares {row} = {declares!r}: neither a plane item nor an include_str!")
if not rows and not fails:
    fails.append(f"{manifest}: no [package.metadata.busbar.linked] row names {krate}")
for f in fails:
    print("compose-selftest: FAIL:", f)
if fails:
    sys.exit(1)
print(f"compose-selftest: ok: {manifest} links {krate} at rows {rows}")
PY
