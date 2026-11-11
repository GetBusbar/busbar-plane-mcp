#!/usr/bin/env bash
# THE SUBJECT'S COMPOSITION: which busbar package the `mcp` suite builds, with this checkout's plane in it.
#
#   compose.sh <busbar checkout> <this plane's crate dir> <stage dir>
#
# Prints the manifest path of the package to build (`cargo build --manifest-path <it>
# --bin busbar`). The staged manifest carries the candidate patch so nested Cargo
# metadata queries resolve the same graph as the outer build.
#
# The package is busbar's default distribution (dist/default): the root crate (crates/busbar) is core
# with no plugin linked, so it serves no MCP. The checkout is copied to <stage> and is never written.
# In the copy, the dist's two rows that name an item inside this plane are pointed at where THIS plane
# keeps it, the way busbar's dist names them once it pins this plane:
#   linked-entry    plane-mcp-door  the module the door is exported from (the crate root, when the
#                                   plane has no `pub mod plane_door`)
#   linked-declares plane-mcp-door  the plane's own declares.json, by path (the document its door's
#                                   Statement carries; the plane exports no `DECLARES`)
# Busbar's code, its other rows and its initial lockfile are the pin's.
set -euo pipefail
checkout="${1:?busbar checkout}"; plane="${2:?plane crate dir}"; stage="${3:?stage dir}"
plane="$(cd "$plane" && pwd)"
rm -rf "$stage"; mkdir -p "$stage"
tar -C "$checkout" --exclude=./target --exclude=./dist/default/target --exclude=./.git -cf - . | tar -C "$stage" -xf -
"${PYTHON:-python3}" -I - "$stage/dist/default/Cargo.toml" "$plane" >&2 <<'PY'
import json, os, re, sys, tomllib
manifest, plane = sys.argv[1:3]
text = open(manifest).read()
lib = open(os.path.join(plane, "src", "lib.rs")).read()

def set_row(table, key, value):
    global text
    sec = re.search(r"^\[" + re.escape(table) + r"\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if not sec:
        sys.exit(f"compose: {manifest} has no [{table}]")
    body = sec.group(1)
    row = re.compile(r'^' + re.escape(key) + r'\s*=\s*"[^\n]*$', re.M)
    if not row.search(body):
        sys.exit(f"compose: [{table}] has no `{key}` row")
    new = row.sub(lambda _: f"{key} = {value}", body, count=1)
    text = text[: sec.start(1)] + new + text[sec.end(1):]
    print(f"compose: [{table}] {key} = {value}")

if not re.search(r"^pub mod plane_door\b", lib, re.M):
    set_row("package.metadata.busbar.linked-entry", "plane-mcp-door", '"busbar_plane_mcp"')
if not re.search(r"^pub (const|static) DECLARES\b", lib, re.M):
    declares = os.path.join(plane, "declares.json")
    if not os.path.isfile(declares):
        sys.exit(f"compose: {declares} is missing")
    if any(c in declares for c in '"\\#\n'):
        sys.exit(f"compose: {declares}: a path busbar's row reader cannot carry")
    # A TOML multi-line basic string: busbar's row reader (linked_gen.rs, not a TOML parser) trims
    # the quotes and emits the rest as the row's Rust expression, `include_str!("<path>")`.
    set_row("package.metadata.busbar.linked-declares", "plane-mcp-door",
            '"""include_str!("' + declares + '")"""')
document = tomllib.loads(text)
source = document.get("workspace", {}).get("dependencies", {}).get("busbar-plane-mcp", {}).get("git")
if not source:
    sys.exit("compose: the staged distribution names no git source for busbar-plane-mcp to patch")
if source in document.get("patch", {}):
    sys.exit(f"compose: the staged distribution already patches {source}")
text += (f'\n[patch.{json.dumps(source)}]\n'
         f'busbar-plane-mcp = {{ path = {json.dumps(plane)} }}\n')
print(f"compose: patched {source} busbar-plane-mcp to {plane}")
open(manifest, "w").write(text)
PY
printf '%s\n' "$stage/dist/default/Cargo.toml"
