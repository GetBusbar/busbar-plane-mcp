#!/usr/bin/env python3
"""Controller-only public-tool preparation. Never execute inside the candidate.

Run with Node 22.23.3 on PATH. --work and --output must be outside the candidate
checkout. Network access downloads only the locked public SDK/npm/PyPI inputs.
The output is a Linux x86_64/Python 3.11 bundle, independent of builder platform.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(row, destination):
    if not destination.exists():
        with urllib.request.urlopen(row["uri"]) as source, destination.open("wb") as target:
            shutil.copyfileobj(source, target)
    if sha(destination) != row["sha256"]:
        raise ValueError("public source checksum mismatch: " + destination.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    work, output = args.work.resolve(), args.output.resolve()
    for path in (work, output):
        if path == REPO or REPO in path.parents:
            raise ValueError("public tool staging must be outside the candidate checkout")
    if output.exists():
        raise ValueError("output already exists; use a new output directory")
    if subprocess.check_output(["node", "--version"], text=True).strip() != "v22.23.3":
        raise ValueError("stage with pinned Node 22.23.3")
    work.mkdir(parents=True, exist_ok=True)
    lock = json.loads((HERE / "sources.lock.json").read_text())
    provenance = []
    fetch(lock["conformance"], work / "conformance.tar.gz")
    provenance.append({k: lock["conformance"][k] for k in ("uri", "sha256")})
    for name in ("pnpm", "sdk"):
        archive = work / (name + ".tar.gz")
        fetch(lock[name], archive)
        provenance.append({k: lock[name][k] for k in ("uri", "sha256")})
        dest = work / name
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir()
        with tarfile.open(archive) as stream:
            # Both upstream archives have one top-level directory. Reject links
            # and traversal before stripping it, including on older Python.
            for member in stream.getmembers():
                parts = Path(member.name).parts
                if member.name.startswith("/") or ".." in parts or not (member.isfile() or member.isdir()):
                    raise ValueError("unsupported public archive entry")
                if len(parts) < 2:
                    continue
                target = dest.joinpath(*parts[1:])
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with stream.extractfile(member) as source, target.open("wb") as sink:
                        shutil.copyfileobj(source, sink)
                    target.chmod(0o755 if member.mode & 0o111 else 0o644)
    pnpm = ["node", str(work / "pnpm/bin/pnpm.cjs")]
    if subprocess.check_output(pnpm + ["--version"], text=True).strip() != "10.26.1":
        raise ValueError("incorrect pinned pnpm")
    env = dict(os.environ, CI="true", COREPACK_ENABLE_NETWORK="0")
    # No user npm credentials/configuration are read by this public-only build.
    env.update(NPM_CONFIG_USERCONFIG=str(work / "empty.npmrc"),
               NPM_CONFIG_GLOBALCONFIG=str(work / "empty-global.npmrc"))
    (work / "empty.npmrc").write_text("")
    (work / "empty-global.npmrc").write_text("")
    install = ["install", "--frozen-lockfile", "--ignore-scripts", "--store-dir", str(work / "store")]
    subprocess.run(pnpm + install, cwd=work / "sdk", env=env, check=True)
    subprocess.run(pnpm + ["--filter", "@modelcontextprotocol/test-conformance...", "run", "build"],
                   cwd=work / "sdk", env=env, check=True)
    output.mkdir(parents=True)
    build = r"""
const path = require('node:path');
const root = process.argv[1];
const tsx = require.resolve('tsx', {paths:[root]});
const esbuild = require(require.resolve('esbuild', {paths:[tsx]}));
esbuild.buildSync({entryPoints:[path.join(root,'test/conformance/src/everythingServer.ts')],
  outfile:process.argv[2], bundle:true, platform:'node', target:'node22', format:'cjs'});
"""
    subprocess.run(["node", "-e", build, str(work / "sdk"), str(output / "everythingServer.cjs")], check=True)
    suite = work / "official-suite"
    suite.mkdir(exist_ok=True)
    for name in ("package.json", "pnpm-lock.yaml"):
        shutil.copyfile(HERE / name, suite / name)
    subprocess.run(pnpm + install + ["--node-linker=hoisted"], cwd=suite, env=env, check=True)
    # Hoisted npm packages contain no workspace links. Dereference npm bin links
    # only while copying; the resulting controller input contains regular files.
    shutil.copytree(suite, output / "official-suite", symlinks=False)
    site = output / "python/site-packages"
    site.mkdir(parents=True)
    wheels = work / "wheels"
    wheels.mkdir(exist_ok=True)
    for row in lock["python_wheels"]:
        wheel = wheels / row["filename"]
        fetch(row, wheel)
        provenance.append({k: row[k] for k in ("uri", "sha256")})
        with zipfile.ZipFile(wheel) as stream:
            for entry in stream.infolist():
                parts = Path(entry.filename).parts
                if entry.filename.startswith("/") or ".." in parts or stat.S_ISLNK(entry.external_attr >> 16):
                    raise ValueError("unsupported wheel entry")
                if entry.is_dir():
                    continue
                # These locked wheels have no .data relocation sections.
                if any(part.endswith(".data") for part in parts):
                    raise ValueError("wheel requires an unsupported installation relocation")
                target = site.joinpath(*parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(stream.read(entry))
                target.chmod(0o644)
    (output / "python/bin").mkdir()
    launcher = output / "python/bin/python"
    launcher.write_text('#!/bin/sh\nexec /usr/bin/python3 -I "$(dirname "$0")/../launch.py" "$@"\n')
    launcher.chmod(0o755)
    shutil.copyfile(HERE / "python-launch.py", output / "python/launch.py")
    identity = {"schema": lock["schema"], "platform": lock["platform"], "python": lock["python"],
                "node": lock["node"], "pnpm": lock["pnpm"]["version"],
                "sdk": lock["sdk"]["revision"], "conformance": "0.2.0-alpha.11", "mcp": "2.2.0"}
    (output / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    shutil.copyfile(HERE / "sources.lock.json", output / "sources.lock.json")
    shutil.copyfile(work / "sdk/pnpm-lock.yaml", output / "sdk-pnpm-lock.yaml")
    shutil.copyfile(work / "sdk/LICENSE", output / "sdk-LICENSE")
    files = {}
    for path in sorted(output.rglob("*")):
        mode = path.lstat()
        if stat.S_ISDIR(mode.st_mode):
            continue
        if not stat.S_ISREG(mode.st_mode) or mode.st_nlink != 1:
            raise ValueError("bundle contains a non-regular or multiply linked file")
        executable = bool(mode.st_mode & 0o111)
        path.chmod(0o755 if executable else 0o644)
        files[path.relative_to(output).as_posix()] = {"sha256": sha(path), "executable": executable}
    manifest = {"schema": "busbar.native-conformance-inputs/1", "bundles": {"mcp-tools": {
        "path": str(output), "files": files, "provenance": provenance}}}
    manifest_path = output.parent / (output.name + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(manifest_path)


if __name__ == "__main__":
    main()
