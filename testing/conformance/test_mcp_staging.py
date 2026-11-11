"""Focused regressions for the confined MCP harness and its candidate composition."""

import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "testing/mcp-conformance/mcp-subject/compose.sh"
WORKDIR = ROOT / "testing/conformance/mcp-workdir.sh"
SOURCE = "https://github.com/GetBusbar/busbar-plane-mcp"


class McpStaging(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="mcp-staging-")
        self.addCleanup(self.scratch.cleanup)
        self.base = Path(self.scratch.name)

    def fixture(self, extra=""):
        checkout = self.base / "core"
        manifest = checkout / "dist/default/Cargo.toml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            '[package.metadata.busbar.linked-entry]\n'
            'plane-mcp-door = "busbar_plane_mcp::plane_door"\n'
            '[package.metadata.busbar.linked-declares]\n'
            'plane-mcp-door = "busbar_plane_mcp::DECLARES"\n'
            '[workspace.dependencies]\n'
            f'busbar-plane-mcp = {{git = "{SOURCE}", rev = "pinned"}}\n'
            + extra
        )
        plane = self.base / "original candidate" / "plane-mcp"
        (plane / "src").mkdir(parents=True)
        (plane / "src/lib.rs").write_text("pub use plane_door::door;\n")
        (plane / "declares.json").write_text("{}\n")
        return checkout, manifest, plane

    def test_composition_persists_original_candidate_patch_without_changing_core(self):
        checkout, original, plane = self.fixture()
        before = original.read_bytes()
        result = subprocess.run(
            ["bash", str(COMPOSE), str(checkout), str(plane), str(self.base / "staged")],
            check=True, text=True, capture_output=True,
        )
        staged = tomllib.loads(Path(result.stdout.strip()).read_text())
        self.assertEqual(staged["patch"][SOURCE]["busbar-plane-mcp"], {"path": str(plane)})
        self.assertEqual(original.read_bytes(), before)
        self.assertEqual(
            staged["package"]["metadata"]["busbar"]["linked-entry"]["plane-mcp-door"],
            "busbar_plane_mcp",
        )
        self.assertIn(str(plane / "declares.json"),
                      staged["package"]["metadata"]["busbar"]["linked-declares"]["plane-mcp-door"])

    def test_composition_refuses_an_existing_patch_instead_of_overriding_it(self):
        checkout, _, plane = self.fixture(f'\n[patch."{SOURCE}"]\nother = {{path = "elsewhere"}}\n')
        result = subprocess.run(
            ["bash", str(COMPOSE), str(checkout), str(plane), str(self.base / "staged")],
            text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already patches", result.stderr)

    def test_readonly_harness_gets_fresh_writable_reports_and_scratch(self):
        source = self.base / "candidate"
        battery = source / "testing/mcp-conformance"
        tools = source / "testing/conformance/mcp-tools"
        battery.mkdir(parents=True)
        tools.mkdir(parents=True)
        body = "#!/bin/sh\nmkdir -p .mcp-conformance testing/mcp-conformance/reports testing/target/h2-scratch\n"
        (battery / "probe.sh").write_text(body)
        (battery / "reports").mkdir()
        (battery / "reports/stale.json").write_text('{"status":"pass"}')
        (tools / "runtime.sh").write_text("# immutable public-tool identity check\n")
        paths = [source, *source.rglob("*")]
        for path in paths:
            path.chmod(0o555 if path.is_dir() else 0o444)
        self.addCleanup(lambda: [path.chmod(0o755 if path.is_dir() else 0o644) for path in paths])
        output = self.base / "evidence"
        runs = []
        for _ in range(2):
            result = subprocess.run(["bash", str(WORKDIR), str(source), str(output)],
                                    check=True, capture_output=True, text=True)
            work = Path(result.stdout.strip())
            self.assertTrue(work.is_relative_to(output))
            self.assertFalse((work / "testing/mcp-conformance/reports").exists())
            self.assertEqual((work / "testing/mcp-conformance/probe.sh").read_text(), body)
            subprocess.run(["sh", "testing/mcp-conformance/probe.sh"], cwd=work, check=True)
            runs.append(work)
        self.assertNotEqual(*runs)
        self.assertFalse((source / ".mcp-conformance").exists())
        self.assertFalse((source / "testing/target").exists())
        self.assertEqual((battery / "reports/stale.json").read_text(), '{"status":"pass"}')
        self.assertFalse(os.stat(battery).st_mode & 0o200)


if __name__ == "__main__":
    unittest.main()
