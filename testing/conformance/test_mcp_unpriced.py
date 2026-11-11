"""The pricing witness must reject zero pricing and unrelated failures."""

import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "mcp-conformance/mcp-subject/judge-unpriced.py"
spec = importlib.util.spec_from_file_location("judge_unpriced", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

WARNING = ("tools.rate_card has no configured rate for lane 'mcp_server:probe' "
           "billable class(es) bytes; these classes remain unpriced. Raw counts remain available.")


def error(lane="mcp_server:probe", unit="bytes", code="unpriced_class"):
    return {"error": {"code": code, "message":
            f"usage cannot be priced: the rate card in force names no price for class `{unit}` of `{lane}`"}}


class UnpricedWitness(unittest.TestCase):
    def test_exact_refusal_and_warning_pass(self):
        for lane in ("mcp_server:probe", "mcp\x1fmcp_server:probe"):
            module.judge("409", error(lane), WARNING)

    def test_zero_partial_or_unrelated_response_cannot_pass(self):
        for status, body in [
            ("200", {"spend_cents": 0}), ("200", {"spend_cents": 1}),
            ("200", error()), ("500", error()), ("409", {}),
            ("409", error(code="internal")), ("409", error(unit="tool_calls")),
            ("409", error(lane="mcp_server:other")),
            ("409", error(lane="another-plane\x1fmcp_server:probe")),
            ("409", dict(error(), spend_cents=0)),
        ]:
            with self.subTest(status=status, body=body), self.assertRaises(ValueError):
                module.judge(status, body, WARNING)

    def test_absent_wrong_or_unrelated_warning_cannot_pass(self):
        for log in ("", WARNING.replace("bytes", "tool_calls"),
                    WARNING.replace("mcp_server:probe", "mcp_server:other"),
                    WARNING.replace("these classes remain unpriced", "priced at zero")):
            with self.subTest(log=log), self.assertRaises(ValueError):
                module.judge("409", error(), log)


if __name__ == "__main__":
    unittest.main()
