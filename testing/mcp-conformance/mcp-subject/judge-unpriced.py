#!/usr/bin/env python3
"""Judge this H2 fixture's missing-price warning and monetary-read refusal."""

import json
from pathlib import Path
import re
import sys


def judge(status, body, log):
    warning = "tools.rate_card has no configured rate for lane 'mcp_server:probe' billable class(es) bytes"
    if not any(warning in line and "these classes remain unpriced" in line for line in log.splitlines()):
        raise ValueError("startup did not warn about this lane's unpriced bytes")
    if status != "409":
        raise ValueError(f"monetary usage read returned HTTP {status}, expected 409")
    if not isinstance(body, dict) or not isinstance(body.get("error"), dict):
        raise ValueError("monetary usage read has no error object")
    error = body["error"]
    if error.get("code") != "unpriced_class":
        raise ValueError("monetary usage read did not refuse with unpriced_class")
    message = error.get("message")
    match = re.fullmatch(
        r"usage cannot be priced: the rate card in force names no price for class `bytes` of `([^`]+)`",
        message if isinstance(message, str) else "",
    )
    # The generic ledger may qualify the lane with its plane key and unit separator.
    if not match or match[1] not in ("mcp_server:probe", "mcp\x1fmcp_server:probe"):
        raise ValueError("unpriced refusal did not name bytes on the probe lane")
    if any(key in body or key in error for key in ("spend_cents", "spend_micros")):
        raise ValueError("an unpriced refusal must not supply a monetary figure")


if __name__ == "__main__":
    try:
        judge(sys.argv[1], json.loads(Path(sys.argv[2]).read_text()), Path(sys.argv[3]).read_text())
    except (ValueError, OSError) as error:
        raise SystemExit(f"unpriced fixture: {error}") from error
