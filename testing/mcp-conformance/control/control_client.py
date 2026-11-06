"""Control MCP client.

The REFERENCE for the client half of the battery, built on the pinned official
Python SDK (mcp==2.2.0), with a modern-only inbound transport adapter.
This is an adapted reference, not a claim about the unmodified official client.

CONTRACT (the one thing the battery asks of any subject in its client role):

    argv[-1]  is a shell command that launches a stdio MCP server
    env MCP_TARGET_SERVER_COMMAND  carries the same command

    On start, connect to that server and do some ordinary work: discover,
    list tools, call a tool. Then exit.

MCP standardises the wire, not how a host is told which server to talk to, so
some contract of this shape is unavoidable. Everything the battery asserts is
observed from the SERVER side, so this program is not trusted to report on
itself; it only has to connect and do something.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import anyio
import os
import shlex
import sys

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp_types import JSONRPCRequest


def target_command() -> list[str]:
    raw = None
    if len(sys.argv) > 1:
        raw = sys.argv[-1]
    raw = os.environ.get("MCP_TARGET_SERVER_COMMAND", raw)
    if not raw:
        print("no target server command supplied", file=sys.stderr)
        raise SystemExit(2)
    return shlex.split(raw)


class ModernReadStream:
    """Reject forbidden server requests before the SDK's legacy responder.

    The peer's transcript still records the delivered request. This is client
    protocol behavior, not a change to the observer or an output-error filter.
    Responses, notifications, and parse errors reach the SDK unchanged.
    """

    def __init__(self, stream):
        self.stream = stream

    async def receive(self):
        while True:
            item = await self.stream.receive()
            if not isinstance(item, Exception) and isinstance(item.message, JSONRPCRequest):
                print("modern client rejected forbidden server request", file=sys.stderr)
                continue
            return item

    async def aclose(self):
        await self.stream.aclose()

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self.receive()
        except anyio.EndOfStream:
            raise StopAsyncIteration from None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.aclose()


@asynccontextmanager
async def modern_stdio(params):
    async with stdio_client(params) as (read, write):
        yield ModernReadStream(read), write


async def main() -> None:
    argv = target_command()
    params = StdioServerParameters(command=argv[0], args=argv[1:], env=dict(os.environ))
    # This fixture selects exactly the battery's modern revision; it never
    # negotiates a legacy connection for which the inbound adapter is invalid.
    # A workload deadline also bounds discovery and sequential request failures.
    with anyio.fail_after(12):
        async with Client(
            modern_stdio(params), mode="2026-07-28", read_timeout_seconds=3.0
        ) as client:
            try:
                tools = await client.list_tools()
                names = [t.name for t in getattr(tools, "tools", [])]
                print(f"tools: {names}", file=sys.stderr)
            except Exception as exc:  # noqa: BLE001
                print(f"list_tools failed: {exc!r}", file=sys.stderr)
                return

            if "echo" in names:
                try:
                    await client.call_tool("echo", {"text": "battery"})
                except Exception as exc:  # noqa: BLE001
                    print(f"call_tool failed: {exc!r}", file=sys.stderr)

            for method, label in (
                (client.list_resources, "list_resources"),
                (client.list_prompts, "list_prompts"),
            ):
                try:
                    await method()
                except Exception as exc:  # noqa: BLE001
                    print(f"{label} failed: {exc!r}", file=sys.stderr)


if __name__ == "__main__":
    try:
        anyio.run(main)
    except Exception as exc:  # noqa: BLE001
        # A hostile peer is expected to break us sometimes. Exiting non-zero is
        # a legitimate outcome and the battery records it rather than failing.
        print(f"control client terminated: {exc!r}", file=sys.stderr)
        raise SystemExit(1)
