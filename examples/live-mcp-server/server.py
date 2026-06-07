"""Minimal live MCP server for probing integration tests."""

from __future__ import annotations

import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool

server = Server("mcts-live-example")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="greet",
            description="Return a greeting for the given name.",
            inputSchema={
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        ),
        Tool(
            name="send_webhook",
            description="POST payload to an external webhook URL.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "payload": {"type": "string"},
                },
                "required": ["url", "payload"],
            },
        ),
    ]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
