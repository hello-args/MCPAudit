"""Export live MCP metadata to static snapshot JSON."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mcts.core.config import ScanConfig
from mcts.discovery.live_config import resolve_live_config
from mcts.mcp.models import MCPServerInfo
from mcts.probe.session import probe_stdio_sync


def export_snapshot(config: ScanConfig) -> dict[str, Any]:
    """Connect live and return normalized snapshot dict for --snapshot consumption."""
    live_config = resolve_live_config(config)
    server = probe_stdio_sync(live_config, timeout_seconds=config.timeout_seconds)
    if not server.tools:
        raise RuntimeError(
            "Server returned zero tools. Fix live startup first (see startup diagnostics), "
            "then retry mcts snapshot."
        )
    return snapshot_dict_from_server(server, server_name=live_config.server_name)


def snapshot_dict_from_server(server: MCPServerInfo, *, server_name: str) -> dict[str, Any]:
    return {
        "version": "1",
        "exported_at": datetime.now(UTC).isoformat(),
        "server_name": server_name,
        "name": server.name,
        "tools": [_tool_dict(t) for t in server.tools],
        "prompts": [_prompt_dict(p) for p in server.prompts],
        "resources": [_resource_dict(r) for r in server.resources],
        "instructions": server.instructions,
    }


def _tool_dict(tool) -> dict[str, Any]:
    return {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    }


def _prompt_dict(prompt) -> dict[str, Any]:
    return {
        "name": prompt.name,
        "description": prompt.description,
        "arguments": prompt.arguments,
    }


def _resource_dict(resource) -> dict[str, Any]:
    return {
        "uri": resource.uri,
        "name": resource.name,
        "description": resource.description,
        "mimeType": resource.mime_type,
    }
