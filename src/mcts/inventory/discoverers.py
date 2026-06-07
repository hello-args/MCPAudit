"""Discover MCP client configuration files."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from mcts.inventory.models import InventoryEntry

CLIENT_PATHS: dict[str, list[str]] = {
    "linux": [
        "~/.cursor/mcp.json",
        "~/.vscode/mcp.json",
        "~/.config/Code/User/settings.json",
        "~/.codeium/windsurf/mcp_config.json",
    ],
    "darwin": [
        "~/.cursor/mcp.json",
        "~/.vscode/mcp.json",
        "~/Library/Application Support/Claude/claude_desktop_config.json",
        "~/Library/Application Support/Code/User/settings.json",
        "~/.codeium/windsurf/mcp_config.json",
    ],
    "win32": [
        "~/.cursor/mcp.json",
        "~/.vscode/mcp.json",
        "~/AppData/Roaming/Claude/claude_desktop_config.json",
        "~/AppData/Roaming/Code/User/settings.json",
        "~/.codeium/windsurf/mcp_config.json",
    ],
}


def _platform_key() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform == "win32":
        return "win32"
    return "linux"


def discover_config_paths() -> list[tuple[str, Path]]:
    rows: list[tuple[str, Path]] = []
    for raw in CLIENT_PATHS.get(_platform_key(), CLIENT_PATHS["linux"]):
        path = Path(raw).expanduser()
        if path.exists():
            client = _client_from_path(path)
            rows.append((client, path))
    return rows


def _client_from_path(path: Path) -> str:
    text = str(path).lower()
    if "cursor" in text:
        return "cursor"
    if "claude" in text:
        return "claude"
    if "windsurf" in text or "codeium" in text:
        return "windsurf"
    if "vscode" in text or "code/user" in text:
        return "vscode"
    return "unknown"


def parse_config_file(client: str, path: Path) -> list[InventoryEntry]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    servers: dict = {}
    if "mcpServers" in payload:
        servers = payload["mcpServers"]
    elif client == "vscode" and isinstance(payload.get("mcp"), dict):
        servers = payload["mcp"].get("servers", {})

    entries: list[InventoryEntry] = []
    for server_name, config in servers.items():
        if not isinstance(config, dict):
            continue
        command = config.get("command")
        args = config.get("args") or []
        env_keys = sorted((config.get("env") or {}).keys())
        entries.append(
            InventoryEntry(
                client=client,
                config_path=str(path),
                server_name=server_name,
                command=command,
                args=[str(a) for a in args],
                env_keys=env_keys,
            )
        )
    return entries
