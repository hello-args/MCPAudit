"""Load MCP server launch config from client JSON files."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcts.discovery.env_expand import expand_args, expand_mapping, expand_value
from mcts.discovery.json5_util import load_json5
from mcts.probe.auth import RemoteAuth
from mcts.probe.models import LiveServerConfig, RemoteServerConfig


class ConfigDiscoveryError(RuntimeError):
    """Raised when a config file or server entry cannot be loaded."""


def load_servers_dict(config_path: Path) -> dict:
    """Load the mcpServers mapping from a client config file."""
    path = config_path.expanduser().resolve()
    if not path.exists():
        raise ConfigDiscoveryError(f"Config file not found: {path}")
    try:
        if path.suffix.lower() in (".json5", ".jsonc"):
            payload = load_json5(path)
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ConfigDiscoveryError(f"Invalid config JSON: {path}") from exc
    servers = payload.get("mcpServers")
    if servers is None and isinstance(payload.get("mcp"), dict):
        servers = payload["mcp"].get("servers", {})
    if not isinstance(servers, dict):
        raise ConfigDiscoveryError(f"No mcpServers block in {path}")
    return servers


def list_server_names(config_path: Path) -> list[str]:
    """Return sorted server names from an MCP client config."""
    return sorted(load_servers_dict(config_path))


_BARE_PYTHON = frozenset({"python", "python3", "python3.11", "python3.12", "python3.13"})


def _venv_python_candidates(config_dir: Path) -> list[Path]:
    import sys

    if sys.platform == "win32":
        return [
            config_dir / ".venv" / "Scripts" / "python.exe",
            config_dir / ".venv" / "Scripts" / "python3.exe",
            config_dir / "venv" / "Scripts" / "python.exe",
            config_dir / "venv" / "Scripts" / "python3.exe",
        ]
    return [
        config_dir / ".venv" / "bin" / "python",
        config_dir / ".venv" / "bin" / "python3",
        config_dir / "venv" / "bin" / "python",
        config_dir / "venv" / "bin" / "python3",
    ]


def resolve_interpreter(command: str, config_dir: Path) -> tuple[str, str | None]:
    """Resolve relative interpreters and bare python to project venv when present."""
    cmd_path = Path(command)
    if cmd_path.is_absolute() and cmd_path.exists():
        return command, None
    if command in _BARE_PYTHON:
        for candidate in _venv_python_candidates(config_dir):
            if candidate.is_file():
                return str(candidate.resolve()), None
        return command, (
            f"Config uses bare {command!r}; no project .venv interpreter found under {config_dir}. "
            "Set an explicit path such as .venv/bin/python in the MCP config."
        )
    candidate = (config_dir / command).resolve()
    if candidate.exists():
        return str(candidate), None
    return command, f"Interpreter not found: {candidate}"


def load_server_from_config(
    config_path: Path,
    server_name: str,
    *,
    expand_vars: str = "auto",
) -> LiveServerConfig:
    """Parse a Cursor/Claude/VS Code MCP config and return stdio launch params."""
    entry = _load_entry(config_path, server_name)
    command = entry.get("command")
    if not command:
        raise ConfigDiscoveryError(
            f"Server {server_name!r} has no stdio command (use --url for remote HTTP servers)"
        )
    args = [str(a) for a in entry.get("args") or []]
    env = {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
    if expand_vars != "off":
        command = expand_value(str(command), mode=expand_vars)
        args = expand_args(args, mode=expand_vars)
        env = expand_mapping(env, mode=expand_vars)
    merged_env = {**os.environ, **env}
    config_dir = config_path.expanduser().resolve().parent
    resolved_command, _ = resolve_interpreter(str(command), config_dir)
    return LiveServerConfig(
        command=resolved_command,
        args=args,
        env=merged_env,
        cwd=str(config_dir),
        server_name=server_name,
    )


def load_remote_from_config(
    config_path: Path,
    server_name: str,
    *,
    expand_vars: str = "auto",
) -> RemoteServerConfig:
    entry = _load_entry(config_path, server_name)
    url = entry.get("url") or entry.get("serverUrl") or entry.get("server_url")
    if not url:
        raise ConfigDiscoveryError(f"Server {server_name!r} has no remote url")
    if expand_vars != "off":
        url = expand_value(str(url), mode=expand_vars)
    transport = str(entry.get("transport") or entry.get("type") or "streamable-http")
    headers = {str(k): str(v) for k, v in (entry.get("headers") or {}).items()}
    if expand_vars != "off":
        headers = expand_mapping(headers, mode=expand_vars)
    auth = RemoteAuth(
        bearer_token=entry.get("bearerToken") or entry.get("bearer_token"),
        headers=headers,
        oauth_token_url=entry.get("oauthTokenUrl") or entry.get("oauth_token_url"),
        oauth_client_id=entry.get("oauthClientId") or entry.get("oauth_client_id"),
        oauth_client_secret=entry.get("oauthClientSecret") or entry.get("oauth_client_secret"),
        oauth_scopes=entry.get("oauthScopes") or entry.get("oauth_scopes"),
    )
    return RemoteServerConfig(url=str(url), transport=transport, auth=auth, server_name=server_name)


def _load_entry(config_path: Path, server_name: str) -> dict:
    path = config_path.expanduser().resolve()
    servers = load_servers_dict(path)
    if server_name not in servers:
        available = ", ".join(sorted(servers)) or "(none)"
        raise ConfigDiscoveryError(f"Server {server_name!r} not found in {path}. Available: {available}")
    entry = servers[server_name]
    if not isinstance(entry, dict):
        raise ConfigDiscoveryError(f"Server entry {server_name!r} is not an object")
    return entry
