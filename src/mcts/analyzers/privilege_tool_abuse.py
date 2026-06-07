"""High-privilege MCP tool execution abuse (MCTS-T-1030)."""

from __future__ import annotations

from typing import Any

_PRIVILEGED_TOOLS = frozenset({"execute_command", "run_shell", "docker_run", "sys_admin"})

_PRIVILEGED_ARG_MARKERS = (
    "sudo",
    "su -",
    "chmod +s",
    "chown root",
    "chroot",
    "--privileged",
    "-v /:/",
    "/etc/shadow",
    "/etc/sudoers",
)


def detect_privilege_tool_abuse(event: dict[str, Any]) -> bool:
    """Detect MCTS-T-1030 indicators in tool execution telemetry."""
    tool_name = str(event.get("tool_name", ""))
    if tool_name not in _PRIVILEGED_TOOLS:
        return False
    params = event.get("parameters") if isinstance(event.get("parameters"), dict) else {}
    args = str(params.get("args", "")).lower()
    if not args:
        args = str(event.get("args", "")).lower()
    return any(marker in args for marker in _PRIVILEGED_ARG_MARKERS)
