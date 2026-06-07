"""MCTS-T-1036 — MCP Inspector RCE via SSE stdio command injection (CVE-2025-49596)."""

from __future__ import annotations

from typing import Any

_SUSPICIOUS_COMMANDS = (
    "command=calc",
    "command=cmd",
    "command=powershell",
    "command=bash",
    "command=sh",
    "command=curl",
    "command=wget",
    "command=python",
    "command=node",
    "command=nc",
    "command=netcat",
)

_INSPECTOR_PORTS = frozenset({6277, 6274})


def detect_inspector_rce_event(event: dict[str, Any]) -> bool:
    """Detect MCP Inspector SSE endpoints launching suspicious stdio commands."""
    log = event.get("log_entry", event)
    if not isinstance(log, dict):
        return False

    path = str(log.get("c-uri-path") or "")
    query = str(log.get("c-uri-query") or "")
    if path != "/sse" or "transportType=stdio" not in query:
        return False
    if "command=" not in query:
        return False

    port = log.get("cs-uri-port")
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        port_int = None

    if any(marker in query for marker in _SUSPICIOUS_COMMANDS):
        return True
    return port_int in _INSPECTOR_PORTS
