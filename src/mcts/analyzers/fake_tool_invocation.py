"""Fake or spoofed MCP tool invocation (MCTS-T-1032)."""

from __future__ import annotations

import json
from typing import Any

_SUSPICIOUS_TOOL_NAMES = (
    "admin",
    "root",
    "sudo",
    "escalate",
    "bypass",
    "system_",
    "shell",
    "eval",
    "session_escalate",
)

_SUSPICIOUS_ARGUMENTS = (
    "bypass_acl",
    "bypass_restrictions",
    "elevated",
    "unrestricted",
    "sudo",
)


def detect_fake_tool_invocation(event: dict[str, Any]) -> bool:
    """Detect MCTS-T-1032 indicators in tools/call telemetry."""
    payload = event.get("event", event)
    action = str(payload.get("event.action") or payload.get("action", ""))
    if action and action != "tools/call":
        method = str(payload.get("method", ""))
        if method != "tools/call":
            return False

    tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else {}
    tool_name = str(tool.get("name") or payload.get("tool_name") or payload.get("tool.name") or "")
    lowered_name = tool_name.lower()
    if any(marker in lowered_name for marker in _SUSPICIOUS_TOOL_NAMES):
        return True

    arguments = tool.get("arguments") or payload.get("tool.arguments") or payload.get("arguments")
    blob = _argument_blob(arguments)
    return any(marker in blob for marker in _SUSPICIOUS_ARGUMENTS)


def _argument_blob(arguments: Any) -> str:
    if isinstance(arguments, str):
        return arguments.lower()
    if isinstance(arguments, dict):
        return json.dumps(arguments, default=str).lower()
    if isinstance(arguments, list):
        return json.dumps(arguments, default=str).lower()
    return ""
