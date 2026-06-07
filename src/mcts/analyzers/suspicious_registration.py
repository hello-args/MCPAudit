"""Suspicious MCP tool registration (MCTS-T-1031)."""

from __future__ import annotations

from typing import Any

_SUSPICIOUS_MANIFEST = ("attacker", "typo", "malicious")


def detect_suspicious_tool_registration(event: dict[str, Any]) -> bool:
    """Detect MCTS-T-1031 indicators in tool.register telemetry."""
    payload = event.get("event", event)
    event_type = str(payload.get("event_type", ""))
    if event_type == "tool_execution":
        return False

    action = str(payload.get("event.action") or payload.get("action", ""))
    if action and action != "tool.register":
        return False

    manifest_url = str(payload.get("manifest_url") or payload.get("manifestUrl") or "")
    publisher = payload.get("publisher")
    trust_score = payload.get("trust_score")

    if manifest_url.startswith("http://"):
        return True
    lowered = manifest_url.lower()
    if any(marker in lowered for marker in _SUSPICIOUS_MANIFEST):
        return True
    if publisher is None and trust_score is None and manifest_url:
        return True
    return action == "tool.register" and publisher is None and trust_score is None
