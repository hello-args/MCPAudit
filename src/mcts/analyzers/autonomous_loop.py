"""MCTS-T-1035 — repeated identical MCP tool invocations (autonomous loop exploit)."""

from __future__ import annotations

from typing import Any


def detect_autonomous_loop_event(event: dict[str, Any], *, threshold: int = 3) -> bool:
    """Detect loop symptoms from a batch of events or a single row with an events list."""
    rows = event.get("events")
    if isinstance(rows, list):
        return _detect_repeated_calls(rows, threshold=threshold)
    if isinstance(event, list):
        return _detect_repeated_calls(event, threshold=threshold)
    return False


def _detect_repeated_calls(rows: list[Any], *, threshold: int) -> bool:
    counts: dict[tuple[str, str, str], int] = {}
    for entry in rows:
        if not isinstance(entry, dict):
            continue
        key = (
            str(entry.get("session_id", "")),
            str(entry.get("tool_name", "")),
            str(entry.get("args_hash", "")),
        )
        if not key[0] or not key[1]:
            continue
        counts[key] = counts.get(key, 0) + 1
        if counts[key] >= threshold:
            return True
    return False
