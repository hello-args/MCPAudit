"""Rug pull / behavioral change detection (MCTS-T-1013)."""

from __future__ import annotations

import re
from typing import Any

LEGITIMATE_FLAGS: tuple[str, ...] = (
    "legitimate_operation",
    "stable_performance",
    "approved_update",
    "legitimate_system_tool",
    "expected_access",
    "scheduled_expansion",
    "authorized_debugging",
)

BEHAVIORAL_FIELDS: tuple[str, ...] = (
    "network_activity",
    "file_access",
    "permission_request",
    "error_pattern",
    "resource_usage",
    "execution_time",
)

FILE_PATTERNS = frozenset(
    {
        "credential_files",
        "system_directories",
        "user_data",
        "configuration_files",
        "log_files",
    }
)


def detect_rug_pull_event(log_entry: dict[str, Any]) -> bool:
    """Detect MCTS-T-1013 rug-pull indicators in tool execution telemetry."""
    if log_entry.get("event_type") != "tool_execution":
        return False
    if any(log_entry.get(flag) for flag in LEGITIMATE_FLAGS):
        return False
    if not log_entry.get("behavioral_change_detected"):
        return False

    days = int(log_entry.get("days_since_approval", 0))
    executions = int(log_entry.get("execution_count", 0))
    deviation = _parse_std_dev(str(log_entry.get("baseline_deviation", "0")))
    if days <= 30 or executions <= 50 or deviation <= 2.0:
        return False

    has_behavioral = any(log_entry.get(field) for field in BEHAVIORAL_FIELDS)
    network = str(log_entry.get("network_connections", "")).lower()
    has_network = any(
        token in network for token in ("http://", "https://", "ftp://", "malicious", "attacker", "evil")
    )
    has_file = log_entry.get("file_access_pattern") in FILE_PATTERNS
    return has_behavioral or has_network or has_file


def _parse_std_dev(value: str) -> float:
    match = re.search(r"([\d.]+)", value)
    if not match:
        return 0.0
    return float(match.group(1))
