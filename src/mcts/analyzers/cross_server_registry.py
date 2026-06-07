"""Cross-server tool shadowing via registry events (MCTS-T-1029)."""

from __future__ import annotations

from typing import Any

_CAPABILITY_MARKERS = (
    "expanded_operations",
    "elevated_permissions",
    "unexpected_scope",
    "privilege_escalation",
)

_CONFLICT_TYPES = ("name_collision", "namespace_conflict", "identical_name")

_UNTRUSTED_LEVELS = ("unknown", "untrusted", "unverified")

_ADMIN_OPS = ("write", "delete", "execute", "admin", "root", "system")


def detect_cross_server_shadowing(event: dict[str, Any]) -> bool:
    """Detect MCTS-T-1029 indicators in tool registration telemetry."""
    log = event.get("log_entry", event)
    if not isinstance(log, dict):
        return False
    if str(log.get("event_type", "")) != "tool_registration":
        return False
    if _is_authorized_registration(log):
        return False

    if _duplicate_conflict(log):
        return True
    if _capability_mismatch(log):
        return True
    if _priority_manipulation(log):
        return True
    if _unauthorized_access(log):
        return True
    if _namespace_pollution(log):
        return True
    return _shadowing_indicators(log)


def _is_authorized_registration(log: dict[str, Any]) -> bool:
    if log.get("authorized_registration") or log.get("authorized_deployment"):
        return True
    if log.get("capability_change") == "authorized":
        return True
    if log.get("authorization_id") or log.get("approval_workflow") == "completed":
        return True
    if log.get("synchronization_event") or log.get("sync_operation") == "registry_sync":
        return True
    if log.get("failover_configuration") and log.get("server_trust_level") == "trusted":
        return True
    if log.get("load_balancing") and log.get("server_trust_level") == "trusted":
        return True
    return bool(log.get("legitimate_operation"))


def _duplicate_conflict(log: dict[str, Any]) -> bool:
    if not log.get("duplicate_tool_detected"):
        return False
    server_count = int(log.get("server_count") or 0)
    if server_count <= 1:
        return False
    conflict = str(log.get("conflict_type", ""))
    return any(marker in conflict for marker in _CONFLICT_TYPES)


def _capability_mismatch(log: dict[str, Any]) -> bool:
    caps = str(log.get("tool_capabilities", ""))
    if not any(marker in caps for marker in _CAPABILITY_MARKERS):
        return False
    return log.get("capability_change") == "unauthorized" and bool(log.get("scope_expansion"))


def _priority_manipulation(log: dict[str, Any]) -> bool:
    if str(log.get("server_priority", "")).lower() != "high":
        return False
    if log.get("registration_timing") != "suspicious":
        return False
    trust = str(log.get("server_trust_level", ""))
    return trust in _UNTRUSTED_LEVELS or bool(log.get("priority_override"))


def _unauthorized_access(log: dict[str, Any]) -> bool:
    if log.get("tool_access_pattern") != "privilege_escalation":
        return False
    if log.get("resource_access") != "beyond_scope":
        return False
    op = str(log.get("operation_type", ""))
    return any(marker in op for marker in _ADMIN_OPS)


def _namespace_pollution(log: dict[str, Any]) -> bool:
    if not log.get("bulk_registration"):
        return False
    if int(log.get("tool_count") or 0) <= 50:
        return False
    return bool(log.get("registration_burst") and log.get("similar_names_detected"))


def _shadowing_indicators(log: dict[str, Any]) -> bool:
    if log.get("tool_resolution_pattern") != "unexpected":
        return False
    return bool(log.get("legitimate_tool_bypassed") or log.get("response_interception"))
