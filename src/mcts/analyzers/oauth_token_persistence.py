"""MCTS-T-1037 — OAuth token persistence / reuse after logout or credential rotation."""

from __future__ import annotations

from typing import Any


def detect_oauth_token_persistence(logs: list[dict[str, Any]]) -> bool:
    """Evaluate a sequence of OAuth telemetry rows for persistence abuse."""
    logout_time: str | None = None
    logout_user: str | None = None
    password_change_time: str | None = None
    password_user: str | None = None

    for log in logs:
        if log.get("event_type") == "user_logout":
            logout_time = str(log.get("timestamp", ""))
            logout_user = str(log.get("user_id", ""))
        elif (
            log.get("event_type") == "token_usage"
            and str(log.get("user_id", "")) == logout_user
            and logout_time
            and int(log.get("time_since_logout") or 0) >= 300
        ):
            return True

        if log.get("event_type") == "password_change":
            password_change_time = str(log.get("timestamp", ""))
            password_user = str(log.get("user_id", ""))
        elif (
            log.get("event_type") == "token_refresh"
            and str(log.get("user_id", "")) == password_user
            and password_change_time
            and int(log.get("time_since_password_change") or 999999) <= 86400
        ):
            return True

    for log in logs:
        if (
            log.get("event_type") in {"token_refresh", "api_access"}
            and int(log.get("geographic_distance") or 0) > 1000
            and int(log.get("time_delta") or 999999) < 3600
            and not log.get("flight_duration_reasonable")
        ):
            return True

        if (
            log.get("event_type") == "token_refresh"
            and log.get("token_type") == "refresh_token"
            and int(log.get("concurrent_sessions") or 0) > 1
        ):
            return True

        if (
            log.get("event_type") == "token_exchange"
            and log.get("client_family") == "microsoft_foci"
            and log.get("token_scope_expansion")
        ):
            return True

        if (
            log.get("event_type") == "prt_usage"
            and log.get("device_binding_validation") is False
            and log.get("conditional_access_bypass")
        ):
            return True

    return False


def detect_oauth_token_persistence_event(event: dict[str, Any]) -> bool:
    """Accept either a scenario payload with logs[] or a single log row."""
    logs = event.get("logs")
    if isinstance(logs, list):
        return detect_oauth_token_persistence([row for row in logs if isinstance(row, dict)])
    return False
