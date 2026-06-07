"""Runtime OAuth telemetry detectors (MCTS-T-1017, MCTS-T-1018, MCTS-T-1019)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

ROGUE_ISSUER_MARKERS = (
    "attacker",
    "malicious",
    "rogue",
    "evil",
    "phish",
    "fake-oauth",
)

TRUSTED_ISSUER_HOSTS = (
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.windows.net",
    "github.com",
    "signin.aws.amazon.com",
    "appleid.apple.com",
    "auth0.com",
    "okta.com",
    "login.salesforce.com",
)

ELEVATED_OPERATIONS = frozenset(
    {"delete", "admin", "modify_permissions", "system_config", "write_all", "grant_access"}
)
LOW_SCOPES = frozenset({"read", "list", "view"})
HIGH_SCOPES = frozenset({"write", "delete", "admin", "execute"})
BROAD_SCOPE_MARKERS = ("admin", "*:*", "system.", "root", "read:all", "write:all")


def _event_action(event: dict[str, Any]) -> str:
    return str(event.get("event.action") or event.get("event_action") or "")


def _issuer_host(event: dict[str, Any]) -> str:
    for key in ("iss", "issuer.url", "issuer_url", "token_issuer"):
        value = event.get(key)
        if isinstance(value, str) and value.startswith("http"):
            return (urlparse(value).hostname or "").lower()
    return ""


def _is_untrusted_issuer(host: str) -> bool:
    if not host:
        return False
    if any(marker in host for marker in ROGUE_ISSUER_MARKERS):
        return True
    if any(trusted in host for trusted in TRUSTED_ISSUER_HOSTS):
        return False
    return any(marker in host for marker in (".example", "localhost", "127.0.0.1"))


def _scope_text(event: dict[str, Any]) -> str:
    for key in ("token.scope", "granted_scopes", "token_scope", "scope"):
        value = event.get(key)
        if value is not None:
            return str(value).lower()
    return ""


def detect_rogue_as_event(event: dict[str, Any]) -> bool:
    """MCTS-T-1017 — rogue AS, PoP bypass, key substitution, super-token issuance."""
    action = _event_action(event)
    host = _issuer_host(event)

    if action == "token.issued":
        scope = _scope_text(event)
        broad = any(marker in scope for marker in BROAD_SCOPE_MARKERS)
        if broad and (_is_untrusted_issuer(host) or "admin" in scope):
            return True

    if action == "token.validated":
        cnf = event.get("token.cnf.jkt")
        pop_required = event.get("config.pop_required") or event.get("config_pop_required")
        if pop_required and cnf in (None, "", "undefined"):
            return True

    if action == "token.signature.valid":
        kid = str(event.get("token.kid") or event.get("kid") or "")
        if kid and ("unknown" in kid.lower() or "rogue" in kid.lower()):
            return True
        if kid and _is_untrusted_issuer(host):
            return True

    if action in {"discovery.fetch", "openid.configuration", "jwks.fetch"}:
        issuer_url = str(event.get("issuer.url") or event.get("issuer_url") or "")
        if issuer_url and _is_untrusted_issuer((urlparse(issuer_url).hostname or "").lower()):
            return True

    return False


def detect_confused_deputy_event(event: dict[str, Any]) -> bool:
    """MCTS-T-1018 — token forwarding across users, tenants, or audiences."""
    event_type = str(event.get("event_type") or event.get("event.action") or "")

    owner = event.get("token_owner_id")
    requester = event.get("request_user_id")
    if owner and requester and str(owner) != str(requester):
        return True

    source_user = event.get("source_user")
    destination_user = event.get("destination_user")
    if source_user and destination_user:
        match_users = event.get("match_users")
        if match_users is False or str(source_user) != str(destination_user):
            if event_type in {"token_forward", "authorization_forward", "credential_relay"}:
                return True
            if event.get("action") in {"forward_authorization", "relay_token", "proxy_authentication"}:
                return True

    original_owner = event.get("original_token_owner")
    accessor_owner = event.get("accessing_instance_owner")
    if original_owner and accessor_owner and str(original_owner) != str(accessor_owner):
        return True

    aud = event.get("token_audience") or event.get("jwt_aud_claim")
    target = event.get("destination_instance") or event.get("target_service_id")
    if aud == "*":
        return True
    if aud and target and event.get("match_audience") is False:
        return True
    if aud and target and str(aud) != str(target) and event.get("match_audience") is not False:
        return True

    token_tenant = event.get("token_tenant_id")
    accessing_tenant = event.get("accessing_tenant_id")
    if token_tenant and accessing_tenant and str(token_tenant) != str(accessing_tenant):
        return True

    if event.get("token_passthrough_detected") is True:
        return True
    issued_for = event.get("token_issued_for")
    server_id = event.get("mcp_server_id")
    if issued_for and server_id and str(issued_for) != str(server_id):
        return True

    if event.get("consent_validated") is False or event.get("per_client_consent") is False:
        if event.get("consent_cookie_reused") is True:
            return True
        if event_type in {"oauth_authorization", "token_issuance"}:
            return True

    expected = event.get("expected_issuer")
    actual = event.get("actual_issuer")
    if expected and actual and str(expected) != str(actual):
        return True

    principal = event.get("principal_account")
    target_role = event.get("target_role_account")
    if (
        principal
        and target_role
        and str(principal) != str(target_role)
        and event.get("external_id") in (None, "")
        and event.get("trust_policy_violated") is not False
    ):
        return True

    if event.get("impossible_travel_detected") is True:
        return True

    depth = event.get("tool_chain_depth")
    if isinstance(depth, int) and depth >= 2:
        if event.get("original_auth_context_preserved") is False:
            return True
        parent = event.get("parent_tool_user")
        invoked = event.get("invoked_tool_user")
        if parent and invoked and str(parent) != str(invoked):
            return True

    token_id = event.get("token_id")
    if token_id and int(event.get("using_instance_count") or 0) >= 2:
        return True
    return bool(event.get("jwt_jti") and int(event.get("unique_client_count") or 0) >= 2)


def detect_scope_substitution_event(event: dict[str, Any]) -> bool:
    """MCTS-T-1019 — elevated or substituted OAuth scopes at runtime."""
    log = event.get("log_entry", event)
    if not isinstance(log, dict):
        return False

    if log.get("within_baseline") is True and log.get("scope_validation") == "passed":
        return False
    if log.get("within_policy") is True or log.get("temporary_elevation_approved") is True:
        return False
    if log.get("requester_type") == "service_account" and log.get("token_subject_type") == "service_account":
        return False
    if log.get("user_role") == "administrator" and log.get("scope_validation") == "passed":
        return False
    if log.get("batch_operation") is True and log.get("all_requests_same_scope") is True:
        return False

    event_type = str(log.get("event_type") or "")

    if (
        event_type == "authorization_check"
        and log.get("scope_validation") == "failed"
        and log.get("token_signature_valid")
        and log.get("audience_validation") == "passed"
    ):
        return True

    granted = str(log.get("granted_scopes") or log.get("token_scope") or "").lower()
    operation = str(log.get("operation_type") or "")
    elevated_op = operation in ELEVATED_OPERATIONS or any(
        marker in granted for marker in ("admin", "delete", "write_all", "*")
    )

    if event_type in {"api_request", "mcp_tool_invocation", "mcp_tool_chain_analysis"} and elevated_op:
        if log.get("scope_deviation_severity") in {"high", "critical"}:
            return True
        if log.get("baseline_exceeded") is True:
            return True
        if log.get("privilege_elevation") is True:
            return True
        if log.get("wildcard_scope_detected") is True:
            return True
        if "*" in granted:
            return True

    if (
        event_type == "scope_usage_analysis"
        and log.get("scope_elevation_detected")
        and log.get("baseline_exceeded")
        and log.get("scope_deviation_severity") in {"high", "critical"}
    ):
        return True

    if event_type == "token_usage_pattern":
        if log.get("same_user") and log.get("scope_variance") == "high":
            count = int(log.get("unique_token_count") or 0)
            window = int(log.get("time_window_seconds") or 9999)
            if count >= 2 and window <= 600:
                return True
        if log.get("escalation_pattern") == "gradual" and int(log.get("unique_token_count") or 0) >= 4:
            return True

    source_scope = str(log.get("source_tool_scope") or "")
    target_scope = str(log.get("target_operation_scope") or "")
    if log.get("privilege_elevation") and source_scope in LOW_SCOPES and target_scope in HIGH_SCOPES:
        return True

    if event_type == "token_analysis":
        if log.get("token_scope_change_detected") and log.get("elevated_scope"):
            return True
        if log.get("scope_modification_detected") and log.get("elevated_scope"):
            return True

    if (
        event_type == "authorization_sequence"
        and int(log.get("failed_attempts") or 0) >= 2
        and log.get("final_attempt_status") == "success"
        and log.get("token_changed")
        and int(log.get("time_window_seconds") or 999) <= 60
    ):
        return True

    if (
        event_type == "api_request"
        and log.get("token_subject_type") == "service_account"
        and log.get("requester_type") == "user"
        and any(marker in granted for marker in ("admin", "service", "automation"))
    ):
        return True

    if (
        event_type == "token_validation"
        and log.get("token_audience_mismatch")
        and log.get("token_accepted")
        and log.get("different_service")
    ):
        return True

    if log.get("time_of_day") == "off_hours" and log.get("scope_deviation_severity") in {"high", "critical"}:
        return True

    return bool(log.get("geographic_anomaly") and log.get("scope_deviation_severity") in {"high", "critical"})
