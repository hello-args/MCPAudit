"""YAML governance policies for scan and inventory gates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class GovernancePolicy(BaseModel):
    min_score: int | None = Field(default=None, ge=0, le=100)
    min_security_score: int | None = Field(default=None, ge=0, le=100)
    max_absolute_risk: int | None = Field(default=None, ge=0)
    max_risk_level: str | None = Field(default=None)
    min_category_score_v2: dict[str, int] = Field(default_factory=dict)
    max_critical: int | None = Field(default=None, ge=0)
    max_high: int | None = Field(default=None, ge=0)
    allowed_servers: list[str] = Field(default_factory=list)
    blocked_servers: list[str] = Field(default_factory=list)
    require_auth_env_for_sensitive: bool = False


def load_policy(path: Path | None) -> GovernancePolicy | None:
    if path is None:
        default = Path(".mcts/policy.yaml")
        if default.exists():
            path = default
        else:
            return None
    if not path.exists():
        raise FileNotFoundError(f"Governance policy not found: {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Governance policy must be a YAML mapping")
    return GovernancePolicy.model_validate(_normalize(payload))


def evaluate_policy(
    *,
    policy: GovernancePolicy,
    score: int,
    critical: int,
    high: int,
    servers: list[str],
    absolute_risk: int | None = None,
    security_score: int | None = None,
    risk_level: str | None = None,
    findings: list | None = None,
) -> list[str]:
    from mcts.report.data import category_scores_v2_gate_failures

    _LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    violations: list[str] = []
    if policy.min_score is not None and score < policy.min_score:
        violations.append(f"legacy score {score} below minimum {policy.min_score}")
    if policy.min_security_score is not None:
        if security_score is None:
            violations.append(
                f"min_security_score {policy.min_security_score} requires v2 scoring "
                "(use --scoring v2 or both)"
            )
        elif security_score < policy.min_security_score:
            violations.append(f"security score {security_score} below minimum {policy.min_security_score}")
    if policy.max_absolute_risk is not None:
        if absolute_risk is None:
            violations.append(
                f"max_absolute_risk {policy.max_absolute_risk} requires v2 scoring (use --scoring v2 or both)"
            )
        elif absolute_risk > policy.max_absolute_risk:
            violations.append(f"absolute risk {absolute_risk} exceeds maximum {policy.max_absolute_risk}")
    if policy.max_risk_level is not None:
        if risk_level is None:
            violations.append(
                f"max_risk_level {policy.max_risk_level!r} requires v2 scoring (use --scoring v2 or both)"
            )
        elif _LEVEL_ORDER.get(risk_level, 0) > _LEVEL_ORDER.get(policy.max_risk_level, 0):
            violations.append(f"risk level {risk_level!r} exceeds maximum {policy.max_risk_level!r}")
    if policy.min_category_score_v2:
        if absolute_risk is None:
            violations.append("min_category_score_v2 requires v2 scoring (use --scoring v2 or both)")
        elif findings is not None:
            violations.extend(category_scores_v2_gate_failures(findings, policy.min_category_score_v2))
    if policy.max_critical is not None and critical > policy.max_critical:
        violations.append(f"critical findings {critical} exceed max {policy.max_critical}")
    if policy.max_high is not None and high > policy.max_high:
        violations.append(f"high findings {high} exceed max {policy.max_high}")
    if policy.allowed_servers:
        for server in servers:
            if server not in policy.allowed_servers:
                violations.append(f"server {server!r} not in allowlist")
    for server in policy.blocked_servers:
        if server in servers:
            violations.append(f"blocked server present: {server}")
    return violations


def _normalize(payload: dict[str, Any]) -> dict[str, Any]:
    row = dict(payload)
    if "allowlist" in row and "allowed_servers" not in row:
        row["allowed_servers"] = row.pop("allowlist")
    if "blocklist" in row and "blocked_servers" not in row:
        row["blocked_servers"] = row.pop("blocklist")
    return row
