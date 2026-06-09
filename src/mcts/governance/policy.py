"""YAML governance policies for scan and inventory gates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class GovernancePolicy(BaseModel):
    min_score: int | None = Field(default=None, ge=0, le=100)
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
) -> list[str]:
    violations: list[str] = []
    if policy.min_score is not None and score < policy.min_score:
        violations.append(f"score {score} below minimum {policy.min_score}")
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
