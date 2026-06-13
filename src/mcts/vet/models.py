"""Package vetting report models."""

from __future__ import annotations

from pydantic import BaseModel, Field

from mcts.reporting.models import Severity


class VetFinding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    recommendation: str
    evidence: dict = Field(default_factory=dict)


class VetReport(BaseModel):
    ecosystem: str
    package: str
    version: str | None = None
    verdict: str
    findings: list[VetFinding] = Field(default_factory=list)

    @property
    def risk_score(self) -> int:
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
        }
        return min(100, sum(weights.get(f.severity, 0) for f in self.findings))
