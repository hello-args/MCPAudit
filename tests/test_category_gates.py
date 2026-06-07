"""Category gate parsing and CLI integration tests."""

from __future__ import annotations

from mcts.report.data import category_gate_failures, parse_category_gates
from mcts.reporting.models import Finding, Severity


def test_parse_category_gates_accepts_comma_and_repeatable() -> None:
    gates = parse_category_gates(["permissions:10", "injection:5,execution:3"])
    assert gates == {"permissions": 10, "injection": 5, "execution": 3}


def test_category_gate_failures_when_score_meets_limit() -> None:
    findings = [
        Finding(
            id="p1",
            analyzer="permission_analyzer",
            title="perm",
            description="d",
            severity=Severity.HIGH,
            recommendation="r",
        ),
        Finding(
            id="p2",
            analyzer="permission_analyzer",
            title="perm2",
            description="d",
            severity=Severity.HIGH,
            recommendation="r",
        ),
    ]
    failures = category_gate_failures(findings, {"permissions": 10})
    assert failures
    assert "Excessive Permissions" in failures[0]


def test_category_gate_passes_below_limit() -> None:
    findings = [
        Finding(
            id="p1",
            analyzer="permission_analyzer",
            title="perm",
            description="d",
            severity=Severity.LOW,
            recommendation="r",
        )
    ]
    assert not category_gate_failures(findings, {"permissions": 10})
