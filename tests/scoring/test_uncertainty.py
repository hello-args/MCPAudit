"""Uncertainty helpers for scoring v2."""

from mcts.reporting.models import Finding, Severity
from mcts.scoring.uncertainty import analyzer_disagreement_factor


def test_analyzer_disagreement_factor_defaults_without_conflict() -> None:
    findings = [
        Finding(
            id="a",
            analyzer="prompt_injection",
            title="t",
            description="d",
            severity=Severity.HIGH,
            recommendation="fix",
            tool="read_file",
        )
    ]
    assert analyzer_disagreement_factor(findings) == 1.0


def test_analyzer_disagreement_factor_amplifies_on_tool_severity_conflict() -> None:
    findings = [
        Finding(
            id="a",
            analyzer="prompt_injection",
            title="t",
            description="d",
            severity=Severity.HIGH,
            recommendation="fix",
            tool="read_file",
        ),
        Finding(
            id="b",
            analyzer="data_leakage",
            title="t",
            description="d",
            severity=Severity.LOW,
            recommendation="fix",
            tool="read_file",
        ),
    ]
    assert analyzer_disagreement_factor(findings) == 1.4
