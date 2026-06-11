"""History and trend series tests for scoring v2."""

from __future__ import annotations

from datetime import UTC, datetime

from mcts.mcp.models import MCPServerInfo
from mcts.output.history import record_scan_run, trend_points_for_target
from mcts.report.data import score_trend, trend_meta
from mcts.reporting.models import RiskScore, ScanReport, ScanSummary, ScoreBasis
from mcts.scoring.models import RiskScoreV2, ScoreV2Basis


def _minimal_report(**kwargs) -> ScanReport:
    defaults = dict(
        version="0.0.0",
        target="server.py",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(name="demo"),
        findings=[],
        summary=ScanSummary(),
        score=RiskScore(
            overall=80,
            risk_index=20,
            raw_risk=10,
            penalty=0,
            basis=ScoreBasis(critical=0, high=0, medium=0, low=0, scorable_total=0, excluded_non_scorable=0),
        ),
    )
    defaults.update(kwargs)
    return ScanReport(**defaults)


def test_record_scan_run_includes_scoring_version(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report = _minimal_report(
        summary=ScanSummary(critical=1, high=2, medium=1, low=1, total=5),
        scoring_version="both",
        score_v2=RiskScoreV2(
            absolute_risk=340,
            risk_range=(300, 380),
            risk_range_confidence="high",
            risk_level="high",
            security_score=28,
            confidence_score=75,
            legacy_overall=80,
            basis=ScoreV2Basis(
                scorable_count=5,
                excluded_non_scorable=1,
                severity_counts={"critical": 1, "high": 2, "medium": 1, "low": 1},
            ),
        ),
    )
    record_scan_run(report)
    points = trend_points_for_target("server.py")
    assert len(points) == 1
    assert points[0]["scoring_version"] == "both"
    assert points[0]["absolute_risk"] == 340
    assert points[0]["security_score"] == 28
    assert points[0]["findings_total"] == 5
    assert points[0]["critical"] == 1
    assert points[0]["high"] == 2


def test_trend_meta_uses_v2_series_when_uniform(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    for risk in (200, 250):
        report = _minimal_report(
            scoring_version="v2",
            score_v2=RiskScoreV2(
                absolute_risk=risk,
                risk_range=(risk - 20, risk + 20),
                risk_range_confidence="medium",
                risk_level="high",
                security_score=40,
                confidence_score=70,
                legacy_overall=80,
                basis=ScoreV2Basis(
                    scorable_count=3,
                    excluded_non_scorable=0,
                    severity_counts={"high": 2, "medium": 1},
                ),
            ),
        )
        record_scan_run(report)
    report = _minimal_report(scoring_version="v2")
    points = score_trend(report)
    meta = trend_meta(report, points)
    assert meta["series_key"] == "absolute_risk"
    assert points[-1]["trend_value"] == 250
