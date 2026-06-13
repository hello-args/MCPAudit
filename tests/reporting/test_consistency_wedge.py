"""Phase A½ consistency wedge — display-aligned surfaces when enforce."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPServerInfo
from mcts.output.history import record_scan_run, trend_points_for_target
from mcts.report.data import category_scores, llm_owasp_mappings
from mcts.reporting.models import Finding, ScanReport, ScanSummary, Severity
from mcts.scoring.engine import RiskScoringEngine

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")


def test_enforce_score_basis_uses_display_severity() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    assert report.summary.critical >= 1
    assert report.display_summary is not None
    assert report.display_summary.critical == 0
    assert report.score.basis.critical == 0
    assert RiskScoringEngine.verify(report.findings, report.score, use_display=True)


def test_off_score_basis_uses_template_severity() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="off")).run()
    assert report.score.basis.critical == report.summary.critical
    assert RiskScoringEngine.verify(report.findings, report.score, use_display=False)


def test_history_records_display_critical_and_trust_mode(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    record_scan_run(report)
    points = trend_points_for_target(str(SINGLE_TOOL.resolve()))
    assert len(points) == 1
    assert points[0]["findings_trust_mode"] == "enforce"
    assert points[0]["display_critical"] == 0
    assert points[0]["critical"] == report.summary.critical


def test_category_scores_use_display_when_enforced() -> None:
    finding = Finding(
        id="x",
        analyzer="attack_chains",
        severity=Severity.CRITICAL,
        display_severity=Severity.MEDIUM,
        title="Overlap chain",
        description="d",
        recommendation="r",
    )
    template_rows = category_scores([finding], use_display=False)
    display_rows = category_scores([finding], use_display=True)
    template_row = next(r for r in template_rows if r["key"] == "attack_chains")
    display_row = next(r for r in display_rows if r["key"] == "attack_chains")
    assert template_row["score"] > display_row["score"]


def test_owasp_risk_level_uses_display_when_enforced() -> None:
    finding = Finding(
        id="x",
        analyzer="attack_chains",
        severity=Severity.CRITICAL,
        display_severity=Severity.MEDIUM,
        title="Overlap chain",
        description="d",
        recommendation="r",
    )
    template = llm_owasp_mappings([finding], use_display=False)
    display = llm_owasp_mappings([finding], use_display=True)
    llm06_template = next(r for r in template["categories"] if r["id"] == "LLM06")
    llm06_display = next(r for r in display["categories"] if r["id"] == "LLM06")
    assert llm06_template["risk_level"] == "critical"
    assert llm06_display["risk_level"] == "medium"


def test_scanner_sets_findings_trust_mode_on_report() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    assert report.findings_trust_mode == "enforce"


def test_severity_filter_uses_display_when_trust_on() -> None:
    from mcts.reporting.display import effective_severity

    report = Scanner(
        ScanConfig(
            target=SINGLE_TOOL,
            findings_trust_mode="enforce",
            severity_filter=["critical"],
        )
    ).run()
    security = [f for f in report.findings if f.analyzer not in {"compliance", "live_discovery", "static_discovery"}]
    assert all(effective_severity(f) == Severity.CRITICAL for f in security)
    assert not any(f.analyzer == "attack_chains" for f in security)


def _minimal_report(**kwargs) -> ScanReport:
    from mcts.reporting.models import RiskScore, ScoreBasis

    defaults = dict(
        version="0.0.0",
        target="server.py",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(name="demo"),
        findings=[],
        summary=ScanSummary(),
        findings_trust_mode="enforce",
        display_summary=ScanSummary(critical=0, high=1, medium=2, low=0, total=3),
        score=RiskScore(
            overall=80,
            risk_index=20,
            raw_risk=10,
            penalty=10,
            basis=ScoreBasis(critical=0, high=1, medium=2, low=0, scorable_total=3, excluded_non_scorable=0),
        ),
    )
    defaults.update(kwargs)
    return ScanReport(**defaults)


def test_score_trend_fallback_uses_display_when_enforce() -> None:
    report = _minimal_report(
        summary=ScanSummary(critical=2, high=1, medium=0, low=0, total=3),
    )
    from mcts.report.data import score_trend

    points = score_trend(report)
    assert points[0]["critical"] == 0
    assert points[0]["display_critical"] == 0
