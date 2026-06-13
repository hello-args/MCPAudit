"""Combined scan + governance policy gate evaluation."""

from __future__ import annotations

from datetime import UTC, datetime

from mcts.core.config import ScanConfig
from mcts.governance.auth_env import evaluate_auth_env_violations
from mcts.governance.policy import evaluate_policy, load_policy
from mcts.governance.scan_gates import evaluate_scan_gate_violations
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, RiskScore, ScanReport, ScanSummary, ScoreBasis


def _policy_server_ids(report: ScanReport) -> list[str]:
    """Identifiers checked against YAML allowlist/blocklist."""
    ids: list[str] = []
    name = (report.server.name or "").strip()
    if name:
        ids.append(name)
    target = str(report.target).strip()
    if target and target not in ids:
        ids.append(target)
    return ids or [target]


def collect_gate_violations(report: ScanReport, config: ScanConfig) -> list[str]:
    """Scan gates plus YAML governance policy (allowlist, v2 category mins, etc.)."""
    violations = list(evaluate_scan_gate_violations(report, config))
    violations.extend(evaluate_auth_env_violations(config))
    if config.ignore_policy:
        return violations
    try:
        policy = load_policy(config.governance_policy)
    except FileNotFoundError:
        policy = None
    if policy is None:
        return violations
    violations.extend(evaluate_policy(policy=policy, servers=_policy_server_ids(report)))
    return violations


def build_gate_scan_report(
    findings: list[Finding],
    config: ScanConfig,
    *,
    target: str | None = None,
    scan_scope: str = "repository",
) -> ScanReport:
    """Minimal ScanReport for gate evaluation on auxiliary finding lists."""
    report_target = target or str(config.target)
    summary = ScanSummary.from_findings(findings)
    display_summary = (
        ScanSummary.from_display(findings, security_only=True)
        if config.findings_trust_mode != "off"
        else None
    )
    basis = ScoreBasis(
        critical=summary.critical,
        high=summary.high,
        medium=summary.medium,
        low=summary.low,
        scorable_total=summary.total,
        excluded_non_scorable=max(0, len(findings) - summary.total),
    )
    score = RiskScore(overall=100, risk_index=0, raw_risk=0, penalty=0, basis=basis)
    return ScanReport(
        version="0.0.0",
        target=report_target,
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(name=report_target),
        findings=findings,
        summary=summary,
        display_summary=display_summary,
        findings_trust_mode=config.findings_trust_mode,
        score=score,
        scan_scope=scan_scope,
    )


def collect_findings_gate_violations(
    findings: list[Finding],
    config: ScanConfig,
    *,
    target: str | None = None,
    scan_scope: str = "repository",
) -> list[str]:
    """Policy/CLI gates for vet, fuzz, inventory, and other non-Scanner entry points."""
    report = build_gate_scan_report(
        findings,
        config,
        target=target,
        scan_scope=scan_scope,
    )
    return collect_gate_violations(report, config)
