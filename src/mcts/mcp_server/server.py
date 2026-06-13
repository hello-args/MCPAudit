"""MCTS MCP server tools for IDE agents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcts.taxonomy.mapper import load_taxonomy


def scan_mcp_target(target: str, live: bool = False) -> str:
    """Run an MCTS security scan on an MCP server path or repository."""
    from mcts.core.config import ScanConfig
    from mcts.core.scanner import Scanner

    config = ScanConfig(
        target=Path(target),
        live=live,
        live_consent=live,
    )
    report = Scanner(config).run()
    return json.dumps(report.model_dump(mode="json"), indent=2)


def scan_mcp_server(target: str, live: bool = False) -> str:
    """Alias for scan_mcp_target — run an MCTS security scan on an MCP server."""
    return scan_mcp_target(target, live=live)


def list_techniques() -> str:
    """List bundled MCTS-T techniques and default analyzers."""
    data = load_taxonomy()
    rows = []
    for technique_id in sorted(data.get("techniques", {})):
        row = data["techniques"][technique_id]
        rows.append(
            {
                "technique_id": technique_id,
                "name": row.get("name"),
                "severity_default": row.get("severity_default"),
                "analyzers": row.get("analyzers") or [],
            }
        )
    return json.dumps({"techniques": rows, "count": len(rows)}, indent=2)


def explain_finding(finding_id: str, report_json: str) -> str:
    """Explain a finding from a scan report JSON payload by finding ID."""
    payload = json.loads(report_json)
    findings = payload.get("findings") or []
    match = next((row for row in findings if row.get("id") == finding_id), None)
    if match is None:
        return json.dumps({"error": f"Finding not found: {finding_id}"})

    explanation = {
        "id": match.get("id"),
        "title": match.get("title"),
        "severity": match.get("severity"),
        "display_severity": match.get("display_severity"),
        "impact": match.get("impact"),
        "evidence_strength": match.get("evidence_strength"),
        "evidence_type": match.get("evidence_type"),
        "finding_type": match.get("finding_type"),
        "finding_kind": match.get("finding_kind"),
        "priority_score": match.get("priority_score"),
        "chain_level": match.get("chain_level"),
        "rule_stability": match.get("rule_stability"),
        "analyzer": match.get("analyzer"),
        "technique_id": match.get("technique_id"),
        "description": match.get("description"),
        "recommendation": match.get("recommendation"),
        "tool": match.get("tool"),
    }
    evidence = match.get("evidence") or {}
    explanation["confidence_factors"] = evidence.get("confidence_factors")
    explanation["false_positive_conditions"] = evidence.get("false_positive_conditions")
    explanation["counterfactual_remediation"] = evidence.get("counterfactual_remediation")
    explanation["facts"] = evidence.get("facts")
    explanation["interpretation"] = evidence.get("interpretation")
    explanation["runtime_validation"] = evidence.get("runtime_validation")
    explanation["evidence"] = evidence
    return json.dumps(explanation, indent=2)


def compare_baselines(baseline_report_json: str, current_report_json: str) -> str:
    """Compare two scan reports and summarize score and finding deltas."""
    baseline = _report_summary(json.loads(baseline_report_json))
    current = _report_summary(json.loads(current_report_json))
    delta: dict[str, Any] = {
        "baseline": baseline,
        "current": current,
        "score_delta": current["overall_score"] - baseline["overall_score"],
        "finding_delta": current["finding_count"] - baseline["finding_count"],
        "new_findings": _new_finding_ids(baseline, current),
    }
    if baseline.get("absolute_risk") is not None and current.get("absolute_risk") is not None:
        delta["absolute_risk_delta"] = current["absolute_risk"] - baseline["absolute_risk"]
    if baseline.get("security_score") is not None and current.get("security_score") is not None:
        delta["security_score_delta"] = current["security_score"] - baseline["security_score"]
    if baseline.get("scoring_version") or current.get("scoring_version"):
        delta["scoring_mode_note"] = (
            "Legacy overall_score and v2 absolute_risk use different scales — compare like with like."
        )
    chain_delta = (current.get("critical") or 0) - (baseline.get("critical") or 0)
    if chain_delta and delta.get("finding_delta", 0) != chain_delta:
        delta["chain_meta_note"] = (
            "Finding deltas may include attack_chains meta-rows excluded from v2 absolute_risk."
        )
    display_crit_delta = (current.get("display_critical") or 0) - (baseline.get("display_critical") or 0)
    if display_crit_delta and display_crit_delta != chain_delta:
        delta["display_critical_delta"] = display_crit_delta
    return json.dumps(delta, indent=2)


def create_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError(
            "MCP server mode requires the [mcp] extra.\n"
            'Install with: pip install "mcp-mcts[mcp]"\n'
            "Or, from a repo checkout: uv sync --extra mcp\n"
            "Run `mcts doctor .` to verify optional extras."
        ) from exc

    app = FastMCP("mcts")
    app.tool()(scan_mcp_target)
    app.tool()(scan_mcp_server)
    app.tool()(list_techniques)
    app.tool()(explain_finding)
    app.tool()(compare_baselines)
    return app


def _severity_counts(payload: dict[str, Any]) -> dict[str, int]:
    trust_mode = str(payload.get("findings_trust_mode") or "off")
    display = payload.get("display_summary") or {}
    template = payload.get("summary") or {}
    use_display = trust_mode == "enforce" or (
        trust_mode == "warn" and display.get("critical") is not None
    )
    active = display if use_display and display else template
    return {
        "critical": int(active.get("critical") or 0),
        "high": int(active.get("high") or 0),
    }


def _report_summary(payload: dict[str, Any]) -> dict[str, Any]:
    score = payload.get("score") or {}
    score_v2 = payload.get("score_v2") or {}
    findings = payload.get("findings") or []
    template = payload.get("summary") or {}
    display = payload.get("display_summary") or {}
    counts = _severity_counts(payload)
    summary: dict[str, Any] = {
        "overall_score": int(score.get("overall") or 0),
        "finding_count": len(findings),
        "finding_ids": sorted(str(row.get("id")) for row in findings if row.get("id")),
        "critical": counts["critical"],
        "high": counts["high"],
        "template_critical": int(template.get("critical") or 0),
        "template_high": int(template.get("high") or 0),
        "display_critical": int(display.get("critical") or 0) if display else None,
        "display_high": int(display.get("high") or 0) if display else None,
        "findings_trust_mode": payload.get("findings_trust_mode") or "off",
        "scoring_version": payload.get("scoring_version") or "legacy",
    }
    if score_v2:
        if score_v2.get("absolute_risk") is not None:
            summary["absolute_risk"] = int(score_v2["absolute_risk"])
        if score_v2.get("security_score") is not None:
            summary["security_score"] = int(score_v2["security_score"])
        if score_v2.get("risk_level"):
            summary["risk_level"] = str(score_v2["risk_level"])
    return summary


def _new_finding_ids(baseline: dict[str, Any], current: dict[str, Any]) -> list[str]:
    old = set(baseline.get("finding_ids") or [])
    return sorted(fid for fid in current.get("finding_ids") or [] if fid not in old)
