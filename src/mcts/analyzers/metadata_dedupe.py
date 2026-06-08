"""Remove duplicate metadata poisoning findings across analyzers."""

from __future__ import annotations

from mcts.reporting.models import Finding


def dedupe_metadata_findings(findings: list[Finding]) -> list[Finding]:
    """Drop metadata_integrity poison hits when surface_metadata already reported them."""
    surface_keys = {
        _poison_key(finding)
        for finding in findings
        if finding.analyzer == "surface_metadata" and "poison" in finding.id
    }
    if not surface_keys:
        return findings

    kept: list[Finding] = []
    for finding in findings:
        if (
            finding.analyzer == "metadata_integrity"
            and "meta-poison" in finding.id
            and _poison_key(finding) in surface_keys
        ):
            continue
        kept.append(finding)
    return kept


def _poison_key(finding: Finding) -> tuple[str, str, str]:
    tool = finding.tool or ""
    pattern = str(finding.evidence.get("pattern", ""))
    surface = str(finding.evidence.get("surface", "tool"))
    return tool, pattern, surface
