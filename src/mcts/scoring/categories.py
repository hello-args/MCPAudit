"""Analyzer → score-bucket mapping for partitioned scoring."""

from __future__ import annotations

from enum import StrEnum

from mcts.reporting.models import Finding


class ScoreBucket(StrEnum):
    MCP_SURFACE = "mcp_surface"
    SUPPLY_CHAIN = "supply_chain"
    DEPENDENCY_HYGIENE = "dependency_hygiene"


SUPPLY_CHAIN_ANALYZERS = frozenset(
    {
        "supply_chain",
        "vulnerable_package",
        "npm_audit",
        "virustotal",
        "pip_audit",
    }
)

_UNPINNED_MARKERS = ("unpinned", "unpinned_version", "missing_pin")


def bucket_for_finding(finding: Finding) -> ScoreBucket:
    """Assign each finding to exactly one score bucket."""
    analyzer = finding.analyzer
    if analyzer in SUPPLY_CHAIN_ANALYZERS:
        if _is_dependency_hygiene(finding):
            return ScoreBucket.DEPENDENCY_HYGIENE
        return ScoreBucket.SUPPLY_CHAIN
    if _is_dependency_hygiene(finding):
        return ScoreBucket.DEPENDENCY_HYGIENE
    return ScoreBucket.MCP_SURFACE


def _is_dependency_hygiene(finding: Finding) -> bool:
    evidence = finding.evidence or {}
    tags = evidence.get("tags") or evidence.get("tag") or []
    if isinstance(tags, str):
        tags = [tags]
    lowered = {str(t).lower() for t in tags}
    if lowered & set(_UNPINNED_MARKERS):
        return True
    title = finding.title.lower()
    return "unpinned" in title or "unpinned version" in title
