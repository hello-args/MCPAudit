"""Tests for partitioned MCP vs supply-chain scoring."""

from __future__ import annotations

from mcts.reporting.models import Finding, Severity
from mcts.scoring.categories import ScoreBucket, bucket_for_finding
from mcts.scoring.partitions import partition_findings, score_partitioned


def _finding(analyzer: str, title: str = "issue") -> Finding:
    return Finding(
        id=f"test-{analyzer}",
        analyzer=analyzer,
        title=title,
        description="desc",
        severity=Severity.HIGH,
        recommendation="fix",
    )


def test_supply_chain_bucket() -> None:
    finding = _finding("supply_chain")
    assert bucket_for_finding(finding) == ScoreBucket.SUPPLY_CHAIN


def test_mcp_surface_bucket() -> None:
    finding = _finding("prompt_injection")
    assert bucket_for_finding(finding) == ScoreBucket.MCP_SURFACE


def test_partitioned_scores_differ() -> None:
    findings = [
        _finding("prompt_injection"),
        _finding("supply_chain"),
        _finding("supply_chain"),
        _finding("vulnerable_package"),
    ]
    buckets = partition_findings(findings)
    assert len(buckets[ScoreBucket.MCP_SURFACE]) == 1
    assert len(buckets[ScoreBucket.SUPPLY_CHAIN]) == 3
    breakdown = score_partitioned(findings)
    assert breakdown.mcp_surface > breakdown.supply_chain
    assert 0 <= breakdown.composite <= 100


def test_ifd_like_partition_mcp_high_supply_low() -> None:
    """Entrypoint MCP findings dominate; repo supply-chain findings stay separate."""
    mcp_findings = [_finding("prompt_injection", "injection")]
    supply_findings = [
        _finding("supply_chain", "unpinned setuptools"),
        _finding("vulnerable_package", "CVE-2024-0001"),
        _finding("vulnerable_package", "CVE-2024-0002"),
    ] * 10
    mcp_breakdown = score_partitioned(mcp_findings)
    supply_breakdown = score_partitioned(supply_findings)
    combined = score_partitioned(mcp_findings + supply_findings)
    assert mcp_breakdown.mcp_surface >= 80
    assert supply_breakdown.supply_chain < 50
    assert combined.mcp_surface > combined.supply_chain
