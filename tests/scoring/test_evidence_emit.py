"""Tests for v2 scoring evidence enrichment."""

from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_emit import enrich_scoring_evidence
from mcts.scoring.evidence_tags import has_v2_evidence
from mcts.scoring.factors import classify_exploitability
from mcts.scoring.weights import load_weights


def test_permission_analyzer_gets_precondition_evidence() -> None:
    from mcts.analyzers.permissions import PermissionAnalyzer
    from mcts.mcp.models import MCPServerInfo, MCPTool

    server = MCPServerInfo(
        tools=[MCPTool(name="wipe_db", description="Delete all records permanently")]
    )
    findings = PermissionAnalyzer().analyze(server)
    assert findings
    assert findings[0].evidence.get("precondition_level") == "some"
    assert findings[0].confidence is not None
    assert has_v2_evidence(findings[0])


def test_command_execution_exploitability_class() -> None:
    finding = Finding(
        id="cmd-1",
        analyzer="command_execution",
        title="Exec",
        description="d",
        severity=Severity.HIGH,
        recommendation="fix",
        tool="run",
    )
    enriched = enrich_scoring_evidence([finding])[0]
    weights = load_weights("manual_v1")
    expected = weights.classifiers["exploitability"]["command_execution"]
    assert classify_exploitability(enriched, weights) == expected


def test_attack_chains_path_hop_count_from_graph() -> None:
    finding = Finding(
        id="chain-credential-theft",
        analyzer="attack_chains",
        title="Chain",
        description="d",
        severity=Severity.CRITICAL,
        recommendation="fix",
        evidence={},
    )
    graph = {
        "paths": [
            {
                "id": "path-1",
                "finding_ids": ["chain-credential-theft"],
                "hop_count": 2,
                "nodes": ["a", "b", "c"],
            }
        ]
    }
    enriched = enrich_scoring_evidence([finding], attack_graph=graph)[0]
    assert enriched.evidence.get("hop_count") == 2
    assert enriched.evidence.get("path") == ["a", "b", "c"]
