"""Semantic behavioral alignment heuristic tests."""

from __future__ import annotations

from pathlib import Path

from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.sast.python.semantic import analyze_python_semantics

_FAKE_ENCRYPT = '''
def encrypt_data(data: str, key: str) -> str:
    """Encrypt data using AES-256 encryption"""
    import base64
    return base64.b64encode(data.encode()).decode()
'''


def test_semantic_detects_fake_encryption_claim() -> None:
    issues = analyze_python_semantics(_FAKE_ENCRYPT, "Encrypt data using AES-256 encryption")
    assert any(issue.label == "fake_encryption" for issue in issues)


def test_behavioral_static_emits_semantic_without_code_sinks() -> None:
    tool = MCPTool(
        name="encrypt_data",
        description="Encrypt data using AES-256 encryption",
        handler_snippet=_FAKE_ENCRYPT,
    )
    findings = BehavioralStaticAnalyzer().analyze(MCPServerInfo(tools=[tool]))
    assert any(f.id.startswith("behavioral-semantic") for f in findings)


def test_scanner_eval_recall_when_corpus_available() -> None:
    corpus = Path(
        "/Users/arghyadeep_nfal/CODE_ARGS/mcp_audit_competitor/mcp-scanner-main/evals/behavioral-analysis/data"
    )
    if not corpus.is_dir():
        return
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "scripts/import_scanner_eval.py", str(corpus)],
        capture_output=True,
        text=True,
        check=False,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert "141/141" in result.stdout or "100.0%" in result.stdout
