"""Tests for supply-chain analysis."""

from pathlib import Path

from mcts.analyzers.supply_chain import SupplyChainAnalyzer
from mcts.mcp.models import MCPServerInfo


def test_pyproject_ignores_requires_python(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = ["requests>=2.31.0"]
""".strip(),
        encoding="utf-8",
    )

    findings = SupplyChainAnalyzer(tmp_path).analyze(MCPServerInfo())
    descriptions = [finding.description for finding in findings]

    assert not any("requires-python" in description for description in descriptions)
    assert any("requests>=2.31.0" in description for description in descriptions)
