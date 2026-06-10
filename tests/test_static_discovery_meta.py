"""Tests for static discovery meta-findings."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.discovery.static_meta import static_discovery_meta_findings
from mcts.mcp.models import MCPServerInfo

ROOT = Path(__file__).resolve().parents[1]
RUST_RMCP_BENCH = ROOT / "examples" / "bench" / "rust-mcp-rmcp"


def test_static_meta_when_rust_sources_but_no_tools() -> None:
    server = MCPServerInfo(name="demo", tools=[], discovery_mode="static")
    config = ScanConfig(target=RUST_RMCP_BENCH, languages=["python", "typescript"])
    findings = static_discovery_meta_findings(server, config)
    assert not findings


def test_static_meta_emits_when_rust_enabled_but_zero_tools() -> None:
    server = MCPServerInfo(name="demo", tools=[], discovery_mode="static")
    config = ScanConfig(target=RUST_RMCP_BENCH, languages=["rust"])
    findings = static_discovery_meta_findings(server, config)
    assert any(f.analyzer == "static_discovery" for f in findings)


def test_rmcp_repo_scan_discovers_tools_without_explicit_language_flag() -> None:
    from mcts.discovery.language_detect import resolve_default_languages

    config = ScanConfig(
        target=RUST_RMCP_BENCH,
        languages=resolve_default_languages(RUST_RMCP_BENCH),
    )
    report = Scanner(config).run()
    assert report.server.tools
    assert not any(f.id == "static-discovery-rust-incomplete" for f in report.findings)
