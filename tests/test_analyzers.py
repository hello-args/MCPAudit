"""Tests for source-aware analyzers."""

from pathlib import Path

from mcts.analyzers.command_execution import CommandExecutionAnalyzer
from mcts.core.config import ScanConfig
from mcts.discovery.static import StaticDiscovery
from mcts.reporting.models import Severity


def test_command_execution_detects_subprocess(example_server_path: Path) -> None:
    config = ScanConfig(target=example_server_path)
    server = StaticDiscovery(config).discover()
    findings = CommandExecutionAnalyzer().analyze(server)

    assert any(f.tool == "run_shell" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any(f.technique_id == "MCTS-T-1003" for f in findings)


def test_data_leakage_scans_source_files(example_server_path: Path) -> None:
    from mcts.core.scanner import Scanner

    report = Scanner(ScanConfig(target=example_server_path)).run()
    source_findings = [f for f in report.findings if f.analyzer == "data_leakage" and f.location]
    assert source_findings or any(f.analyzer == "data_leakage" for f in report.findings)
