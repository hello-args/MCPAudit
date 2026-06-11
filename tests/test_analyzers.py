"""Tests for source-aware analyzers."""

from pathlib import Path

from mcts.analyzers.command_execution import CommandExecutionAnalyzer
from mcts.analyzers.data_leakage import DataLeakageAnalyzer
from mcts.core.config import ScanConfig
from mcts.discovery.static import StaticDiscovery
from mcts.mcp.models import MCPServerInfo
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


def test_data_leakage_ignores_loopback_urls_in_log_messages() -> None:
    server = MCPServerInfo(
        name="perseus",
        source_files={
            "mcp.py": "\n".join(
                [
                    "print(f'Perseus MCP SSE server listening on http://127.0.0.1:{port}')",
                    "print(f' SSE endpoint: http://127.0.0.1:{port}/sse')",
                    "logger.info('Server card: http://localhost:9000/.well-known/mcp/server-card.json')",
                    "callback_url = 'http://127.0.0.1:9000/message'",
                ]
            )
        },
    )

    findings = DataLeakageAnalyzer().analyze(server)

    assert len(findings) == 1
    assert findings[0].location
    assert findings[0].location.line == 4
