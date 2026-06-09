"""Integration tests for the scanner."""

import json
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.reporting.models import Severity


def test_config_static_scan_includes_disclaimer(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"demo": {"command": "python", "args": ["-m", "x"]}}}))
    (tmp_path / "app.py").write_text("x = 1\n")
    report = Scanner(ScanConfig(target=tmp_path, config_path=config, config_server="demo")).run()
    assert report.scan_scope == "config-static"
    assert report.server.discovery_mode == "config-static"
    assert report.scan_notes
    assert "Config-static scan" in report.scan_notes[0]
    assert "demo" in report.scan_notes[0]


def test_static_repo_zero_tools_notice(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hello')\n")
    report = Scanner(ScanConfig(target=tmp_path)).run()
    assert not report.server.tools
    assert report.tool_discovery_notice
    assert "tools/list" in report.tool_discovery_notice.lower()


def test_scan_finds_critical_issues(example_server_path: Path) -> None:
    config = ScanConfig(target=example_server_path)
    report = Scanner(config).run()

    assert report.summary.total > 0
    assert report.summary.critical >= 1
    assert report.score.overall < 100
    assert any(f.severity == Severity.CRITICAL for f in report.findings)
