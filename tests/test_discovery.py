"""Tests for repository-wide static discovery."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.discovery.static import StaticDiscovery

BENCH_REPO = Path(__file__).parent.parent / "examples" / "bench" / "multi-file-server"


def test_static_discovery_finds_tools_in_repo() -> None:
    config = ScanConfig(target=BENCH_REPO)
    info = StaticDiscovery(config).discover()

    tool_names = {tool.name for tool in info.tools}
    assert "read_config" in tool_names
    assert "notify_webhook" in tool_names
    assert len(info.source_files) >= 1


def test_tools_have_input_schema_and_capabilities() -> None:
    config = ScanConfig(target=BENCH_REPO)
    info = StaticDiscovery(config).discover()

    read_tool = next(t for t in info.tools if t.name == "read_config")
    assert read_tool.input_schema.get("properties", {}).get("path") is not None
    assert read_tool.capability is not None
    assert read_tool.capability.reads_untrusted_input is True


def test_scan_repo_directory() -> None:
    report = Scanner(ScanConfig(target=BENCH_REPO)).run()
    assert len(report.server.tools) >= 2
    assert report.attack_graph.get("edges")
