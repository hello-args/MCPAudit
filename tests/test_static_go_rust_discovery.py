"""Tests for Go and Rust static MCP discovery."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.discovery.static_go import GoStaticDiscovery
from mcts.discovery.static_runner import discover_static
from mcts.discovery.static_rust import RustStaticDiscovery

ROOT = Path(__file__).resolve().parents[1]
GO_BENCH = ROOT / "examples" / "bench" / "go-mcp-server"
RUST_BENCH = ROOT / "examples" / "bench" / "rust-mcp-server"
RUST_RMCP_BENCH = ROOT / "examples" / "bench" / "rust-mcp-rmcp"


def test_go_static_discovery_finds_registered_tools() -> None:
    config = ScanConfig(target=GO_BENCH, languages=["go"])
    info = GoStaticDiscovery(config).discover()
    names = {tool.name for tool in info.tools}
    assert "run_shell" in names
    assert "list_files" in names


def test_rust_static_discovery_finds_registered_tools() -> None:
    config = ScanConfig(target=RUST_BENCH, languages=["rust"])
    info = RustStaticDiscovery(config).discover()
    names = {tool.name for tool in info.tools}
    assert "run_command" in names


def test_discover_static_runner_includes_go_and_rust() -> None:
    config = ScanConfig(target=ROOT / "examples" / "bench", languages=["go", "rust"])
    info = discover_static(config)
    names = {tool.name for tool in info.tools}
    assert "run_shell" in names
    assert "run_command" in names


def test_rust_macro_discovery_finds_rmcp_tools() -> None:
    config = ScanConfig(target=RUST_RMCP_BENCH, languages=["rust"])
    info = RustStaticDiscovery(config).discover()
    names = {tool.name for tool in info.tools}
    assert "run_shell" in names
    assert "list_files" in names


def test_default_language_detect_includes_rust_for_rmcp_repo() -> None:
    from mcts.discovery.language_detect import resolve_default_languages

    langs = resolve_default_languages(RUST_RMCP_BENCH)
    assert "rust" in langs
