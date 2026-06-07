"""Tests for TypeScript/JavaScript static discovery."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.discovery.static_js import JsStaticDiscovery
from mcts.discovery.static_runner import discover_static
from mcts.mcp.client import MCPClient

BENCH_TS_REPO = Path(__file__).parent.parent / "examples" / "bench" / "multi-file-ts-server"
SERVER_TS = BENCH_TS_REPO / "server.ts"
LEGACY_TS = BENCH_TS_REPO / "handlers" / "legacy.ts"
EXTRA_TS = BENCH_TS_REPO / "handlers" / "extra.ts"


def test_js_static_discovery_finds_register_tool() -> None:
    config = ScanConfig(target=BENCH_TS_REPO)
    info = JsStaticDiscovery(config).discover()

    tool_names = {tool.name for tool in info.tools}
    assert "read_config" in tool_names
    assert "notify_webhook" in tool_names
    assert len(info.source_files) >= 2


def test_js_tools_have_schema_and_capabilities() -> None:
    config = ScanConfig(target=BENCH_TS_REPO)
    info = JsStaticDiscovery(config).discover()

    read_tool = next(t for t in info.tools if t.name == "read_config")
    assert read_tool.input_schema.get("properties", {}).get("path") == {"type": "string"}
    assert read_tool.capability is not None
    assert read_tool.capability.reads_untrusted_input is True


def test_js_list_tools_handler_pattern() -> None:
    config = ScanConfig(target=LEGACY_TS)
    info = JsStaticDiscovery(config).discover()

    tool_names = {tool.name for tool in info.tools}
    assert "list_env" in tool_names


def test_js_tool_method_pattern() -> None:
    config = ScanConfig(target=EXTRA_TS)
    info = JsStaticDiscovery(config).discover()

    assert any(tool.name == "echo_message" for tool in info.tools)


def test_discover_static_merges_python_and_typescript(tmp_path: Path) -> None:
    py_dir = tmp_path / "mixed"
    handlers = py_dir / "handlers"
    handlers.mkdir(parents=True)
    (handlers / "alpha.py").write_text(
        '@mcp.tool()\ndef alpha_tool(x: str) -> str:\n    """Alpha."""\n    return x\n',
        encoding="utf-8",
    )
    ts_source = (
        'server.registerTool("beta_tool", '
        '{ description: "Beta", inputSchema: { q: z.string() } }, '
        "async () => ({}));\n"
    )
    (py_dir / "server.ts").write_text(ts_source, encoding="utf-8")

    info = discover_static(ScanConfig(target=py_dir))
    names = {tool.name for tool in info.tools}
    assert "alpha_tool" in names
    assert "beta_tool" in names
    assert len(info.source_files) == 2


def test_scan_ts_repo_directory() -> None:
    report = Scanner(ScanConfig(target=BENCH_TS_REPO)).run()
    names = {tool.name for tool in report.server.tools}
    assert "read_config" in names
    assert "notify_webhook" in names
    assert "list_env" in names


def test_mcp_client_discovers_single_ts_file() -> None:
    info = MCPClient(SERVER_TS).discover()
    assert any(tool.name == "read_config" for tool in info.tools)


def test_python_only_config_skips_typescript() -> None:
    info = discover_static(ScanConfig(target=BENCH_TS_REPO, languages=["python"]))
    assert info.tools == []
    assert info.source_files == {}
