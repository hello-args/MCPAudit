"""Tests for live MCP stdio probing."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from mcts.core.config import ScanConfig
from mcts.discovery.config import load_server_from_config
from mcts.discovery.live_config import resolve_live_config
from mcts.discovery.merge import merge_server_info
from mcts.mcp.client import MCPClient
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.probe.consent import LiveProbeConsentError, require_live_consent
from mcts.probe.models import LiveServerConfig
from mcts.probe.session import probe_stdio

LIVE_SERVER = Path(__file__).parent.parent / "examples" / "live-mcp-server" / "server.py"


def test_live_consent_required() -> None:
    with pytest.raises(LiveProbeConsentError):
        require_live_consent(flag=False)


def test_load_server_from_config(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "demo": {"command": "uv", "args": ["run", "server.py"], "env": {"FOO": "bar"}},
                }
            }
        )
    )
    live = load_server_from_config(config, "demo")
    assert live.command == "uv"
    assert live.args == ["run", "server.py"]
    assert live.env["FOO"] == "bar"


def test_resolve_live_config_from_python_target() -> None:
    config = ScanConfig(target=LIVE_SERVER, live=True, live_consent=True)
    live = resolve_live_config(config)
    assert live.command == sys.executable
    assert live.args == [str(LIVE_SERVER.resolve())]


def test_merge_enriches_schema_from_live() -> None:
    static = MCPServerInfo(
        tools=[
            MCPTool(
                name="greet",
                description="Static desc",
                input_schema={},
                source_file="server.py",
                handler_snippet="def greet(): ...",
            )
        ],
        discovery_mode="static",
    )
    live = MCPServerInfo(
        tools=[
            MCPTool(
                name="greet",
                description="Live desc",
                input_schema={"type": "object", "properties": {"name": {"type": "string"}}},
                discovered_via="live",
            )
        ],
        discovery_mode="live",
    )
    merged = merge_server_info(static, live)
    tool = merged.tools[0]
    assert tool.discovered_via == "merged"
    assert tool.input_schema["properties"]["name"]["type"] == "string"
    assert tool.handler_snippet is not None
    assert merged.discovery_mode == "merged"


@pytest.mark.asyncio
async def test_probe_stdio_maps_tools() -> None:
    fake_tool = SimpleNamespace(
        name="greet",
        description="Hello",
        inputSchema={"type": "object", "properties": {"name": {"type": "string"}}},
    )
    fake_tools = SimpleNamespace(tools=[fake_tool])
    fake_init = SimpleNamespace(instructions="Be helpful.", serverInfo=SimpleNamespace(version="1.2.3"))

    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock(return_value=fake_init)
    mock_session.list_tools = AsyncMock(return_value=fake_tools)
    mock_session.list_prompts = AsyncMock(return_value=SimpleNamespace(prompts=[]))
    mock_session.list_resources = AsyncMock(return_value=SimpleNamespace(resources=[]))

    class FakeClientSession:
        def __init__(self, read, write):
            pass

        async def __aenter__(self):
            return mock_session

        async def __aexit__(self, *args):
            return None

    class FakeStdioClient:
        def __init__(self, params):
            self.params = params

        async def __aenter__(self):
            return (None, None)

        async def __aexit__(self, *args):
            return None

    fake_stdio_module = SimpleNamespace(stdio_client=FakeStdioClient)
    fake_mcp_module = SimpleNamespace(
        ClientSession=FakeClientSession,
        StdioServerParameters=lambda **kwargs: SimpleNamespace(**kwargs),
    )

    import builtins

    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "mcp.client.stdio":
            return fake_stdio_module
        if name == "mcp":
            return fake_mcp_module
        return original_import(name, globals, locals, fromlist, level)

    with patch.object(builtins, "__import__", side_effect=fake_import):
        info = await probe_stdio(LiveServerConfig(command="python", args=["server.py"]))

    assert info.tools[0].name == "greet"
    assert info.instructions == "Be helpful."
    assert info.discovery_mode == "live"


def test_mcp_client_live_only_config_mode(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"demo": {"command": "echo", "args": ["hi"]}}}))
    scan_config = ScanConfig(
        target=Path("."),
        live=True,
        live_consent=True,
        config_path=config,
        config_server="demo",
        merge_static_live=False,
    )
    fake_live = MCPServerInfo(name="demo", tools=[MCPTool(name="t")], discovery_mode="live")

    with patch("mcts.discovery.live.LiveDiscovery.discover", return_value=fake_live):
        info = MCPClient(Path("."), scan_config).discover()

    assert info.discovery_mode == "live"
    assert info.tools[0].name == "t"


@pytest.mark.integration
@pytest.mark.skipif(
    not LIVE_SERVER.exists(),
    reason="live example server missing",
)
def test_live_probe_example_server() -> None:
    pytest.importorskip("mcp")
    config = ScanConfig(target=LIVE_SERVER, live=True, live_consent=True, merge_static_live=True)
    report_tools = MCPClient(LIVE_SERVER, config).discover().tools
    names = {tool.name for tool in report_tools}
    assert "greet" in names
    assert "send_webhook" in names
