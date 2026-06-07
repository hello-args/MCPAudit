"""Live MCP discovery via stdio probe."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.discovery.live_config import resolve_live_config
from mcts.mcp.models import MCPServerInfo
from mcts.probe.consent import require_live_consent
from mcts.probe.session import probe_stdio_sync


class LiveDiscovery:
    """Discover MCP capabilities by connecting to a running stdio server."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def discover(self) -> MCPServerInfo:
        require_live_consent(flag=self.config.live_consent)
        live_config = resolve_live_config(self.config)
        return probe_stdio_sync(live_config, timeout_seconds=self.config.timeout_seconds)
