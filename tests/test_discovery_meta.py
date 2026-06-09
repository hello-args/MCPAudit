"""Tests for live discovery meta-findings."""

from __future__ import annotations

from mcts.mcp.models import MCPServerInfo
from mcts.probe.discovery_meta import discovery_meta_findings


def test_never_started_message() -> None:
    server = MCPServerInfo(
        name="live",
        discovery_mode="live",
        initialize_succeeded=False,
        discovery_warnings=["process exited before initialize"],
    )
    findings = discovery_meta_findings(server)
    assert findings
    assert "never completed the initialize handshake" in findings[0].description


def test_list_tools_failed_message() -> None:
    server = MCPServerInfo(
        name="live",
        discovery_mode="live",
        initialize_succeeded=True,
        discovery_warnings=["list_tools failed: timeout"],
    )
    findings = discovery_meta_findings(server)
    assert findings
    assert "list_tools failed" in findings[0].description
