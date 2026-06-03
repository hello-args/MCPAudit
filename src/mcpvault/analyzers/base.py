"""Base analyzer interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcpvault.mcp.models import MCPServerInfo
from mcpvault.reporting.models import Finding


class BaseAnalyzer(ABC):
    """Interface implemented by all MCPVault security analyzers."""

    name: str = "base"

    @abstractmethod
    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        """Run analysis and return findings."""
