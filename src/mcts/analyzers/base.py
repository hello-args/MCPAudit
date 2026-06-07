"""Base analyzer interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding


class BaseAnalyzer(ABC):
    """Interface implemented by all MCTS security analyzers."""

    name: str = "base"

    @abstractmethod
    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        """Run analysis and return findings."""
