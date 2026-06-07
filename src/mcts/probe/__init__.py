"""MCP live probing."""

from mcts.probe.consent import require_live_consent
from mcts.probe.models import LiveServerConfig

__all__ = ["LiveServerConfig", "require_live_consent"]
