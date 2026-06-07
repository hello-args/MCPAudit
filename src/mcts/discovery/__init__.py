"""MCP discovery modules."""

from mcts.discovery.static import StaticDiscovery
from mcts.discovery.static_js import JsStaticDiscovery
from mcts.discovery.static_runner import discover_static

__all__ = ["StaticDiscovery", "JsStaticDiscovery", "discover_static"]
