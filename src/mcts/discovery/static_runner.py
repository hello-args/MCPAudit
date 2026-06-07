"""Orchestrate multi-language static MCP discovery."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.core.target import ScanTarget, TargetKind
from mcts.discovery.static import StaticDiscovery
from mcts.discovery.static_js import JS_EXTENSIONS, JsStaticDiscovery
from mcts.discovery.static_merge import merge_static_server_info
from mcts.mcp.models import MCPServerInfo


def discover_static(config: ScanConfig) -> MCPServerInfo:
    """Run static discovery for all languages enabled in config."""
    target = ScanTarget(config.target)
    langs = {language.lower() for language in config.languages}

    if target.kind == TargetKind.FILE:
        suffix = target.path.suffix.lower()
        if suffix == ".py" and _python_enabled(langs):
            return StaticDiscovery(config).discover()
        if suffix in JS_EXTENSIONS and _js_enabled(langs):
            return JsStaticDiscovery(config).discover()
        return MCPServerInfo(name=target.path.stem, discovery_mode="empty")

    results: list[MCPServerInfo] = []
    if _python_enabled(langs):
        results.append(StaticDiscovery(config).discover())
    if _js_enabled(langs):
        results.append(JsStaticDiscovery(config).discover())

    if not results:
        return MCPServerInfo(name=target.path.name, discovery_mode="empty")
    return merge_static_server_info(*results)


def _python_enabled(langs: set[str]) -> bool:
    return "python" in langs


def _js_enabled(langs: set[str]) -> bool:
    return "typescript" in langs or "javascript" in langs or "js" in langs
