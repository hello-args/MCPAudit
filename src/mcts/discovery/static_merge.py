"""Merge static discovery results from multiple language backends."""

from __future__ import annotations

from mcts.mcp.models import MCPServerInfo, MCPTool


def merge_static_server_info(*infos: MCPServerInfo) -> MCPServerInfo:
    """Combine tools and source files from Python, TypeScript, and other static scans."""
    if not infos:
        return MCPServerInfo(name="unknown", discovery_mode="empty")
    if len(infos) == 1:
        return infos[0]

    tools_by_name: dict[str, MCPTool] = {}
    source_files: dict[str, str] = {}
    name = infos[0].name

    for info in infos:
        source_files.update(info.source_files)
        for tool in info.tools:
            existing = tools_by_name.get(tool.name)
            if existing is None or _richness(tool) > _richness(existing):
                tools_by_name[tool.name] = tool

    return MCPServerInfo(
        name=name,
        tools=list(tools_by_name.values()),
        prompts=infos[-1].prompts,
        resources=infos[-1].resources,
        instructions=infos[-1].instructions,
        transport="stdio",
        discovery_mode="static",
        source_files=source_files,
    )


def _richness(tool: MCPTool) -> int:
    return len(tool.input_schema.get("properties", {})) + (2 if tool.description else 0)
