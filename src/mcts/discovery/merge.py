"""Merge static and live MCP discovery results."""

from __future__ import annotations

from mcts.capability.inferrer import infer_capability
from mcts.mcp.models import MCPPrompt, MCPResource, MCPServerInfo, MCPTool


def merge_server_info(static: MCPServerInfo, live: MCPServerInfo) -> MCPServerInfo:
    """Combine static source context with live-enriched schemas and surfaces."""
    tools_by_name: dict[str, MCPTool] = {tool.name: tool.model_copy(deep=True) for tool in static.tools}

    for live_tool in live.tools:
        if live_tool.name in tools_by_name:
            tools_by_name[live_tool.name] = _merge_tool(tools_by_name[live_tool.name], live_tool)
        else:
            clone = live_tool.model_copy(deep=True)
            clone.discovered_via = "live"
            tools_by_name[live_tool.name] = clone

    prompts = _merge_prompts(static.prompts, live.prompts)
    resources = _merge_resources(static.resources, live.resources)

    return MCPServerInfo(
        name=live.name or static.name,
        version=live.version or static.version,
        tools=list(tools_by_name.values()),
        prompts=prompts,
        resources=resources,
        instructions=live.instructions or static.instructions,
        transport="stdio-merged",
        discovery_mode="merged",
        source_files=dict(static.source_files),
    )


def _merge_tool(static_tool: MCPTool, live_tool: MCPTool) -> MCPTool:
    merged_schema = live_tool.input_schema or static_tool.input_schema
    description = live_tool.description or static_tool.description
    tool = static_tool.model_copy(deep=True)
    tool.description = description
    tool.input_schema = merged_schema
    tool.discovered_via = "merged"
    tool.capability = infer_capability(tool)
    return tool


def _merge_prompts(static: list[MCPPrompt], live: list[MCPPrompt]) -> list[MCPPrompt]:
    by_name = {prompt.name: prompt for prompt in static}
    for prompt in live:
        by_name[prompt.name] = prompt
    return list(by_name.values())


def _merge_resources(static: list[MCPResource], live: list[MCPResource]) -> list[MCPResource]:
    by_uri = {resource.uri: resource for resource in static}
    for resource in live:
        by_uri[resource.uri] = resource
    return list(by_uri.values())
