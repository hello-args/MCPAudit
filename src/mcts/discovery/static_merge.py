"""Merge static discovery results from multiple language backends."""

from __future__ import annotations

from mcts.mcp.models import AgentSkillFile, MCPPrompt, MCPServerInfo, MCPTool


def merge_static_server_info(*infos: MCPServerInfo) -> MCPServerInfo:
    """Combine tools, prompts, skills, and source files from static scans."""
    if not infos:
        return MCPServerInfo(name="unknown", discovery_mode="empty")
    if len(infos) == 1:
        return infos[0]

    tools_by_name: dict[str, MCPTool] = {}
    prompts_by_key: dict[tuple[str, str | None], MCPPrompt] = {}
    skills_by_path: dict[str, AgentSkillFile] = {}
    source_files: dict[str, str] = {}
    instruction_blocks: list[tuple[str, str]] = []
    instruction_sources: list[str] = []
    discovery_mode = "static"
    name = infos[0].name

    for info in infos:
        source_files.update(info.source_files)
        if info.discovery_mode == "instruction-files":
            discovery_mode = "static+instruction-files"
        for tool in info.tools:
            existing = tools_by_name.get(tool.name)
            if existing is None or _richness(tool) > _richness(existing):
                tools_by_name[tool.name] = tool
        for prompt in info.prompts:
            key = (prompt.name, prompt.source_file)
            prompts_by_key[key] = prompt
        for skill in info.agent_skills:
            skills_by_path[skill.path] = skill
        for src in info.instruction_sources:
            if src not in instruction_sources:
                instruction_sources.append(src)
        if info.instructions:
            primary = info.instruction_sources[0] if info.instruction_sources else "instructions"
            instruction_blocks.append((primary, info.instructions))

    instructions: str | None = None
    if instruction_blocks:
        instructions = "\n\n---\n\n".join(text for _, text in instruction_blocks)

    return MCPServerInfo(
        name=name,
        tools=list(tools_by_name.values()),
        prompts=list(prompts_by_key.values()),
        instructions=instructions,
        instruction_sources=instruction_sources,
        agent_skills=list(skills_by_path.values()),
        transport="stdio",
        discovery_mode=discovery_mode,
        source_files=source_files,
    )


def _richness(tool: MCPTool) -> int:
    return len(tool.input_schema.get("properties", {})) + (2 if tool.description else 0)
