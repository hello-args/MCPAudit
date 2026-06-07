"""MCP server models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CapabilityProfile(BaseModel):
    reads_untrusted_input: bool = False
    accesses_sensitive_data: bool = False
    mutates_state: bool = False
    egresses_network: bool = False
    executes_commands: bool = False


class MCPTool(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    source_file: str | None = None
    source_line: int | None = None
    handler_snippet: str | None = None
    capability: CapabilityProfile | None = None
    discovered_via: str = "static"


class MCPPrompt(BaseModel):
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = Field(default_factory=list)


class MCPResource(BaseModel):
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str | None = None


class MCPServerInfo(BaseModel):
    name: str = "unknown"
    version: str = "0.0.0"
    tools: list[MCPTool] = Field(default_factory=list)
    prompts: list[MCPPrompt] = Field(default_factory=list)
    resources: list[MCPResource] = Field(default_factory=list)
    instructions: str | None = None
    transport: str = "stdio"
    discovery_mode: str = "static"
    source_files: dict[str, str] = Field(default_factory=dict)
    runtime_events: list[dict[str, Any]] = Field(default_factory=list)
