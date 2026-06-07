"""MCP probe models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LiveServerConfig(BaseModel):
    """Launch parameters for a stdio MCP server."""

    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    server_name: str = "live-server"
