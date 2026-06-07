"""Inventory data models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class InventoryEntry(BaseModel):
    client: str
    config_path: str
    server_name: str
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env_keys: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)


class InventoryReport(BaseModel):
    entries: list[InventoryEntry] = Field(default_factory=list)
    clients_scanned: list[str] = Field(default_factory=list)
    config_files_found: int = 0
