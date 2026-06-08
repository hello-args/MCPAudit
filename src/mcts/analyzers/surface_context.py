"""Shared helpers for multi-surface analyzer findings."""

from __future__ import annotations

from mcts.analyzers.surfaces import (
    DEFAULT_SURFACES,
    ScanSurface,
    ScanSurfaceKind,
    iter_surfaces,
    parse_surfaces,
)
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import SourceLocation


def surface_location(surface: ScanSurface) -> SourceLocation:
    return SourceLocation(file=surface.source_file or "", line=surface.source_line)


def tool_name_for(surface: ScanSurface) -> str | None:
    return surface.name if surface.kind == ScanSurfaceKind.TOOL else None


def surface_text_fields(surface: ScanSurface) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = [
        ("name", surface.name),
        ("description", surface.description),
    ]
    if surface.extra_text:
        rows.append(("extra", surface.extra_text))
    if surface.uri:
        rows.append(("uri", surface.uri))
    return [(field, text) for field, text in rows if text]


def tool_for_surface(server: MCPServerInfo, surface: ScanSurface) -> MCPTool | None:
    if surface.kind != ScanSurfaceKind.TOOL:
        return None
    for tool in server.tools:
        if tool.name == surface.name:
            return tool
    return None


def scan_surfaces(
    server: MCPServerInfo,
    surfaces: frozenset[ScanSurfaceKind] | None = None,
) -> list[ScanSurface]:
    """Iterate scannable surfaces using per-scan options on server info."""
    opts = server.surface_scan
    active = surfaces
    if active is None:
        active = parse_surfaces(opts.surfaces) if opts and opts.surfaces else DEFAULT_SURFACES
    mime = frozenset(opts.resource_mime_allowlist) if opts and opts.resource_mime_allowlist else None
    return iter_surfaces(server, surfaces=active, mime_allowlist=mime)
