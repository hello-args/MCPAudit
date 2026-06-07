"""Inventory runner."""

from __future__ import annotations

from pathlib import Path

from mcts.inventory.discoverers import discover_config_paths, parse_config_file
from mcts.inventory.models import InventoryEntry, InventoryReport


def run_inventory() -> InventoryReport:
    entries: list[InventoryEntry] = []
    clients: set[str] = set()
    files_found = 0

    for client, path in discover_config_paths():
        files_found += 1
        clients.add(client)
        entries.extend(parse_config_file(client, path))

    return InventoryReport(
        entries=entries,
        clients_scanned=sorted(clients),
        config_files_found=files_found,
    )


def enrich_with_tool_names(entries: list[InventoryEntry]) -> list[InventoryEntry]:
    """Optionally static-scan each server command target to list tool names."""
    from mcts.core.config import ScanConfig
    from mcts.core.scanner import Scanner

    enriched: list[InventoryEntry] = []
    for entry in entries:
        updated = entry.model_copy()
        target = _resolve_target(entry)
        if target and target.exists():
            report = Scanner(ScanConfig(target=target)).run()
            updated.tools = [tool.name for tool in report.server.tools]
        enriched.append(updated)
    return enriched


def _resolve_target(entry: InventoryEntry) -> Path | None:
    if not entry.args:
        return None
    for arg in entry.args:
        candidate = Path(arg).expanduser()
        if candidate.suffix == ".py" and candidate.exists():
            return candidate
    for arg in entry.args:
        candidate = Path(arg).expanduser()
        if candidate.exists():
            return candidate
    return None
