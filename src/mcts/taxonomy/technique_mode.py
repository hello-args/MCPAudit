"""Per-technique scan mode helpers."""

from __future__ import annotations

from mcts.taxonomy.mapper import load_taxonomy


def analyzers_for_technique(technique_id: str) -> list[str]:
    data = load_taxonomy()
    row = data.get("techniques", {}).get(technique_id)
    if not isinstance(row, dict):
        return []
    analyzers = row.get("analyzers") or []
    return [str(name) for name in analyzers]


def resolve_technique_scan(technique_id: str) -> tuple[list[str], str | None]:
    """Return analyzer allowlist and normalized technique id."""
    normalized = technique_id.strip().upper()
    if not normalized.startswith("MCTS-T-"):
        normalized = f"MCTS-T-{normalized.removeprefix('T-')}"
    return analyzers_for_technique(normalized), normalized
