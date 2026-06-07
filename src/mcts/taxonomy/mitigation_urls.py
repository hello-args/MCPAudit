"""MCTS taxonomy URL helpers."""

from __future__ import annotations

MCTS_REPO = "https://github.com/MCP-Audit/MCTS"
MCTS_DOCS = f"{MCTS_REPO}/blob/main/docs/taxonomy.md"


def mitigation_url(mitigation_id: str) -> str:
    return f"{MCTS_DOCS}#{mitigation_id.lower()}"


def technique_url(technique_id: str) -> str:
    return f"{MCTS_DOCS}#{technique_id.lower()}"


def mitigation_links(mitigation_ids: list[str]) -> list[dict[str, str]]:
    return [{"id": mid, "url": mitigation_url(mid)} for mid in mitigation_ids]
