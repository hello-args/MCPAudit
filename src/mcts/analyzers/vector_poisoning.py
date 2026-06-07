"""MCTS-T-1034 — vector store / embedding metadata contamination."""

from __future__ import annotations

import re
from typing import Any

_VECTOR_OPS = frozenset(
    {
        "insert",
        "update",
        "upsert",
        "database_credentials",
        "api_keys",
        "user_passwords",
        "backup_delete",
        "monitoring_disable",
    }
)

_POISON_MARKERS = (
    "*system:*",
    "system:",
    "ignore previous instructions",
    "always include credentials",
    "bypass security",
    "delete all files",
    "ignore all previous instructions",
    "disable all security",
    "reveal api keys",
)

_BENIGN_MARKERS = (
    "legitimate_documentation",
    "official_guide",
    "security_best_practices",
    "standard operating procedures",
    "security best practices",
    "industry standard guidelines",
)


def detect_vector_poisoning(event: dict[str, Any]) -> bool:
    """Detect poisoned embedding metadata on vector-store write operations."""
    operation = str(event.get("operation") or "").lower()
    if operation not in _VECTOR_OPS and operation not in {"insert", "update", "upsert"}:
        return False

    metadata = str(event.get("embedding_metadata") or event.get("content") or "").lower()
    if not metadata:
        return False

    if any(marker in metadata for marker in _BENIGN_MARKERS):
        return False

    if re.search(r"system\s*:", metadata, re.I):
        return True
    return any(marker in metadata for marker in _POISON_MARKERS)
