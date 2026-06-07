"""MCTS-T-1039 — context memory implants in MCP vector stores."""

from __future__ import annotations

from typing import Any

from mcts.analyzers.tpa_patterns import has_hidden_unicode

_WRITE_OPS = frozenset({"write", "insert", "update", "upsert"})
_UNTRUSTED_SOURCES = ("untrusted", "external", "unknown", "malicious", "suspicious")
_PERSISTENCE_MARKERS = (
    "session_persistence",
    "retention: permanent",
    "expires: never",
    "always_retrieve",
    "auto_reload",
)
_MALICIOUS_MARKERS = (
    "system:",
    "ignore",
    "override",
    "execute",
    "privilege",
    "bypass",
    "disregard",
    "forget",
    "previous instructions",
)


def detect_context_memory_implant(event: dict[str, Any]) -> bool:
    """Detect suspicious vector-store writes indicating persistent memory implants."""
    operation = str(event.get("operation_type") or event.get("operation") or "").lower()
    if operation and operation not in _WRITE_OPS:
        return False

    source = str(event.get("source") or "").lower()
    metadata = str(event.get("metadata") or "").lower()
    content = str(event.get("content") or "").lower()
    embedding = str(event.get("embedding_metadata") or "").lower()
    text = " ".join(part for part in (metadata, content, embedding) if part)

    untrusted = any(marker in source for marker in _UNTRUSTED_SOURCES)
    persistence = any(marker in metadata for marker in _PERSISTENCE_MARKERS)
    malicious = any(marker in text for marker in _MALICIOUS_MARKERS) or has_hidden_unicode(text)
    vector_anomaly = str(event.get("vector_priority") or "").lower() in {
        "999",
        "1000",
        "max",
        "critical",
        "urgent",
    }
    cross_session = str(event.get("session_scope") or "").lower() in {
        "global",
        "all_users",
        "all_sessions",
        "persistent",
        "shared",
    }

    if untrusted and persistence and malicious:
        return True
    if persistence and malicious:
        return True
    if untrusted and malicious and operation in _WRITE_OPS:
        return True
    return operation in _WRITE_OPS and vector_anomaly and cross_session
