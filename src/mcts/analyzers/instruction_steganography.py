"""MCTS-T-1041 — hidden instructions in MCP tool metadata (Unicode / HTML steganography)."""

from __future__ import annotations

from typing import Any

from mcts.analyzers.tpa_patterns import has_hidden_unicode, scan_text_templates


def _description_text(event: dict[str, Any]) -> str:
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        desc = metadata.get("description")
        if isinstance(desc, str):
            return desc
    for key in ("description", "tool_description"):
        value = event.get(key)
        if isinstance(value, str):
            return value
    return ""


def detect_instruction_steganography(event: dict[str, Any]) -> bool:
    """Return True when tool metadata hides instructions via ZWSP/HTML/bidi controls."""
    text = _description_text(event)
    if not text:
        return False
    if has_hidden_unicode(text):
        return True
    if scan_text_templates(text):
        return True
    return "<!--" in text
