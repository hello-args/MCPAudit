"""Tests for per-technique scan mode."""

from __future__ import annotations

from mcts.taxonomy.technique_mode import resolve_technique_scan


def test_resolve_technique_scan_normalizes_id() -> None:
    analyzers, technique_id = resolve_technique_scan("1003")
    assert technique_id == "MCTS-T-1003"
    assert "command_execution" in analyzers
