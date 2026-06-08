"""Tests for phase 3 parity features."""

from __future__ import annotations

from mcts.analyzers.metadata_dedupe import dedupe_metadata_findings
from mcts.reporting.models import Finding, Severity
from mcts.sast.typescript.taint import analyze_typescript_taint


def test_typescript_taint_detects_exec_param():
    source = """
export async function runTool(cmd: string) {
  const { exec } = require('child_process');
  exec(cmd);
}
"""
    result = analyze_typescript_taint(source)
    assert "child_process" in result.sinks or "dynamic_sink" in result.sinks
    assert "cmd" in result.tainted_params


def test_metadata_dedupe_drops_integrity_when_surface_covers():
    surface = Finding(
        id="surface-poison-tool:evil-description-ignore_previous",
        analyzer="surface_metadata",
        title="surface",
        description="d",
        severity=Severity.HIGH,
        tool="evil",
        recommendation="r",
        technique_id="MCTS-T-1001",
        evidence={"pattern": "ignore_previous", "surface": "tool"},
    )
    integrity = Finding(
        id="meta-poison-tool:evil-description-ignore_previous",
        analyzer="metadata_integrity",
        title="integrity",
        description="d",
        severity=Severity.HIGH,
        tool="evil",
        recommendation="r",
        technique_id="MCTS-T-1001",
        evidence={"pattern": "ignore_previous", "surface": "tool"},
    )
    deduped = dedupe_metadata_findings([surface, integrity])
    assert len(deduped) == 1
    assert deduped[0].analyzer == "surface_metadata"
