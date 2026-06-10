"""Tests for scripts/run_behavioral_regression.py exit codes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(*extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/run_behavioral_regression.py", *extra],
        capture_output=True,
        text=True,
        check=False,
        cwd=_REPO_ROOT,
    )


def test_behavioral_regression_default_exits_zero() -> None:
    result = _run()
    assert result.returncode == 0
    assert "Total findings:" in result.stdout


def test_behavioral_regression_json_reports_vulnerable_findings() -> None:
    result = _run("--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["vulnerable_findings"] >= 1


def test_behavioral_regression_strict_exits_one_on_missing_example(tmp_path: Path) -> None:
    missing = tmp_path / "missing.py"
    result = _run("--examples", str(missing), "--strict")
    assert result.returncode == 1
    assert "missing example" in result.stderr


def test_behavioral_regression_min_findings_exits_one_when_unmet() -> None:
    result = _run("--min-findings", "9999")
    assert result.returncode == 1


def test_behavioral_regression_min_findings_passes_when_met() -> None:
    result = _run("--min-findings", "1")
    assert result.returncode == 0
