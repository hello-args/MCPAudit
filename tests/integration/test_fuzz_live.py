"""Integration tests for live MCP fuzzing."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
LIVE_SERVER = REPO / "examples" / "live-mcp-server" / "server.py"


@pytest.mark.integration
def test_fuzz_live_safe_completes() -> None:
    if not LIVE_SERVER.exists():
        pytest.skip("live example server missing")
    env = {**os.environ, "MCTS_LIVE_OK": "1", "MCTS_NO_VENV_WARN": "1"}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcts.cli.main",
            "fuzz",
            str(LIVE_SERVER),
            "--i-understand-live-risk",
        ],
        env=env,
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    assert result.returncode in (0, 1), result.stderr + result.stdout


@pytest.mark.integration
def test_fuzz_exits_2_on_startup_failure(tmp_path: Path) -> None:
    bad = tmp_path / "bad_server.py"
    bad.write_text(
        "import sys\nprint('ModuleNotFoundError: No module named \\'ifd\\'', file=sys.stderr)\nsys.exit(1)\n"
    )
    env = {**os.environ, "MCTS_LIVE_OK": "1", "MCTS_NO_VENV_WARN": "1"}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcts.cli.main",
            "fuzz",
            str(bad),
            "--i-understand-live-risk",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    combined = result.stdout + result.stderr
    assert "FAILED TO START" in combined or "Import Error" in combined
