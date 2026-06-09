"""Integration tests for live MCP scanning."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

LIVE_SERVER = Path(__file__).resolve().parents[2] / "examples" / "live-mcp-server" / "server.py"


@pytest.mark.integration
def test_live_scan_discovers_tools(tmp_path: Path) -> None:
    if not LIVE_SERVER.exists():
        pytest.skip("live example server missing")
    out = tmp_path / "live-report.json"
    env = {**os.environ, "MCTS_LIVE_OK": "1", "MCTS_NO_VENV_WARN": "1"}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcts.cli.main",
            "scan",
            str(LIVE_SERVER),
            "--live",
            "--no-progress",
            "-o",
            str(out),
        ],
        env=env,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(out.read_text())
    assert len(data["server"]["tools"]) > 0


@pytest.mark.integration
def test_live_credentials_error_message(tmp_path: Path) -> None:
    bad = tmp_path / "sso_server.py"
    bad.write_text(
        "import sys\n"
        "print('ERROR: Could not load credentials from SSO profile', file=sys.stderr)\n"
        "sys.exit(1)\n"
    )
    env = {**os.environ, "MCTS_LIVE_OK": "1", "MCTS_NO_VENV_WARN": "1"}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcts.cli.main",
            "scan",
            str(bad),
            "--live",
            "--no-progress",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    combined = result.stdout + result.stderr
    assert "credentials" in combined.lower() or "missing credentials" in combined.lower()


@pytest.mark.integration
def test_live_import_error_message(tmp_path: Path) -> None:
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
            "scan",
            str(bad),
            "--live",
            "--no-progress",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    combined = result.stdout + result.stderr
    assert "FAILED TO START" in combined or "Import Error" in combined
