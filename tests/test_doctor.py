"""Tests for mcts doctor command."""

from __future__ import annotations

import builtins
import json
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import mcts.cli.doctor as doctor_module
from mcts.cli.main import app

runner = CliRunner()


def test_doctor_warns_bare_python_without_venv(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"local": {"command": "python", "args": []}}}))
    result = runner.invoke(app, ["doctor", str(tmp_path)])
    assert result.exit_code == 0
    assert "interpreter" in result.stdout.lower() or "python" in result.stdout.lower()


def test_doctor_finds_config_and_entrypoint(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"local": {"command": "python", "args": ["-m", "app"]}}}))
    bridge = tmp_path / "ifd" / "mcp" / "bridge.py"
    bridge.parent.mkdir(parents=True)
    bridge.write_text("from mcp.server import Server\nFastMCP()\n@tool\ndef t(): pass\n")
    result = runner.invoke(app, ["doctor", str(tmp_path)])
    assert result.exit_code == 0
    assert ".mcp.json" in result.stdout
    assert "bridge.py" in result.stdout


@pytest.mark.parametrize(
    ("spec", "expected_status"),
    [
        (ModuleSpec("mcp", loader=None), "pass"),
        (None, "warn"),
    ],
)
def test_doctor_reports_mcp_extra_status(
    monkeypatch: pytest.MonkeyPatch,
    spec: ModuleSpec | None,
    expected_status: str,
) -> None:
    monkeypatch.setattr(
        doctor_module.importlib_util,
        "find_spec",
        lambda name: spec if name == "mcp" else None,
    )

    checks: list[tuple[str, str, str]] = []
    did_warn = doctor_module._append_optional_extra_check(
        checks,
        extra_label="Extra [mcp]",
        module_name="mcp",
        available_detail="installed — live scan / mcts-mcp available",
        missing_detail='missing — install with `pip install "mcp-mcts[mcp]"` or `uv sync --extra mcp`',
    )

    assert did_warn is (expected_status == "warn")
    assert checks == [
        (
            expected_status,
            "Extra [mcp]",
            "installed — live scan / mcts-mcp available"
            if expected_status == "pass"
            else 'missing — install with `pip install "mcp-mcts[mcp]"` or `uv sync --extra mcp`',
        )
    ]


def test_doctor_deep_missing_optional_tools_show_warnings(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(doctor_module.importlib_util, "find_spec", lambda _module: None)
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _executable: None)
    monkeypatch.delenv("MCTS_LLM_API_KEY", raising=False)

    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0
    assert "Extra [mcp]: missing" in result.stdout
    assert "[api] extra: modules 'fastapi', 'uvicorn' not found" in result.stdout
    assert "semgrep CLI: not found on PATH" in result.stdout
    assert "pip-audit CLI: not found on PATH" in result.stdout
    assert "opa CLI: not found on PATH" in result.stdout
    assert "MCTS_LLM_API_KEY: not set" in result.stdout


def test_doctor_deep_present_optional_tools_show_pass_lines(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(doctor_module.importlib_util, "find_spec", lambda _module: SimpleNamespace())
    monkeypatch.setattr(doctor_module.shutil, "which", lambda executable: f"C:\\tools\\{executable}.exe")
    monkeypatch.setenv("MCTS_LLM_API_KEY", "test-key")

    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0
    assert "Extra [mcp]: installed" in result.stdout
    assert "[api] extra: modules 'fastapi', 'uvicorn' importable" in result.stdout
    assert "semgrep CLI: found at C:\\tools\\semgrep.exe" in result.stdout
    assert "pip-audit CLI: found at C:\\tools\\pip-audit.exe" in result.stdout
    assert "opa CLI: found at C:\\tools\\opa.exe" in result.stdout
    assert "MCTS_LLM_API_KEY: set" in result.stdout


def test_doctor_deep_missing_optional_extras_do_not_fail_core_only_install(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        doctor_module.importlib_util,
        "find_spec",
        lambda module: None if module in {"mcp", "fastapi"} else SimpleNamespace(),
    )

    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0
    assert "Extra [mcp]: missing" in result.stdout
    assert "[api] extra: module 'fastapi' not found" in result.stdout


def test_doctor_default_reports_api_extra_status(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        doctor_module.importlib_util,
        "find_spec",
        lambda module: None if module in {"fastapi", "uvicorn"} else SimpleNamespace(),
    )

    result = runner.invoke(app, ["doctor", str(tmp_path)])

    assert result.exit_code == 0
    assert "[api] extra: modules 'fastapi', 'uvicorn' not found" in result.stdout
    assert "mcts serve" in result.stdout


def test_serve_missing_api_extra_references_doctor(monkeypatch) -> None:
    real_import = builtins.__import__

    def fail_uvicorn(name, *args, **kwargs):
        if name == "uvicorn":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_uvicorn)

    result = runner.invoke(app, ["serve"])

    assert result.exit_code == 2
    assert "REST API requires optional api extra" in result.stdout
    assert "mcts doctor ." in result.stdout


def test_doctor_deep_exits_zero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0


def test_doctor_deep_without_config_shows_skip_message(tmp_path: Path) -> None:
    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0
    assert "Deep checks: skipped — no MCP config found" in result.stdout


def test_doctor_deep_without_module_shows_skip_message(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"local": {"command": "python", "args": ["server.py"]}}}))

    result = runner.invoke(app, ["doctor", "--deep", str(tmp_path)])

    assert result.exit_code == 0
    assert "Deep checks: skipped for 'local' — no -m module in launch args" in result.stdout


def test_doctor_deep_json_includes_skip_status(tmp_path: Path) -> None:
    result = runner.invoke(app, ["doctor", "--deep", "--json", str(tmp_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout.split("Saved")[0].strip())
    deep_checks = [row for row in payload["checks"] if row["label"] == "Deep checks"]
    assert deep_checks
    assert deep_checks[0]["status"] == "warn"
    assert "skipped" in deep_checks[0]["detail"]
