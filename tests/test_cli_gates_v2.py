"""v2 CI gate tests."""

import contextlib
from pathlib import Path
from unittest.mock import patch

from mcts.cli.main import _check_gates
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner


def test_v2_gate_requires_scoring_mode() -> None:
    report = Scanner(
        ScanConfig(target=Path("examples/baseline-mcp-server/server.py"), scoring_mode="legacy")
    ).run()
    config = ScanConfig(
        target=Path("examples/baseline-mcp-server/server.py"),
        scoring_mode="legacy",
        max_absolute_risk=10,
    )
    with patch("mcts.cli.main.typer.Exit", side_effect=SystemExit(1)):
        try:
            _check_gates(report, config)
        except SystemExit:
            return
    raise AssertionError("expected exit when v2 gate set without score_v2")


def test_legacy_min_score_gate_unchanged() -> None:
    report = Scanner(
        ScanConfig(target=Path("examples/vulnerable-mcp-server/server.py"), scoring_mode="legacy")
    ).run()
    config = ScanConfig(
        target=Path("examples/vulnerable-mcp-server/server.py"),
        scoring_mode="legacy",
        min_score=100,
    )
    with (
        patch("mcts.cli.main.typer.Exit", side_effect=SystemExit(1)) as exit_mock,
        contextlib.suppress(SystemExit),
    ):
        _check_gates(report, config)
    exit_mock.assert_called_once_with(code=1)


def test_min_category_score_v2_gate_exits_on_vulnerable() -> None:
    report = Scanner(
        ScanConfig(target=Path("examples/vulnerable-mcp-server/server.py"), scoring_mode="v2")
    ).run()
    config = ScanConfig(
        target=Path("examples/vulnerable-mcp-server/server.py"),
        scoring_mode="v2",
        min_category_score_v2={"injection": 80},
    )
    with (
        patch("mcts.cli.main.typer.Exit", side_effect=SystemExit(1)) as exit_mock,
        contextlib.suppress(SystemExit),
    ):
        _check_gates(report, config)
    exit_mock.assert_called_once_with(code=1)
