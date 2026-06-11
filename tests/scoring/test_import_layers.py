"""Enforce one-way import boundaries for scoring modules."""

import ast
from pathlib import Path


def test_scoring_does_not_import_analyzers() -> None:
    scoring_dir = Path("src/mcts/scoring")
    offenders: list[str] = []
    for path in scoring_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("mcts.analyzers"):
                        offenders.append(f"{path}:{alias.name}")
            elif (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("mcts.analyzers")
            ):
                offenders.append(f"{path}:{node.module}")
    assert offenders == []
