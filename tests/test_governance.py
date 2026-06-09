"""Tests for governance policy evaluation."""

from __future__ import annotations

from pathlib import Path

from mcts.governance import evaluate_policy, load_policy


def test_load_and_evaluate_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "min_score: 80\nmax_critical: 0\nallowed_servers:\n  - cursor/demo\nblocked_servers: []\n"
    )
    policy = load_policy(policy_path)
    assert policy is not None
    violations = evaluate_policy(
        policy=policy,
        score=70,
        critical=0,
        high=1,
        servers=["cursor/other"],
    )
    assert any("score" in item for item in violations)
    assert any("allowlist" in item for item in violations)
