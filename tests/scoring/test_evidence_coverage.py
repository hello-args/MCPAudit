"""PR-4b corpus evidence coverage gate."""

from mcts.scoring.context import scorable_findings_v2
from mcts.scoring.corpus_runner import iter_corpus_reports
from mcts.scoring.evidence_tags import has_non_default_v2_evidence

PILOT_COVERAGE_THRESHOLD = 0.80


def _evidence_coverage(report) -> float:
    scorable = scorable_findings_v2(report.findings)
    if not scorable:
        return 1.0
    tagged = sum(1 for finding in scorable if has_non_default_v2_evidence(finding))
    return tagged / len(scorable)


def test_corpus_servers_meet_evidence_coverage_pilot() -> None:
    failures: list[str] = []
    for server_id, report in iter_corpus_reports(scoring_mode="v2"):
        scorable = scorable_findings_v2(report.findings)
        if not scorable:
            continue
        coverage = _evidence_coverage(report)
        if coverage < PILOT_COVERAGE_THRESHOLD:
            failures.append(f"{server_id}: {coverage:.0%}")
    assert not failures, f"evidence coverage below {PILOT_COVERAGE_THRESHOLD:.0%}: {failures}"


def test_corpus_expected_ordering_from_fixture() -> None:
    import json

    from mcts.scoring.corpus_runner import CORPUS_DIR, scan_corpus_absolute_risks

    expected = json.loads((CORPUS_DIR / "expected_order.json").read_text(encoding="utf-8"))
    risks = scan_corpus_absolute_risks(scoring_mode="v2")
    ordered = sorted(expected, key=lambda server_id: risks[server_id], reverse=True)
    assert ordered == expected
