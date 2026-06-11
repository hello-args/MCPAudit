"""Shared scoring corpus loading and scan helpers."""

from __future__ import annotations

import json
import math
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.reporting.models import ScanReport
from mcts.scoring.context import rebuild_scoring_context_from_report
from mcts.scoring.engine_v2 import dimension_raw_sums
from mcts.scoring.models import FACTOR_DIMENSIONS

CORPUS_DIR = (Path(__file__).resolve().parents[3] / "tests/fixtures/scoring_corpus").resolve()
PACKAGE_STATS_PATH = Path(__file__).resolve().parent / "data/scoring_v2_corpus_stats.json"
EXPERT_RANKINGS_PATH = CORPUS_DIR / "expert_rankings.json"
SERVERS_PATH = CORPUS_DIR / "servers.json"


def load_corpus_entries() -> list[dict[str, Any]]:
    data = json.loads(SERVERS_PATH.read_text(encoding="utf-8"))
    return list(data.get("servers", []))


def build_corpus_scan_config(entry: dict[str, Any], *, scoring_mode: str = "v2") -> ScanConfig:
    overrides = dict(entry.get("scan_config") or {})
    return ScanConfig(
        target=Path(entry["path"]),
        scoring_mode=scoring_mode,
        **overrides,
    )


def iter_corpus_reports(*, scoring_mode: str = "v2") -> Iterator[tuple[str, ScanReport]]:
    for entry in load_corpus_entries():
        if entry.get("skip"):
            continue
        report = Scanner(build_corpus_scan_config(entry, scoring_mode=scoring_mode)).run()
        yield entry["server_id"], report


@dataclass(frozen=True)
class CorpusMetrics:
    risks: dict[str, int]
    dimension_buckets: dict[str, list[float]]


def scan_corpus_metrics(*, scoring_mode: str = "v2") -> CorpusMetrics:
    """Single-pass corpus scan returning absolute risks and per-axis raw sums."""
    risks: dict[str, int] = {}
    dimension_buckets: dict[str, list[float]] = {dim: [] for dim in FACTOR_DIMENSIONS}
    for entry in load_corpus_entries():
        if entry.get("skip"):
            continue
        config = build_corpus_scan_config(entry, scoring_mode=scoring_mode)
        report = Scanner(config).run()
        server_id = entry["server_id"]
        if report.score_v2 is None:
            raise RuntimeError(f"score_v2 missing for corpus server {server_id}")
        risks[server_id] = report.score_v2.absolute_risk
        ctx = rebuild_scoring_context_from_report(report, config)
        raw = dimension_raw_sums(report.findings, ctx)
        for dim in FACTOR_DIMENSIONS:
            dimension_buckets[dim].append(raw[dim])
    return CorpusMetrics(risks=risks, dimension_buckets=dimension_buckets)


def scan_corpus_absolute_risks(*, scoring_mode: str = "v2") -> dict[str, int]:
    return scan_corpus_metrics(scoring_mode=scoring_mode).risks


def _percentile(sorted_values: list[int], pct: float) -> int:
    if not sorted_values:
        return 0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * (pct / 100.0)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return sorted_values[int(rank)]
    weight = rank - low
    return round(sorted_values[low] * (1 - weight) + sorted_values[high] * weight)


def spearman_rho(ranked_a: list[float], ranked_b: list[float]) -> float:
    """Pure-Python Spearman rank correlation (no scipy)."""
    n = len(ranked_a)
    if n < 2 or n != len(ranked_b):
        return 0.0

    def ranks(values: list[float]) -> list[float]:
        order = sorted(range(n), key=lambda i: values[i])
        out = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and values[order[j + 1]] == values[order[i]]:
                j += 1
            avg_rank = (i + j) / 2.0 + 1.0
            for k in range(i, j + 1):
                out[order[k]] = avg_rank
            i = j + 1
        return out

    ra = ranks(ranked_a)
    rb = ranks(ranked_b)
    d2 = sum((a - b) ** 2 for a, b in zip(ra, rb, strict=True))
    return 1.0 - (6.0 * d2) / (n * (n * n - 1))


def _percentile_float(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * (pct / 100.0)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return sorted_values[int(rank)]
    weight = rank - low
    return sorted_values[low] * (1 - weight) + sorted_values[high] * weight


def _dimension_p95_from_buckets(dimension_buckets: dict[str, list[float]]) -> dict[str, int]:
    """P95 per axis using servers with non-zero raw sums (zeros excluded)."""
    p95: dict[str, int] = {}
    for dim, values in dimension_buckets.items():
        positive = sorted(max(0.0, value) for value in values if value > 0)
        if not positive:
            p95[dim] = 1
            continue
        raw_p95 = _percentile_float(positive, 95)
        p95[dim] = max(1, round(raw_p95))
    return p95


def build_package_stats_from_metrics(metrics: CorpusMetrics, *, version: str) -> dict[str, Any]:
    risks = metrics.risks
    distribution = sorted(risks.values())
    positive = [value for value in distribution if value > 0] or distribution
    stats = json.loads(PACKAGE_STATS_PATH.read_text(encoding="utf-8"))
    stats["version"] = version
    stats["distribution"] = distribution
    stats["server_count"] = len(distribution)
    stats["p25"] = _percentile(distribution, 25)
    stats["p50"] = _percentile(distribution, 50)
    stats["p75"] = _percentile(distribution, 75)
    stats["p90"] = _percentile(distribution, 90)
    stats["p95"] = _percentile(positive, 95) if positive else 0
    max_risk = max(distribution) if distribution else 0
    stats["risk_bands"] = {
        "low": [0, max(99, stats["p25"] - 1)],
        "medium": [max(100, stats["p25"]), max(249, stats["p50"])],
        "high": [max(250, stats["p75"]), max(499, stats["p90"])],
        "critical": [max(500, stats["p95"]), max_risk + 1000],
    }
    stats["dimension_p95"] = _dimension_p95_from_buckets(metrics.dimension_buckets)
    return stats


def build_package_stats_from_risks(risks: dict[str, int], *, version: str) -> dict[str, Any]:
    """Backward-compatible wrapper when only absolute risks are available."""
    stats = json.loads(PACKAGE_STATS_PATH.read_text(encoding="utf-8"))
    preserved_dims = stats.get("dimension_p95", {})
    empty = {dim: [] for dim in FACTOR_DIMENSIONS}
    built = build_package_stats_from_metrics(
        CorpusMetrics(risks=risks, dimension_buckets=empty),
        version=version,
    )
    if preserved_dims:
        built["dimension_p95"] = preserved_dims
    return built
