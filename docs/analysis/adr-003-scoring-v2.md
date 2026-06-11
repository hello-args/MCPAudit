# ADR-003: MCTS Risk Score v2

**Status:** Accepted  
**Date:** 2026-06-11  
**Spec:** [scoring-spec-v2.md](../reporting/scoring-spec-v2.md)

## Context

Legacy scoring (`score.overall`) uses severity-only exponential decay. Clients need explainable, stable absolute risk with factor breakdowns and attack-chain amplification without double-counting chain meta-findings.

## Decisions

| Topic | Choice |
|-------|--------|
| Dual score in CI | `--min-score` stays on legacy `overall` until v2.2 |
| `scoring_mode="v2"` | Runs **both** engines: legacy `score` + `score_v2` |
| Chain meta-findings in v2 sum | **Exclude** — `attack_chains` in `NON_SCORING_V2` |
| Chain multiplier | `paths_v1` tool correlation on validated paths (`medium+` severity) |
| `hop_count` | `len(path_nodes) - 1` on edge-validated paths |
| Analyzer when v2 on | Always run `AttackChainAnalyzer`; bypass `--analyzers` / `--surfaces` |
| `chain_factor` gating | `enable_attack_chains` / `--no-attack-chains` sets `chain_factor_mode: disabled` |
| `weights_hash` | `ScoreV2Basis.weights_hash` only — not on `RiskScoreV2` |
| API score gates | CLI enforces exit codes; API returns `gate_violations` array without HTTP gate exit (v2.0) |
| Canonical graph | `scoring/graph.py` owns paths; `report/data.build_attack_graph()` delegates |
| Fake path rejection | BFS returns `None` when disconnected — never `[start, end]` |
| Model location | v2 types in `scoring/models.py`; `ScanReport` imports `RiskScoreV2` |
| `dimension_scores` | RFC factor axes only; OWASP in `category_scores_v2()` (PR-4d) |
| Bracket formula | `1 + Σ factor_increments` — no YAML bracket double-weight |
| Confidence | Affects `confidence_score` / `risk_range` only — never `absolute_risk` |

## Consequences

- `ScanReport.score` remains always populated (backward compatible).
- `ScanReport.score_v2` is additive when v2/both is enabled.
- Under v2/both, attack chains analyzer always runs; `--no-attack-chains` disables multiplier only.
- Legacy and v2 scores may diverge on the same scan — expected (different formulas and scorable sets).
