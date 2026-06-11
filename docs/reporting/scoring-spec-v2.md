# MCTS Risk Score v2 — Specification

> **Read first:** [Scoring developer guide](scoring-guide.md) — mental model, CI flags, JSON fields.  
> This page is the **technical v2 reference** (formulas and implementation map).

**Status:** GA (default `--scoring both`)  
**ADR:** [adr-003-scoring-v2.md](../analysis/adr-003-scoring-v2.md)  
**Legacy spec:** [scoring-spec.md](scoring-spec.md)  
**SARIF:** [sarif-score-v2.md](sarif-score-v2.md)

## Overview

v2 adds `score_v2` with **absolute risk** (integer, higher = worse) next to legacy `score.overall` (0–100, higher = better).

## Scorable set

Excluded from v2 sum: `compliance`, `attack_chains` meta-findings. Tool-attributed findings from other analyzers are scored.

## Per-finding formula (RFC §4.1)

```
bracket = 1 + Σ factor_increments
base_risk = severity_w × bracket
finding_risk = round(base_risk × chain_factor)
absolute_risk = Σ finding_risk
```

Factor increments come from classifiers in `weights_v1.yaml` under `classifiers:`. Evidence tags on findings refine classifiers when emitters populate `reachability_tag`, `exploitability_class`, etc.

## Chain multiplier

`chain_factor` applies to tool findings on validated graph paths (`hop_count` ≥ 1). Severity floor: medium+. Meta chain rows are display-only.

| hop_count | chain_factor |
|-----------|--------------|
| 0–1 | 1.0 |
| 2 | 1.15 |
| 3 | 1.35 |
| 4+ | 1.50 |

## Output (`score_v2`)

| Field | Description |
|-------|-------------|
| `absolute_risk` | Stable integer sum |
| `security_score` | `100 - percentile(absolute_risk, corpus)` when stats available |
| `risk_level` | Band from corpus or literals: low/medium/high/critical |
| `risk_range` | Confidence interval on absolute risk (not driven by finding confidence) |
| `dimension_scores` | Eight factor axes 0–100 (higher = worse) |
| `top_contributors` | Top 10 findings/paths by contribution |
| `category_scores_v2` | Separate OWASP tiles, 100 = good (dashboard JSON) |
| `basis` | Scorable counts, excluded meta-rows, `weights_hash` |

## Aggregation formulas (§8.8–8.10)

### §8.8 `confidence_score` (RFC §4.3)

Confidence affects `confidence_score` and `risk_range` only — **never** `absolute_risk`. Inputs are v2-scorable findings with aligned per-finding risks:

```
pairs = [(risk, finding) for finding, risk in zip(scorable, risks) if risk > 0]
if no pairs → confidence_score = 100
else confidence_score = round(100 × Σ(effective_confidence(f) × risk) / Σ risk)
```

`effective_confidence` applies per-analyzer caps from `uncertainty.py` when `finding.confidence >= 0.99`.

### §8.9 `risk_range` spread (RFC §4.12)

```
if absolute_risk == 0 → risk_range = (0, 0), label = "high"
mean_conf = weighted mean of effective_confidence by finding_risk
base_spread = absolute_risk × (1 - mean_conf) × 0.35
spread = base_spread × evidence_quality_factor × analyzer_disagreement_factor
low = max(0, round(absolute_risk - spread))
high = round(absolute_risk + spread)
label = high if mean_conf >= 0.85 else medium if mean_conf >= 0.65 else low
```

- `evidence_quality_factor`: 0.8 when live_probe + handler_traced tags present; else 1.2  
- `analyzer_disagreement_factor`: 1.4 when conflicting severities share a tool; else 1.0

### §8.10 `top_contributors` selection (RFC §4.14)

1. Rank scorable findings by `finding_risk` descending; take up to **9** rows (`type=finding`).  
2. Append one explainability row (`type=attack_chain`) for the highest `hop_count` path when paths exist and total rows &lt; 10.  
3. JSON export caps at **10** rows and omits verbose `evidence_tags`.

Per-finding contributor fields: `risk_contribution`, `confidence` (effective × 100), `chain_factor`, `factors` breakdown.

### `dimension_scores` normalization (§7.5)

Per-axis raw sum = Σ factor increment for that axis across scorable findings. Normalized 0–100 (higher = worse):

```
if raw <= 0 → 0
elif corpus dimension_p95[axis] > 0 → min(100, round(100 × raw / p95))
else → min(100, round(100 × raw / max(absolute_risk, 1)))
```

`dimension_p95` per axis is recomputed from corpus scans via `scripts/calibrate_scoring_weights.py --write-package-stats`.

## CI gates

| Flag | Applies to |
|------|------------|
| `--min-score` | Legacy only |
| `--min-security-score` | v2 benchmark score |
| `--max-absolute-risk` | v2 absolute risk |
| `--max-risk-level` | v2 band |
| `--min-category-score-v2` | v2 OWASP tiles (100=good; fail when below minimum) |
| `--fail-on-category` | Legacy category tiles only |

## Implementation map

| Module | Role |
|--------|------|
| `scoring/engine_v2.py` | Sum, verify, contributors |
| `scoring/context.py` | `build_scoring_context`, chain factors |
| `scoring/graph.py` | `canonical_attack_graph`, `build_paths` |
| `scoring/evidence_tags.py` | PR-4b analyzer evidence tag helpers |
| `scoring/evidence_emit.py` | Graph/scope-dependent evidence enrichment |
| `scoring/weights_v1.yaml` | Classifier lookup tables |
