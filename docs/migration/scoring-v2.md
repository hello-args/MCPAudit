# Migrating to MCTS Risk Score v2

## Enable v2

```bash
mcts scan <target> --scoring v2      # legacy + score_v2 in JSON
mcts scan <target> --scoring both    # same; UI shows both when supported
```

Default is `--scoring both` (legacy `score.overall` plus `score_v2` in JSON and reports).

## Score differences (expected)

| Metric | Legacy `score.overall` | v2 `absolute_risk` |
|--------|------------------------|-------------------|
| Scorable set | All except `compliance` | Excludes `compliance` **and** `attack_chains` |
| Chain signal | Critical chain meta-rows in sum | `chain_factor` on tool-attributed findings |
| Scale | 0–100 (higher = better) | Unbounded integer (higher = worse) |

Same scan can show different numbers — not a regression.

## `--no-attack-chains`

Under `--scoring v2|both`, the attack chains analyzer **still runs** (graph + meta-findings). The flag disables the chain multiplier only (`chain_factor_mode: disabled`). Use `--scoring legacy` to omit chain meta-findings entirely.

## CI gates

| Flag | Applies to |
|------|------------|
| `--min-score` | Legacy `score.overall` only |
| `--min-security-score` | v2 `security_score` (requires corpus stats) |
| `--max-absolute-risk` | v2 `absolute_risk` |
| `--max-risk-level` | v2 `risk_level` |
| `--fail-on-category` | Legacy category points only |

## API

`ScanRequest` accepts `scoring_mode`, `weights_profile`, and v2 gate fields. HTTP responses do not fail on gates in v2.0 — inspect `score_v2` client-side (ADR-003).

## History & trends

`mcts_analysis/history.json` entries include `scoring_version`. When all runs use v2/both, the HTML trend chart plots `absolute_risk` (never mixed with legacy score on one axis). Mixed history shows legacy score with a warning.

## Machine-wide & inventory

`mcts scan --machine-wide` and inventory batch scans include `absolute_risk`, `security_score`, and `risk_level` per server when v2 is enabled. `worst_absolute_risk` is reported in machine-wide summaries.

## Governance policy

Optional `.mcts/policy.yaml` fields:

```yaml
min_score: 70              # legacy overall only
min_security_score: 50     # v2 benchmark score
max_absolute_risk: 500     # v2 absolute risk ceiling
max_risk_level: medium     # v2 band gate
min_category_score_v2:     # v2 OWASP tiles (100=good; fail when below)
  injection: 80
  privilege: 70
```

## Asset overrides

Optional `.mcts/assets.yaml` for v2 `asset_value` overrides:

```yaml
overrides:
  customer_db: 0.9
  temp_cache: 0.2
```

Pass `--assets-path .mcts/assets.yaml` or set `assets_path` on `ScanConfig`.
