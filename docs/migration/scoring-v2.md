# Scoring v2 — migration & configuration

> **New to scoring?** Start with the [Scoring developer guide](../reporting/scoring-guide.md) — it explains the two scores, CI flags, and JSON fields in plain language.

This page covers **configuration and migration** details not repeated in the main guide.

---

## Modes

| `--scoring` | `score.overall` | `score_v2` in JSON |
|-------------|-----------------|-------------------|
| `both` (**default**) | Yes | Yes |
| `v2` | Yes | Yes |
| `legacy` | Yes | No |

```bash
mcts scan <target>                  # both (default)
mcts scan <target> --scoring legacy # legacy only
```

---

## Governance policy (`.mcts/policy.yaml`)

```yaml
# Legacy
min_score: 70
max_critical: 0

# v2 (optional)
min_security_score: 50
max_absolute_risk: 500
max_risk_level: medium
min_category_score_v2:
  injection: 80
  privilege: 70
```

Use with `mcts scan --policy .mcts/policy.yaml`.

---

## Asset overrides (`.mcts/assets.yaml`)

Optional v2 `asset_value` tuning:

```yaml
overrides:
  customer_db: 0.9
  temp_cache: 0.2
```

```bash
mcts scan <target> --assets-path .mcts/assets.yaml
```

---

## History & trends

`mcts_analysis/history.json` entries include:

- `scoring_version`
- `absolute_risk`, `security_score`, `risk_level` (when v2 ran)

Trend charts never mix legacy and v2 on the same Y-axis.

---

## Machine-wide & inventory

`mcts scan --machine-wide` and `mcts inventory --scan-all` add per-server v2 fields and `worst_absolute_risk` in summaries when v2 is enabled.

---

## API notes

- Request fields: `scoring_mode`, `weights_profile`, `corpus_stats_path`, `assets_path`, v2 gate fields
- Response: `gate_violations` array; HTTP 200 even when gates fail (use CLI for exit codes)

See [REST API](../platform/rest-api.md).

---

## Upgrading legacy-only CI

1. **No rush** — `--min-score` still works on `score.overall`.
2. **Add v2 gate alongside** — e.g. `--max-absolute-risk` without removing `--min-score`.
3. **Tune thresholds** on your corpus servers (baseline vs vulnerable).
4. **Switch primary metric** when team is ready — v2.2+ may repoint default CI docs to `security_score`.

---

## Related

- [Scoring developer guide](../reporting/scoring-guide.md)
- [Scoring spec v2](../reporting/scoring-spec-v2.md)
- [ADR-003](../analysis/adr-003-scoring-v2.md)
