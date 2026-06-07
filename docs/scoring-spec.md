# Scoring Specification

MCTS computes an auditable **security score** and **risk index** from findings. Every `ScanReport` includes a `ScoreBasis` so teams can verify how the number was derived.

**Implementation:** `src/mcts/scoring/engine.py`, category logic in `src/mcts/report/data.py`

---

## Severity weights

| Severity | Raw risk points |
|----------|-----------------|
| Critical | 25 |
| High | 10 |
| Medium | 3 |
| Low | 1 |

```python
raw_risk = critical×25 + high×10 + medium×3 + low×1
```

Only findings from **security analyzers** count. Meta-findings from `compliance` are excluded (`NON_SCORING_ANALYZERS`).

---

## Overall security score

Exponential decay — higher is better:

```
overall = round(100 × e^(-raw_risk / 50))
```

- `raw_risk == 0` → score **100**
- Clamped to `[0, 100]`
- Decay scale constant: `RISK_DECAY_SCALE = 50`

**Example:** 3 Critical + 7 High + 2 Medium → raw_risk = 3×25 + 7×10 + 2×3 = **151** → overall ≈ **5**

The terminal and JSON report show the formula via `score.basis`.

---

## Risk index

Linear cap on raw risk — higher is worse:

```
risk_index = min(100, raw_risk)
```

Useful for dashboards that treat “risk” as a 0–100 burden rather than inverted security score.

---

## JSON fields

```json
{
  "score": {
    "overall": 5,
    "risk_index": 100,
    "raw_risk": 151,
    "penalty": 151,
    "basis": {
      "critical": 3,
      "high": 7,
      "medium": 2,
      "low": 0,
      "scorable_total": 12,
      "excluded_non_scorable": 2
    }
  }
}
```

---

## Category breakdown

Category scores power the **terminal dashboard**, **HTML radar chart**, and **`--fail-on-category`** CI gates.

Each category sums weighted finding points from mapped analyzers, capped at a maximum:

| Key | Label | Max | Analyzers |
|-----|-------|-----|-----------|
| `permissions` | Excessive Permissions | 20 | `permission_analyzer` |
| `injection` | Injection & Metadata | 20 | `prompt_injection`, `metadata_integrity`, `schema_surface` |
| `execution` | Execution & Path Risk | 15 | `command_execution`, `path_validation`, `tool_abuse` |
| `data_leakage` | Data Leakage Risk | 15 | `data_leakage` |
| `attack_chains` | Attack Chain Risk | 15 | `attack_chains` |
| `shadowing` | Cross-Server Shadowing | 5 | `cross_server` |
| `jailbreak` | Jailbreak Resistance | 10 | `jailbreak` |

Per-category score: `min(maximum, sum of severity weights for matched findings)`.

Industry benchmark values (for HTML radar overlay) are defined in `report/data.py` → `INDUSTRY_BENCHMARK`.

---

## CI gate semantics

Exit code **1** when a gate fails; **2** for usage/consent errors.

| Flag | Fails when |
|------|------------|
| `--fail-on-critical` | Any critical finding |
| `--min-score N` | `score.overall < N` |
| `--max-critical N` | Critical count > N |
| `--fail-on-category KEY:LIMIT` | Category score ≥ LIMIT (repeatable) |

Category gate example:

```bash
mcts scan ./repo/ \
  --min-score 70 \
  --max-critical 0 \
  --fail-on-category permissions:10 \
  --fail-on-category injection:15
```

Valid category keys: `permissions`, `injection`, `execution`, `data_leakage`, `attack_chains`, `shadowing`, `jailbreak`.

---

## Integrity check

`RiskScoringEngine.verify(findings, score)` re-computes the score and raises if mismatched — prevents hardcoded or stale scores in tests and production.

---

## Related

- [CLI Reference](cli.md)
- [CI Integration](ci-integration.md)
- [HTML Security Dashboard](html-report.md)
