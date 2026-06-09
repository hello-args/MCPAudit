# Reporting

> [Documentation](../index.md) → **Reporting**

How MCTS presents risk: auditable scores, technique IDs, and multi-format export.

---

## Guides

| Page | Contents |
|------|----------|
| [Scoring Specification](scoring-spec.md) | Weights, exponential formula, category breakdown, CI gates, worked examples |
| [Threat Taxonomy](taxonomy.md) | MCTS-T / MCTS-M catalog, runtime techniques, Sigma rules, regression fixtures |
| [HTML Security Dashboard](html-report.md) | Dashboard pages, scoring display, export, implementation, design system |

---

## Output formats

| Format | Command | Use case |
|--------|---------|----------|
| Terminal | `mcts scan` (default) | Developer feedback |
| JSON | `mcts scan -o report.json` | Automation, `mcts report` input |
| SARIF | `mcts scan -f sarif -o report.sarif` | GitHub Code Scanning |
| HTML | `mcts report report.json` | Executive / security review |

---

## Planned reporting

| Format / feature | Status | Phase |
|------------------|--------|-------|
| CycloneDX / SPDX AI-BOM | Planned | 2–3 |
| Nucleus FlexConnect / OCSF JSON | Planned | 2 |
| Interactive attack-graph HTML | Planned | 2 |
| Credential / blast-radius graphs | Planned | 3 |
| Scan history + trend charts | Planned | 2 |
| Dual E/W/X/TF taxonomy option | Planned | 2 |
| AIVSS / letter-grade modes | Partial | 2–4 |
| SBOM-specific HTML report | Planned | 3 |
| Certification badge SVG | Planned | 3 |

Gap index: [Feature Expansion Plan — Reporting](../more/feature-expansion-plan.md#reporting-10) · [Product Positioning](../more/product-positioning.md#complete-gap-index).

---

## Related

- [CLI — output formats](../platform/cli.md)
- [CI Integration](../platform/ci-integration.md)
- [Documentation index](../index.md)
