# HTML Security Dashboard

> [Documentation](../index.md) → [Reporting](README.md)

The HTML dashboard turns a JSON scan report into a **shareable, self-contained web page** — suitable for security reviews, leadership briefings, or audit documentation.

> **Haven't generated a report yet?** Run `mcts scan ./server.py -o report.json` first, then `mcts report report.json -o report.html`.  
> **Two scores on the page?** See [Scoring developer guide](scoring-guide.md) — v2 block is primary; legacy gauge is secondary when `both`.

---

## In plain English

After scanning, you get a JSON file with all findings and scores. The HTML dashboard converts that JSON into a polished web page with:

- **v2 multi-factor scoring** (default scans): absolute risk header, risk level pill, factor-axis radar, top contributors, OWASP `category_scores_v2` tiles
- Legacy visual score gauge and letter grade (A–F) — secondary when `--scoring both`
- Partitioned area scores (MCP Surface, Supply Chain, Dependency Hygiene) when present — legacy formula only
- Severity breakdown, category radar chart, and scan history trend (axis switches to `absolute_risk` when all history entries are v2)
- A searchable findings table with **location**, **MCTS-T technique links**, and remediation advice
- Attack chain visualization
- **OWASP LLM Top 10** and **OWASP MCP Top 10** mapping (including coverage gaps)
- Scan notes and static-scan tool-discovery disclaimers
- One-click export to PDF

The output is a single HTML file — no server needed to view it. Open it in any browser and share it via email or Slack.

---

## Quick start

```bash
# 1. Run a scan and save JSON
mcts scan examples/vulnerable-mcp-server/server.py -o report.json

# 2. Build the HTML dashboard
mcts report report.json -o security-report.html

# 3. Open in a browser
open security-report.html   # macOS
xdg-open security-report.html   # Linux
```

The output is one HTML file with **inlined CSS and JavaScript**. Chart.js and Inter font load from CDN on first open; scan data and brand assets are embedded for portability.

---

## Page structure

### Overview (landing)

| Section | Content |
|---------|---------|
| **Header** | MCTS logo, target path, scan timestamp, export menu |
| **Report guide** | How to read scores vs counts, quick-jump links |
| **v2 score section** | Primary when `score_v2` present: `absolute_risk`, `risk_level` pill, `security_score`, confidence, factor radar, top contributors |
| **Score gauge** | Legacy doughnut chart showing `score.overall` (0–100); labeled "Legacy Security Index (deprecated)" when `both` |
| **Grade card** | Letter grade A–F derived from legacy `score.overall` |
| **Posture badge** | v2: `risk_level` from `score_v2`; legacy-only scans use overall-score bands |
| **Issues summary** | Severity table with counts and meanings |
| **Area sub-scores** | MCP Surface, Supply Chain, Dependency Hygiene, Composite (when `score_breakdown` present) |
| **Checks summary** | Analyzers run, passed, with findings, categories clear |
| **Executive summary** | Narrative posture + P1/P2 recommended actions |
| **Top findings / passed checks** | Quick lists linking to detail pages |
| **Category breakdown** | Progress bars per risk dimension |
| **Radar chart** | Your categories vs industry benchmark |
| **Trend panel** | Historical scores from `scan_history` or `mcts_analysis/history.json` |
| **Risk guide** | Reference cards for score ranges 0–25 through 76–100 |
| **Banners** | Tool-discovery notice (static scans), `scan_notes` (includes instruction-discovery summary when repo markdown was loaded) |

When repository instruction discovery runs, a note is appended to `scan_notes` (visible in the overview banners) listing counts of prompt surfaces, `SKILL.md` files, and system instruction files found. Dedicated sidebar fields for `instruction_sources` / skill counts are not shown yet — use the JSON export or `server.agent_skills` in Raw Data for audit detail.

Sidebar **Scan Information** includes target, **scan scope** (repository / live / snapshot / entrypoint), date/time, tools, and analyzers run.

### Sidebar pages

| Page | Purpose |
|------|---------|
| **Issues to Fix** | Search, filter by severity, sort; columns for location, technique, category, OWASP, tool, remediation |
| **All Checks** | Per-analyzer passed vs issues with severity breakdown |
| **How to Fix** | Prioritized P1–P4 remediation list with mitigation links |
| **Attack Paths** | SVG graph from `attack_graph` capability paths |
| **MCTS-T Map** | Full 79-technique catalog with Detected / Clear filters |
| **Capabilities** | Tool × capability matrix (reads input, egress, exec, etc.) |
| **OWASP Mapping** | LLM Top 10 findings + MCP Top 10 findings and coverage gaps |
| **Raw Data** | Full embedded `ScanReport` JSON for auditors |

Navigation is client-side (no server required).

---

## Findings table columns

| Column | Source | Notes |
|--------|--------|-------|
| Severity | `finding.severity` | Color-coded badge |
| Finding | `title` + `description` | Primary issue text |
| Location | `finding.location` | `file:line` for SAST; `—` when absent |
| Technique | `technique_id` + `technique_url` | Link to MCTS-T scenario when mapped |
| CWE | `finding.cwe_id` | Common Weakness Enumeration when mapped |
| Category | Analyzer label | Friendly name from `ANALYZER_LABELS` |
| OWASP | LLM Top 10 IDs | From `OWASP_LLM_ANALYZER_MAP` (same as compliance) |
| Affected Tool | `finding.tool` | MCP tool name when applicable |
| Confidence | `finding.confidence` | Analyzer confidence (0–100%) |
| Remediation | `recommendation` | Plus MCTS mitigation doc links |

Rows with structured **evidence** expand on click to show the full JSON blob.

Search matches title, category, tool, location, technique ID, CWE, and evidence summary.

---

## Scoring display

### Dual scoring (default: `--scoring both`)

When `score_v2` is present, the dashboard promotes v2 metrics and demotes legacy to a secondary card:

| Element | Source field | Notes |
|---------|--------------|-------|
| Primary header | `score_v2.absolute_risk` + `risk_level` | Unbounded integer; higher = worse |
| Risk range | `score_v2.risk_range` | Confidence interval — not driven by finding confidence |
| Benchmark score | `score_v2.security_score` | 0–100 percentile vs corpus (omitted if no stats) |
| Factor radar | `score_v2.dimension_scores` | Eight RFC factor axes (exploitability, reachability, …) |
| Top contributors | `score_v2.top_contributors` | Max 10 in JSON; expandable factor breakdown in HTML |
| v2 OWASP tiles | `category_scores_v2` | 100 = good polarity; separate from legacy category bars |
| Dual glossary | `score_help` | Explains why legacy and v2 numbers differ (scorable-set divergence) |
| Legacy gauge | `score.overall` | Higher is better (0–100 points); deprecated label when `both` |
| Letter grade | `security_grade(score.overall)` | A=90+, F&lt;60 — legacy only today |

### Legacy-only elements (unchanged formula)

| Element | Source field | Notes |
|---------|--------------|-------|
| Risk index | `score.risk_index` | Shown in legacy detail |
| Area sub-scores | `score_breakdown` | MCP Surface, Supply Chain, Dependency Hygiene — **v1 partitions only** |
| Category bars | `CATEGORY_DEFS` weighting | Higher bar = more risk in dimension |
| Formula tooltip | `score.basis` | Severity-weighted legacy calculation |

**Important:** Legacy security scores are **points**, not pass rates. v2 `absolute_risk` uses a different scorable set (excludes `attack_chains` meta-rows) and factor formula — divergent numbers on the same scan are expected. See [Scoring v2 migration](../migration/scoring-v2.md).

### Trend chart

`score_trend()` picks the Y-axis from history `scoring_version`: all-v2 runs plot `absolute_risk`; mixed history keeps legacy `score` with a warning in `trend_meta`.

---

## Attack chain graph

Renders `ScanReport.attack_graph` from `AttackChainAnalyzer`:

- Nodes = tools with capability profiles
- Edges = inferred attack transitions (read→exfil, read→exec, etc.)
- Empty state when no chains detected (no synthetic fake edges)

---

## OWASP mapping

### LLM Top 10

`llm_owasp_mappings()` uses `OWASP_LLM_ANALYZER_MAP` from `compliance/checks.py` (full LLM01–LLM10):

- **Finding cards** — categories where mapped analyzers reported issues
- **Coverage gap cards** — categories with no findings from mapped analyzers (mirrors compliance `owasp_llm_gaps` evidence)

### MCP Top 10

`mcp_owasp_mappings()` uses the same analyzer→category map as `ComplianceChecker` (`MCP_ANALYZER_MAP` in `compliance/checks.py`):

- **Finding cards** — MCP categories where mapped analyzers reported issues
- **Coverage gap cards** — MCP categories with no findings from mapped analyzers (mirrors compliance meta-findings when `compliance-mcp-top10-gaps` is emitted)

Compliance meta-findings do not affect the security score.

---

## Export options

Header **Export** menu and sidebar actions:

| Action | Mechanism |
|--------|-----------|
| **Download JSON** | Embedded `ScanReport` blob |
| **Save HTML** | Browser save of current document |
| **Print / PDF** | `@media print` styles for executive PDFs |

No data is sent to MCTS servers — all processing is local in the browser.

---

## Implementation architecture

```
mcts report report.json
        │
        ▼
ScanReport.model_validate_json()
        │
        ▼
report/data.py → build_dashboard_payload()
        │
        ▼
report/generators/html_report.py
  ├── Jinja2: templates/dashboard.html
  ├── Inline: assets/styles.css, assets/dashboard.js
  └── Embed: brand/logo-report.png (base64)
        │
        ▼
security-report.html (single file)
```

### Key files

| Path | Role |
|------|------|
| `report/templates/dashboard.html` | Jinja2 shell and section layout |
| `report/assets/styles.css` | Enterprise dark card design system |
| `report/assets/dashboard.js` | Charts, tables, navigation, export |
| `report/assets/icons/` | SVG severity icons |
| `report/data.py` | ScanReport → dashboard JSON |
| `report/generators/html_report.py` | Assembly and inlining |
| `compliance/checks.py` | MCP Top 10 analyzer map (shared with compliance) |
| `brand/logo-report.png` | Hex icon embed (no wordmark — legible at 44×44) |

Entry: `mcts.reporting.html.write_html_report()` delegates to generator.

### Tests

`tests/test_html_report.py` — payload builder validation, location/technique fields, MCP mappings, self-contained HTML smoke checks, delegation from CLI.

---

## Design system

All dashboard cards share:

| Token | Value |
|-------|-------|
| Background | `#0b1730` |
| Border radius | 16px |
| Border | `1px solid rgba(255,255,255,.06)` |
| Shadow | `0 8px 32px rgba(0,0,0,.35)` |
| Transition | 200ms hover lift |

Severity cards: **4px top accent**, gradient backgrounds, large numeric counts, footer risk badges.

---

## CDN dependencies

When opened in a browser, the file may fetch:

| Resource | Purpose |
|----------|---------|
| Chart.js | Radar and trend charts |
| Inter font | Typography |

Scan data itself never leaves the file. See [SECURITY.md](../../SECURITY.md).

---

## Planned enhancements

| Feature | Phase | GAP |
|---------|-------|-----|
| Interactive attack-graph UI (force-directed) | 2 | GAP-218 |
| Standalone `mcts trend` CLI | 2 | History embedded in HTML today |
| Diff view vs baseline | 2 | `--baseline` snapshots |
| Credential / blast-radius graph pages | 3 | L7-07 |

See [Feature Expansion Plan — Reporting](../more/feature-expansion-plan.md#reporting-10) and [Roadmap](../more/roadmap.md).

---

## Related

- [CLI Reference — `mcts report`](../platform/cli.md#mcts-report)
- [Scoring Specification](scoring-spec.md)
- [Architecture — Reporting](../analysis/architecture.md#reporting)
- [Getting Started](../get-started/getting-started.md)
