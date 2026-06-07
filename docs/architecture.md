# Architecture

MCTS follows a modular pipeline architecture designed for extensibility.

**Target evolution:** [Feature Expansion Plan — Part 3](feature-expansion-plan.md#part-3--target-architecture)

---

## Current Architecture (Alpha)

```
ScanConfig.target (single Python file)
        │
        ▼
   MCPClient.discover()     ← regex @tool + AST docstrings
        │
        ▼
   MCPServerInfo (tools only)
        │
        ▼
   BaseAnalyzer × 6  →  ComplianceChecker  →  RiskScoringEngine
        │
        ▼
   ScanReport  →  Terminal UI / JSON / HTML dashboard
```

---

## Target Architecture (Planned)

Three-layer pipeline replacing single-file static parse:

```
┌─────────────────────────────────────────────────────────────────┐
│                        ScanTarget                                │
│  file │ directory │ config │ live_command │ remote_url           │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Discovery Layer                              │
│  StaticDiscovery │ LiveDiscovery │ ConfigDiscovery             │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Analysis Layer                               │
│  Metadata │ Source │ Capability │ Chains │ Compliance │ Policy │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Output Layer                                 │
│  JSON │ SARIF │ HTML │ Markdown │ CI gates                       │
└─────────────────────────────────────────────────────────────────┘
```

### Planned package layout

See [Feature Expansion Plan — Part 5](feature-expansion-plan.md#part-5--module-layout-additive).

Key additions: `discovery/`, `probe/`, `inventory/`, `capability/`, `taxonomy/`, `baseline/`, `fuzz/`.

---

## Components (Current)

### Scanner (`core/scanner.py`)

Orchestrates discovery, analyzers, compliance checks, and scoring into a single `ScanReport`.

### MCP Client (`mcp/client.py`)

Performs **static analysis** of Python MCP server source files. Parses `@tool` decorators and AST docstrings.

**Planned:** `discovery/static.py` (repo walk), `discovery/live.py` (`ProbeSession` over stdio/SSE/HTTP), `discovery/config.py` (client config entries).

### Analyzers (`analyzers/`)

Each analyzer implements `BaseAnalyzer.analyze(server) -> list[Finding]`:

| Analyzer | Purpose | Planned upgrade |
|----------|---------|-----------------|
| `PermissionAnalyzer` | Destructive & privileged tools | + capability inference |
| `PromptInjectionAnalyzer` | Injection attack surfaces | Unicode, imperative patterns, drift |
| `ToolAbuseAnalyzer` | Path traversal & misuse | + source path validation |
| `DataLeakageAnalyzer` | Secrets & sensitive data | Scan full repo source, not metadata only |
| `JailbreakAnalyzer` | Agent manipulation resistance | Weighted surface score (not tool count) |
| `AttackChainAnalyzer` | Multi-step attack paths | Capability-graph BFS |

**Planned analyzers:** `SchemaSurfaceAnalyzer`, `CommandExecutionAnalyzer`, `PathValidationAnalyzer`, `MetadataIntegrityAnalyzer`, `ImplementationDriftAnalyzer`, `CrossServerAnalyzer`, `DependencyPostureAnalyzer`.

### Scoring (`scoring/engine.py`)

Exponential security score: `round(100 × e^(-raw_risk/50))`, with `raw_risk` from severity counts (Critical×25, High×10, Medium×3, Low×1). Compliance meta-findings excluded. Every `RiskScore` includes auditable `ScoreBasis`.

**Planned:** Category gates (`--min-score`), published spec in `docs/scoring-spec.md`.

### Terminal UI (`ui/`)

| Path | Role |
|------|------|
| `ui/theme.py` | Color palettes for `cyber`, `minimal`, `github` |
| `ui/logo.py` | Brand PNG (inline image) or ASCII fallback |
| `ui/dashboard.py` | Scan progress, metrics grid, findings panels |
| `ui/layout.py` | Fixed-width terminal layout helpers |

**Planned:** Category scorecard in CLI output.

### Reporting

**Models (`reporting/`)** — Pydantic `ScanReport`, `Finding`, `RiskScore`, JSON from `mcts scan -o`.

**Planned model fields on `Finding`:** `technique_id` (`MCTS-T-*`), `mitigation_ids`, `cwe_id`, `confidence`, `location`.

**HTML dashboard (`report/`)** — Enterprise UI via `mcts report`:

| Path | Role |
|------|------|
| `report/data.py` | Dashboard JSON (scores, OWASP, attack graph, executive summary) |
| `report/generators/html_report.py` | Jinja2 render + inline CSS/JS |
| `report/templates/dashboard.html` | Page structure |
| `report/assets/` | Styles, Chart.js, SVG icons |

**Planned:** Capability Matrix, Technique Map, real trend data from `.mcts/history/`.

**Planned formats:** `reporting/sarif.py`, `reporting/markdown.py`.

**Flow:**

```
mcts scan -o report.json  →  ScanReport (JSON)
mcts report report.json   →  report/data.py → html_report.py → security-report.html
```

### Brand (`brand/`)

Canonical `logo.png` for terminal; `logo-report.png` embedded in HTML.

### Compliance (`compliance/checks.py`)

OWASP LLM mapping. **Planned:** tie to `MCTS-T-*` technique IDs.

---

## Adding Live MCP Probing

1. Implement `ProbeSession` in `probe/session.py` (async, official `mcp` SDK).
2. `LiveDiscovery` returns same `MCPServerInfo` as static path.
3. `Scanner` merges static + live when `--live` or `--config` is set.
4. Consent gate before subprocess spawn; CI uses `--i-understand-live-risk`.
5. Wire fuzz analyzers to `ProbeSession` for `mcts fuzz`.

Detail: [Feature Expansion Plan — 1.1](feature-expansion-plan.md#11-live-mcp-discovery-probesession).

---

## Adding an Analyzer

1. Subclass `BaseAnalyzer` in `analyzers/`.
2. Set `name` and implement `analyze(server: MCPServerInfo) -> list[Finding]`.
3. Register in `core/scanner.py`.
4. Add benchmark fixture in `examples/bench/` with expected findings.
5. Map findings to `technique_id` via `taxonomy/mapper.py` (when shipped).

---

## Related

- [Feature Expansion Plan](feature-expansion-plan.md)
- [Roadmap](roadmap.md)
- [CLI Reference](cli.md)
