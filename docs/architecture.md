# Architecture

MCTS follows a modular **discover → analyze → score → report** pipeline. The scanner orchestrates static and optional live discovery, runs a registry of security analyzers, applies compliance checks and taxonomy enrichment, and emits JSON/SARIF/terminal/HTML output.

**Planning docs:** [Feature Expansion Plan](feature-expansion-plan.md) · [Roadmap](roadmap.md)

---

## Scan pipeline (current)

```
ScanConfig (CLI → core/config.py)
        │
        ▼
┌─────────────────── Discovery ───────────────────┐
│  StaticDiscovery (Python)  ─┐                   │
│  JsStaticDiscovery (TS/JS) ─┼─ merge (repo)     │
│  LiveDiscovery (stdio MCP) ─┘   optional --live │
└───────────────────────┬─────────────────────────┘
                        ▼
              MCPServerInfo
         (tools, schemas, source snippets,
          runtime_events, discovery_mode)
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   19 analyzers   ComplianceChecker   enrich_findings
   (see table)     (OWASP meta)        (MCTS-T / MCTS-M)
        │               │               │
        └───────────────┴───────────────┘
                        ▼
              RiskScoringEngine → ScanReport
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
  Terminal UI      JSON / SARIF    mcts report → HTML
  (Rich dashboard)
```

### Target kinds (`core/target.py`)

| Kind | Example | Discovery |
|------|---------|-----------|
| File | `./server.py`, `./src/index.ts` | Single-language static |
| Directory | `./my-mcp-repo/` | Walk repo; Python + TS/JS merge |
| Config | `.` + `--config` + `--server` | Launch from client MCP JSON |

---

## Discovery layer (`discovery/`)

| Module | Role |
|--------|------|
| `static.py` | Python: `@tool` decorators, AST docstrings, `input_schema`, handler snippets, source locations |
| `static_js.py` | TypeScript/JavaScript: `registerTool`, `server.tool`, legacy `setRequestHandler` — see [typescript-discovery.md](typescript-discovery.md) |
| `static_runner.py` | Orchestrates languages from `ScanConfig.languages` (default: `python`, `typescript`) |
| `static_merge.py` | Merges multi-language tool lists (richest schema wins) |
| `live.py` | Stdio MCP probe: `list_tools`, prompts, resources, server instructions |
| `live_config.py` | Resolves launch command from client config |
| `merge.py` | Merges static + live `MCPServerInfo` when `--live` and source exists |
| `config.py` | Parses MCP client config entries |

**Live probing** requires the `mcp` extra and explicit consent. See [live-scanning.md](live-scanning.md).

**Runtime telemetry:** `--runtime-events` JSON and auto-generated events from `--live` / `--behavioral-probe` / `mcts fuzz` are attached to `MCPServerInfo.runtime_events` before analyzers run.

---

## Probe layer (`probe/`)

| Module | Role |
|--------|------|
| `session.py` | Async stdio `ProbeSession` (official MCP SDK) |
| `consent.py` | `--i-understand-live-risk` / `MCTS_LIVE_OK=1` gate |
| `events.py` | Normalizes live server metadata into runtime event rows |
| `behavioral.py` | Multi-turn MCTS-T-1026 behavioral probe events |

---

## Scanner (`core/scanner.py`)

`Scanner.run()`:

1. `MCPClient.discover()` → `MCPServerInfo`
2. Merge runtime events (file, live, behavioral probe)
3. Run enabled analyzers; dedupe Sigma matches; enrich with taxonomy
4. `ComplianceChecker.check()` → meta-findings (excluded from score)
5. `RiskScoringEngine.score()` with integrity verification
6. Optional baseline snapshot via `--save-baseline`

Conditional analyzers:

| Analyzer | Enabled when |
|----------|--------------|
| `JailbreakAnalyzer` | `enable_jailbreak` (default on) |
| `AttackChainAnalyzer` | `enable_attack_chains` (default on) |
| `MetadataDiffAnalyzer` | `--baseline` provided |
| `EmbeddingSecretsAnalyzer` | `--semantic-secrets` |

---

## Analyzers (`analyzers/`)

Each analyzer implements `BaseAnalyzer.analyze(server: MCPServerInfo) -> list[Finding]`.

| Analyzer | Focus | Technique IDs (examples) |
|----------|-------|--------------------------|
| `PermissionAnalyzer` | Destructive / over-privileged tools | MCTS-T-1006 |
| `MetadataIntegrityAnalyzer` | Description poisoning | MCTS-T-1001 |
| `PromptInjectionAnalyzer` | Injection surfaces in metadata | MCTS-T-1001 |
| `ToolShadowingAnalyzer` | Shadow / duplicate tool names | MCTS-T-1020 |
| `LineJumpingAnalyzer` | Context precedence attacks | MCTS-T-1021 |
| `ToolAbuseAnalyzer` | Path traversal & misuse metadata | MCTS-T-1002 |
| `SchemaSurfaceAnalyzer` | Full Schema Poisoning (FSP) | MCTS-T-1001.002 |
| `DataLeakageAnalyzer` | Secrets in source + metadata | MCTS-T-1004 |
| `CommandExecutionAnalyzer` | Shell/exec in handlers | MCTS-T-1003 |
| `PathValidationAnalyzer` | Missing path checks in code | MCTS-T-1002 |
| `RuntimeEventsAnalyzer` | Telemetry + schema invocation surfaces | MCTS-T-1023–1041 |
| `SigmaMetadataAnalyzer` | Bundled + custom Sigma YAML rules | MCTS-T-1010, MCTS-S-* |
| `OAuthConfigAnalyzer` | OAuth misconfiguration in source/config | MCTS-T-1011–1019 |
| `SupplyChainAnalyzer` | Dependency posture signals | — |
| `EmbeddingSecretsAnalyzer` | Semantic credential detection (opt-in) | MCTS-T-1022 |
| `MetadataDiffAnalyzer` | Rug-pull baseline diff (opt-in) | MCTS-T-1013, MCTS-T-1040 |
| `JailbreakAnalyzer` | Agent manipulation resistance | MCTS-T-1007 |
| `CrossServerAnalyzer` | Cross-server tool shadowing | MCTS-T-1008 |
| `AttackChainAnalyzer` | Capability-graph multi-step chains | MCTS-T-1005 |

`RuntimeEventsAnalyzer` delegates to focused detectors (`oauth_mixup`, `command_injection`, `rug_pull`, `behavioral_extraction`, etc.) under `analyzers/`.

Findings include `technique_id`, `mitigation_ids`, `cwe_id`, `confidence`, and `location` when available. See [taxonomy.md](taxonomy.md).

---

## Fuzzing (`fuzz/`)

Separate command path: `FuzzRunner` → protocol probes → findings + `runtime_events` JSON.

Pipe fuzz output into a full scan:

```bash
mcts fuzz ./server.py --i-understand-live-risk -o fuzz.json
mcts scan ./server.py --runtime-events fuzz.json
```

See [fuzzing.md](fuzzing.md).

---

## Inventory (`inventory/`)

`mcts inventory` walks known client config paths (Cursor, Claude, VS Code, Windsurf), parses `mcpServers`, and optionally static-scans each entry with `--scan`. `CrossServerAnalyzer.analyze_inventory()` flags tool name collisions across servers.

See [inventory.md](inventory.md).

---

## Scoring (`scoring/engine.py`)

- **Raw risk:** Critical×25 + High×10 + Medium×3 + Low×1 (compliance findings excluded)
- **Overall score:** `round(100 × e^(-raw_risk/50))` — higher is better
- **Risk index:** `min(100, raw_risk)` — higher is worse
- **Category scores:** per-analyzer buckets for dashboard and `--fail-on-category` gates

Full spec: [scoring-spec.md](scoring-spec.md).

---

## Reporting

### Models (`reporting/`)

Pydantic `ScanReport`, `Finding`, `RiskScore`, `ScoreBasis`. JSON from `mcts scan -o`. SARIF via `reporting/sarif.py`.

### Terminal UI (`ui/`)

| Path | Role |
|------|------|
| `theme.py` | `cyber`, `minimal`, `github` palettes |
| `progress.py` | Pre-scan animation |
| `dashboard.py` | Metrics grid, category breakdown, findings panels |
| `report_renderer.py` | Full dashboard assembly |

### HTML dashboard (`report/`)

`mcts report report.json` → Jinja2 template + inline CSS/JS. See [html-report.md](html-report.md).

```
mcts scan -o report.json  →  ScanReport (JSON)
mcts report report.json   →  report/data.py → html_report.py → security-report.html
```

---

## Taxonomy (`taxonomy/`)

- `techniques.json` — MCTS-T technique catalog
- `mapper.py` — attaches `technique_id`, `mitigation_ids`, URLs on findings
- `sigma/` — bundled metadata Sigma rules + optional `--sigma-rules-path` YAML

---

## Package layout

```
src/mcts/
├── cli/           # Typer: scan, report, inventory, fuzz, pentest (stub)
├── core/          # Scanner, ScanConfig, ScanTarget
├── discovery/     # Static (Py/TS), live, merge
├── probe/         # Live stdio session, consent, behavioral events
├── analyzers/     # Security analyzers + runtime detectors
├── capability/    # Per-tool capability inference (attack chains)
├── inventory/     # Client config discovery
├── fuzz/          # Protocol fuzz runner
├── scoring/       # RiskScoringEngine
├── compliance/    # OWASP LLM checks
├── reporting/     # Models, SARIF, HTML entry
├── report/        # HTML dashboard templates/assets
├── taxonomy/      # MCTS-T/M, Sigma rules
├── testing/       # Regression harness (34+ technique fixtures)
└── ui/            # Rich terminal dashboard
```

---

## Adding an analyzer

1. Subclass `BaseAnalyzer` in `analyzers/`.
2. Set `name` and implement `analyze(server: MCPServerInfo) -> list[Finding]`.
3. Register in `core/scanner.py` `self.analyzers`.
4. Map findings to `technique_id` (auto-enriched via `taxonomy/mapper.py` when catalogued).
5. Add regression fixture under `tests/fixtures/regression/MCTS-T-*/` when applicable.

---

## Planned evolution

Still on the roadmap (not yet shipped):

- SSE/HTTP live transports
- `mcts audit-config`, `mcts simulate`, `mcts pentest`, `mcts vet`
- Scan history / trend (`.mcts/history/`)
- HTML Capability Matrix + Technique Map from full taxonomy
- Optional tree-sitter depth for TypeScript handlers

See [roadmap.md](roadmap.md) and [feature-expansion-plan.md](feature-expansion-plan.md).

---

## Related

- [CLI Reference](cli.md)
- [Live Scanning](live-scanning.md)
- [Scoring Spec](scoring-spec.md)
- [CI Integration](ci-integration.md)
