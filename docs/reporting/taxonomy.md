# MCTS Threat Taxonomy

> [Documentation](../index.md) → [Reporting](README.md)

MCTS labels every finding with a **technique ID** (`MCTS-T-*`) and links it to **mitigation IDs** (`MCTS-M-*`). This gives your findings consistent, trackable names instead of free-form descriptions.

> **Just want to see what checks run?** See [Security Checks](../analysis/security-checks.md).
> **Unfamiliar with technique IDs?** See the [Glossary](../glossary.md).

---

## In plain English

When MCTS finds a problem, it tags it with a standard ID like `MCTS-T-1003` (command execution) or `MCTS-T-1001` (description poisoning). These IDs:

- Make findings **searchable and filterable** across scans and teams
- Link to **recommended mitigations** (`MCTS-M-*`)
- Map to **industry standards** (CWE, OWASP LLM Top 10) for compliance reporting
- Appear in SARIF and HTML reports with documentation links

You don't need to memorize these IDs — they appear automatically on every finding. This document is the reference catalog.

**Source of truth:** `src/mcts/taxonomy/techniques.json`

---

## How enrichment works

1. Analyzers emit findings with optional `technique_id`
2. `enrich_findings()` looks up technique metadata in `techniques.json`
3. Matching mitigations (whose `techniques` array includes the ID) attach as `mitigation_ids`
4. Missing IDs may be inferred from analyzer name → catalog mapping
5. URLs generated for HTML/SARIF: `https://github.com/MCP-Audit/MCTS/blob/main/docs/reporting/taxonomy.md`
6. **Crosswalk** — `taxonomy/crosswalk.json` adds interoperable IDs to `finding.evidence`:
   - `aitech` / `aisubtech` — Cisco AI Threat Taxonomy

Fuzz and inventory findings go through the same pipeline.

### Crosswalk example

```json
{
  "technique_id": "MCTS-T-1001",
  "evidence": {
    "aitech": "AITech-PAI",
    "aisubtech": "AISubtech-PAI-001"
  }
}
```

Extend `src/mcts/taxonomy/crosswalk.json` when mapping new techniques to external frameworks.

---

## Core technique IDs (MCTS-T-*)

| ID | Name | Primary analyzers | Severity typical |
|----|------|-------------------|------------------|
| MCTS-T-1001 | Tool Description Poisoning | `prompt_injection`, `metadata_integrity` | High–Critical |
| MCTS-T-1001.002 | Schema Surface Poisoning (FSP) | `schema_surface` | High |
| MCTS-T-1002 | Path Traversal / Missing Validation | `path_validation`, `tool_abuse` | High |
| MCTS-T-1003 | Command Execution via Tool Handler | `command_execution` | Critical |
| MCTS-T-1004 | Sensitive Data Exposure | `data_leakage` | High |
| MCTS-T-1005 | Multi-Step Attack Chain | `attack_chains` | Critical (meta-rows displayed; excluded from v2 `absolute_risk` sum — chain signal is `chain_factor` on tool findings) |
| MCTS-T-1006 | Excessive Tool Permissions | `permission_analyzer` | Critical |
| MCTS-T-1007 | Tool Output Prompt Injection | `jailbreak`, `runtime_events` | High |
| MCTS-T-1008 | Cross-Server Tool Shadowing | `cross_server` | High |
| MCTS-T-1009 | Protocol Fuzzing Exposure | `fuzz`, `runtime_events` | Medium–High |
| MCTS-T-1010 | Sigma Metadata Rule Match | `sigma_metadata` | Varies |
| MCTS-T-1011–1019 | OAuth / token escalation family | `oauth_config`, `runtime_events` | High–Critical |
| MCTS-T-1020 | Tool Shadowing Attack | `tool_shadowing` | High |
| MCTS-T-1021 | Line Jumping / Context Precedence | `line_jumping` | Medium–High |
| MCTS-T-1022 | Semantic Credential Exposure | `embedding_secrets` | High |
| MCTS-T-1023–1039 | Runtime telemetry techniques | `runtime_events` | Varies |
| MCTS-T-1040 | Persistent Tool Redefinition | `metadata_diff`, `runtime_events` | Critical |
| MCTS-T-1041 | Instruction Steganography | `runtime_events`, `instruction_steganography` | High |

Inspect catalog size:

```bash
uv run python -c "from mcts.taxonomy.mapper import technique_catalog; print(len(technique_catalog()))"
```

---

## Runtime event techniques (MCTS-T-1023+)

`RuntimeEventsAnalyzer` routes telemetry rows to focused detectors:

| Detector module | Example technique | Trigger |
|-----------------|-------------------|---------|
| `autonomous_loop.py` | MCTS-T-1035 | Repeated identical tool invocations |
| `command_injection.py` | MCTS-T-1023 | Injection patterns in event payloads |
| `oauth_mixup.py` | MCTS-T-1012 | OAuth redirect / client confusion |
| `rug_pull.py` | MCTS-T-1013 | Metadata drift vs baseline |
| `behavioral_extraction.py` | MCTS-T-1026 | Multi-turn extraction probe |
| `credential_access.py` | MCTS-T-1024 | Sensitive credential file access |
| `tool_redefinition.py` | MCTS-T-1040 | Tool schema changed between sessions |
| `over_privileged.py` | MCTS-T-1006 | Over-privileged process activity |
| `exposed_endpoint.py` | MCTS-T-1027 | Exposed MCP endpoint access |
| `dns_poisoning.py` | MCTS-T-1028 | DNS or certificate poisoning |
| `tool_output_injection.py` | MCTS-T-1007 | Prompt injection in tool output |
| `cross_server_registry.py` | MCTS-T-1029 | Cross-server tool shadowing |
| `privilege_tool_abuse.py` | MCTS-T-1030 | High-privilege tool execution |
| `suspicious_registration.py` | MCTS-T-1031 | Suspicious tool registration |
| `fake_tool_invocation.py` | MCTS-T-1032 | Spoofed tool invocation |
| `sandbox_escape.py` | MCTS-T-1033 | Container sandbox escape |
| `oauth_escalation_runtime.py` | MCTS-T-1017–1019 | Rogue AS, confused deputy, scope substitution |
| `instruction_steganography.py` | MCTS-T-1041 | Hidden instructions in metadata |
| `vector_poisoning.py` | MCTS-T-1034 | Vector store contamination |
| `inspector_rce.py` | MCTS-T-1036 | MCP Inspector RCE attempt |
| `oauth_token_persistence.py` | MCTS-T-1037 | Token persistence after logout |
| `backdoored_install.py` | MCTS-T-1038 | Install-time persistence |
| `context_memory_implant.py` | MCTS-T-1039 | Context memory implant |
| `sampling_abuse.py` | MCTS-T-1016 | Sampling API abuse |

### Event sources

| Source | How attached |
|--------|--------------|
| `--runtime-events` file | CLI loads JSON array into `ScanConfig` |
| `--live` probe | `probe/events.py` normalizes listings |
| `--behavioral-probe` | `probe/behavioral.py` generates rows |
| `mcts fuzz` | `events_from_fuzz_findings()` in output JSON |

---

## Mitigation IDs (MCTS-M-*)

Twenty-five mitigations (`MCTS-M-001` … `MCTS-M-025`) map to one or more techniques. The mapper attaches all mitigations whose `techniques` list includes the finding's `technique_id`.

Example mitigations (see `techniques.json` for full list):

| ID | Theme |
|----|-------|
| MCTS-M-001 | Tool description validation |
| MCTS-M-010 | Schema input validation |
| MCTS-M-015 | OAuth client binding |
| MCTS-M-025 | Semantic secret scanning (`--semantic-secrets`) |

HTML **Recommendations** page groups findings by mitigation priority.

---

## Sigma rule IDs

Bundled metadata rules: `src/mcts/taxonomy/sigma/metadata_rules.json`

When `sigma_metadata` matches a rule, findings reference the corresponding **MCTS-T-*** technique ID. All bundled Sigma rules now have runtime analyzer coverage.

### Custom Sigma rules

```bash
mcts scan ./repo/ --sigma-rules-path ./my-rules/
```

Expected layout:

```
my-rules/
└── MCTS-T-1001/
    └── detection-rule.yml
```

Rules are deduplicated via `analyzers/sigma_dedupe.py` when multiple patterns hit the same tool.

---

## Analyzer → technique quick reference

| Analyzer key | Common techniques |
|--------------|-------------------|
| `permission_analyzer` | MCTS-T-1006 |
| `metadata_integrity` | MCTS-T-1001 |
| `schema_surface` | MCTS-T-1001.002 |
| `command_execution` | MCTS-T-1003 |
| `data_leakage` | MCTS-T-1004 |
| `attack_chains` | MCTS-T-1005 |
| `cross_server` | MCTS-T-1008 |
| `fuzz` | MCTS-T-1009 |
| `metadata_diff` | MCTS-T-1013, MCTS-T-1040 |
| `embedding_secrets` | MCTS-T-1022 |
| `oauth_config` | MCTS-T-1011–1019 |

---

## Regression fixtures

| Asset | Purpose |
|-------|---------|
| `tests/fixtures/regression/MCTS-T-*/` | 79 technique regression cases |
| `src/mcts/testing/regression_harness.py` | CI enforces ≥80% detector accuracy |
| `tests/fixtures/sigma_fixtures/` | Sigma rule validation |

When adding techniques, add a fixture directory matching the ID.

### Planned taxonomy expansion (gap audit)

| Capability | Status | GAP | Notes |
|------------|--------|-----|-------|
| Full bundled Sigma rules in regression | Partial | GAP-137–141 | 85+ fixtures today |
| External mitigation dossiers | Partial | GAP-138 | `mitigation_urls.py` links only |
| Portable technique YAML packs | Missing | GAP-142 | Custom rule pack format |
| Dual E/W/X/TF code option | Missing | GAP-127 | Alongside MCTS-T |
| OWASP MCP Top 10 full 10/10 map | Shipped | GAP-230 | MCP01–MCP10 compliance meta-findings |
| Letter grade A–F | Shipped | GAP-234 | `score.grade` in JSON/HTML |
| MITRE ATLAS mapping | Missing | L6-04 | Framework mapping |

See [Feature Expansion Plan — Taxonomy](../more/feature-expansion-plan.md#taxonomy-8).

---

## SARIF and HTML integration

- SARIF `ruleId` maps to `technique_id` when present
- HTML findings table links technique IDs to GitHub doc URLs
- OWASP mapping is separate (compliance layer) — see [Scoring Spec](scoring-spec.md)

---

## Related

- [Architecture — Taxonomy](../analysis/architecture.md#taxonomy-taxonomy)
- [CLI — sigma and semantic flags](../platform/cli.md#mcts-scan)
- [External Frameworks](../more/external-frameworks.md)
- [Scoring Spec](scoring-spec.md)
