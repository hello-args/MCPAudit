# External Threat Frameworks

> [Documentation](../index.md) → [More](README.md)

MCTS uses a **first-party taxonomy** (`MCTS-T-*` techniques, `MCTS-M-*` mitigations). Industry MCP threat frameworks and Sigma rule corpora inform detection patterns and roadmap priorities but are **not vendored** in this repository.

**Product source of truth:** `src/mcts/taxonomy/techniques.json` · [Threat Taxonomy](../reporting/taxonomy.md)

---

## Framework vs scanner

| Dimension | External threat framework | MCTS |
|-----------|---------------------------|------|
| **What it is** | Threat intelligence catalog | Automated MCP security scanner |
| **Primary output** | Technique dossiers, Sigma YAML, mitigations | Findings, scores, JSON/SARIF/HTML |
| **Execution** | Reference artifacts and documentation | CLI: `mcts scan`, `inventory`, `fuzz` |
| **Answers** | "What attacks exist and how do they work?" | "Does my server/config exhibit this risk?" |

They are **complementary**: frameworks describe the threat space; MCTS operationalizes detection for MCP server authors at build and deploy time.

```
   Industry threat taxonomy
   (techniques, Sigma rules, mitigations)
              │
    patterns adapted into MCTS modules
              │
              ▼
         MCTS scan pipeline
              │
              ▼
   Findings with MCTS-T-* / MCTS-M-* IDs
```

---

## MCTS reports use native IDs only

Scan output emits:

| Field | Format |
|-------|--------|
| `technique_id` | MCTS-T-* |
| `mitigation_ids` | MCTS-M-* list |
| `cwe_id` | CWE when mapped in catalog |

External technique IDs (from third-party corpora) are **never** written to findings. Maintainers may use informal crosswalks internally during gap analysis — those crosswalks are not part of the public report schema.

---

## Pattern adoption in MCTS

Detection patterns from industry reference corpora were adapted into MCTS-owned modules:

| Threat area | MCTS modules | Status |
|-------------|--------------|--------|
| TPA / metadata poisoning | `tpa_patterns.py`, `prompt_injection`, `metadata_integrity`, `sigma_metadata` | Shipped |
| Homoglyph, Unicode tag block, mixed-script | `tpa_patterns.py` | Shipped |
| Recursive schema / FSP | `schema_fsp.py`, `schema_surface.py` | Shipped |
| Credential regex + semantic secrets | `data_leakage.py`, `embedding_secrets.py` | Shipped |
| Path traversal encodings | `path_traversal.py`, fuzz payloads | Shipped |
| Sigma metadata rules | `taxonomy/sigma/metadata_rules.json`, `--sigma-rules-path` | Shipped |
| OAuth misconfiguration | `oauth_config.py`, runtime OAuth cluster | Shipped |
| Rug pull / redefinition | `metadata_diff.py`, `tool_redefinition.py`, `--baseline` | Shipped |
| Supply chain signals | `supply_chain.py` | Partial |
| Cross-server escalation | `cross_server.py` | Shipped |
| Protocol robustness | `fuzz/`, MCTS-T-1009 | Shipped |
| Regression fixtures | `tests/fixtures/regression/MCTS-T-*/` | Shipped (34+ IDs) |

When adapting external Sigma rules:

1. Attribute upstream per license terms in commit messages or rule metadata
2. Ship compiled rules under MCTS-owned paths only (`taxonomy/sigma/`, custom `--sigma-rules-path`)
3. Map to MCTS-T ID before exposing in reports

---

## Static vs runtime detection

| Layer | MCTS capability | Typical external rule type |
|-------|-----------------|----------------------------|
| **Static** | Source + tool metadata at scan time | Metadata poisoning, schema rules |
| **Live probe** | Runtime listings via stdio | Tool manifest verification |
| **Fuzz telemetry** | Protocol response analysis | Error handling, crash detection |
| **Runtime events file** | Imported probe logs | OAuth, rug-pull, behavioral |

Many industry Sigma rules assume **runtime telemetry** (`tool_description`, `path`, `oauth_token`, invocation logs). MCTS primarily performs **pre-deployment static analysis** plus optional live/fuzz layers.

Both are valid; they are not drop-in substitutes. Runtime rules must be adapted to metadata and source context when porting patterns into MCTS analyzers.

---

## Gap analysis workflow for maintainers

When evaluating a new external technique dossier:

1. **Identify MCP boundary relevance** — does it affect tool metadata, schemas, handlers, or protocol?
2. **Classify detection layer** — static, live, fuzz, or runtime events?
3. **Assign or create MCTS-T ID** — update `techniques.json`
4. **Implement analyzer or extend existing** — register in `core/scanner.py`
5. **Add regression fixture** — `tests/fixtures/regression/MCTS-T-<id>/`
6. **Document** — update [Threat Taxonomy](../reporting/taxonomy.md)

---

## Roadmap priorities from threat density

Technique density in industry catalogs suggests MCTS expansion order:

| Priority cluster | MCTS modules / plans |
|------------------|---------------------|
| Initial Access + Execution | TPA, prompt injection, OAuth, command execution |
| Privilege Escalation | Permissions, attack chains, cross-server |
| Persistence | Rug-pull, metadata diff, baseline workflows |
| Exfiltration | Data leakage, attack chains read→egress |
| Advanced runtime | Behavioral probe, deeper fuzz, SSE/HTTP transports |

See [Feature Expansion Plan](feature-expansion-plan.md) Part 4 for phased delivery.

---

## Maintainer gap review (local only)

When evaluating new MCP security capabilities, maintainers run a structured gap review against the [Feature Expansion Plan](feature-expansion-plan.md) backlog. Detailed cross-tool file mappings and ecosystem matrices stay in a **local-only** audit — not published in this repository.

Workflow:

1. Map capability → MCTS module or GAP theme
2. Assign priority (P0–P3) using [Part 11](feature-expansion-plan.md#part-11--prioritized-backlog)
3. Implement with MCTS-T IDs — never vendor third-party IDs in SARIF
4. Add regression fixture when detection lands

**Do not** copy external rule corpora or cloud-only flows into core OSS. Prefer SARIF/event export for runtime gateway partners.

---

## What not to port blindly

| External artifact | Why caution |
|-------------------|-------------|
| Runtime Sigma rules on static-only repos | Log field names do not exist in source scans |
| Behavioral demo thresholds | Tuned for conversation logs, not tool manifests |
| Attack PoC scripts | Use as test vectors only — do not bundle into scanner |
| Immature technique drafts | Wait for stable definitions before MCTS-T promotion |
| Vendor-specific IDs in SARIF | Use MCTS-T only for consistent CI aggregation |

---

## Licensing and attribution

External Sigma rules and technique text may carry distinct licenses (e.g. Detection Copyright, CC BY-SA). MCTS ships **adapted** detection logic under the project Apache 2.0 license where original expression is not copied verbatim. When importing rule YAML, preserve required attribution comments in the rule file header.

---

## Related

- [Threat Taxonomy](../reporting/taxonomy.md)
- [Product Positioning](product-positioning.md)
- [Architecture — Taxonomy](../analysis/architecture.md#taxonomy-taxonomy)
- [Feature Expansion Plan](feature-expansion-plan.md)
