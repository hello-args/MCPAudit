# Protocol Fuzzing

> [Documentation](../index.md) → [Scanning](README.md)

MCTS protocol fuzzing sends **deterministic JSON-RPC probes** to a live stdio MCP server. It tests parser robustness, error handling, and information disclosure — without destructive payloads at default settings.

Fuzz output includes structured **findings** and **runtime_events** that can be replayed into a full `mcts scan` for `RuntimeEventsAnalyzer` and taxonomy enrichment.

**Implementation:** `fuzz/runner.py`, `fuzz/payloads.py`, `fuzz/classifier.py`

---

## Design philosophy

1. **Safe by default** — `safe` level never calls `tools/call`
2. **Explicit consent tiers** — live subprocess + optional aggressive invocation
3. **Deterministic probes** — reproducible CI signals, not random mutation
4. **Pipeline integration** — fuzz JSON feeds `--runtime-events` on scan

---

## Fuzz levels

| Level | Probes include | MCP methods touched | Tool invocation |
|-------|----------------|---------------------|-----------------|
| **safe** (default) | Malformed JSON, bad initialize, unknown methods, duplicate `tools/list` | Read-only / protocol edge cases | None |
| **standard** | safe + `resources/read` traversal URIs, `prompts/get` injection names | Read-only resource/prompt APIs | None |
| **aggressive** | standard + `tools/call` fuzz on discovered tool names | May invoke tools with test payloads | Requires `--i-understand-fuzz-risk` |

Level selection: `--fuzz-level safe|standard|aggressive` → `FuzzLevel` enum in `fuzz/payloads.py`.

### Example safe probes

| Probe ID | What it sends | What it tests |
|----------|---------------|---------------|
| `malformed-json` | Invalid JSON on stdin | Parser crash / stack trace leak |
| `missing-method` | JSON-RPC without `method` | Error handling |
| `invalid-method` | Unknown method name | Should return JSON-RPC error |
| `bad-init-version` | Invalid `protocolVersion` on initialize | Version negotiation |
| `oversized-payload` | Very large string fields | DoS / buffer behavior |
| `duplicate-tools-list` | Repeated `tools/list` | State consistency |

Standard level adds URI traversal patterns on `resources/read` and malicious prompt names on `prompts/get`. Aggressive level synthesizes `tools/call` requests per discovered tool.

---

## Usage

```bash
uv sync --extra mcp

# Safe read-only (recommended for CI)
mcts fuzz examples/live-mcp-server/server.py \
  --fuzz-level safe \
  --i-understand-live-risk

# Standard — read-only resource/prompt probes
mcts fuzz examples/live-mcp-server/server.py \
  --fuzz-level standard \
  --i-understand-live-risk

# Aggressive — may invoke tools
mcts fuzz examples/live-mcp-server/server.py \
  --fuzz-level aggressive \
  --i-understand-live-risk \
  --i-understand-fuzz-risk

# Custom launch
mcts fuzz ./server.py --command uv --args run,server.py \
  --fuzz-level safe --i-understand-live-risk

# From client config
mcts fuzz . --config ~/.cursor/mcp.json --server my-server \
  --fuzz-level safe --i-understand-live-risk -o fuzz.json
```

---

## Consent

| Flag / env | Required for |
|------------|--------------|
| `--i-understand-live-risk` | Starting any fuzz session (subprocess) |
| `MCTS_LIVE_OK=1` | CI bypass for live consent |
| `--i-understand-fuzz-risk` | **aggressive** level only |

Without live consent, exit code **2**. Without fuzz-risk consent on aggressive, exit code **2**.

---

## Output format

Write results with `-o fuzz.json`:

```json
{
  "target": "examples/live-mcp-server/server.py",
  "fuzz_level": "safe",
  "probes_run": 12,
  "runtime_events": [
    {
      "event_type": "fuzz_probe",
      "probe_id": "malformed-json",
      "severity_hint": "medium"
    }
  ],
  "findings": [
    {
      "id": "...",
      "analyzer": "fuzz",
      "title": "Stack trace in JSON-RPC error response",
      "severity": "high",
      "technique_id": "MCTS-T-1009"
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `probes_run` | Count of executed probe cases |
| `runtime_events` | Rows for `RuntimeEventsAnalyzer` via `--runtime-events` |
| `findings` | Taxonomy-enriched fuzz findings (`analyzer: fuzz`) |

---

## Scan pipeline integration

```bash
# Step 1: Fuzz
mcts fuzz ./server.py --i-understand-live-risk -o fuzz.json

# Step 2: Full scan with telemetry replay
mcts scan ./server.py --runtime-events fuzz.json -o report.json

# Step 3: Optional HTML dashboard
mcts report report.json -o security-report.html
```

`events_from_fuzz_findings()` in `analyzers/runtime_events.py` converts fuzz output into runtime event rows.

---

## Finding classifications

`fuzz/classifier.py` categorizes server responses:

| Classification | Severity tendency | Meaning |
|----------------|-------------------|---------|
| Stack trace leaked | High | Internal paths or exceptions in response |
| Path or secret echo | High | Sensitive data reflected in error |
| Dangerous success | Medium–High | Malformed input accepted without error |
| Server crash / hang | Critical | Subprocess died or timed out |
| Clean rejection | None | Expected JSON-RPC error — no finding |

Findings receive **MCTS-T-1009** (Protocol Fuzzing Exposure) and standard `mitigation_ids` via `taxonomy/mapper.py`.

---

## Exit codes

| Code | When |
|------|------|
| 0 | No critical/high findings |
| 1 | Any **critical** or **high** fuzz finding |
| 2 | Consent error, bad level, launch failure |

---

## CI recommendation

Use **safe** level on trusted fixture servers only:

```yaml
- name: Protocol fuzz (safe)
  env:
    MCTS_LIVE_OK: "1"
  run: |
    mcts fuzz ./examples/live-mcp-server/server.py \
      --fuzz-level safe --i-understand-live-risk -o fuzz.json
    mcts scan ./examples/live-mcp-server/server.py \
      --runtime-events fuzz.json --no-progress -o report.json
```

Never run **aggressive** fuzz against production or third-party servers.

---

## Planned fuzz capabilities

| Capability | Status | GAP | Notes |
|------------|--------|-----|-------|
| Remote protocol fuzz (`mcts fuzz --url`) | Planned | GAP-190 | HTTP/SSE targets |
| WebSocket MCP transport fuzz | Missing | GAP-187 | WebSocket transport coverage |
| Docker MCP server auto-detection | Missing | GAP-188 | Container-launched servers |
| Deeper aggressive corpus | Partial | GAP-186 | Expanded dynamic analyzer corpus |

See [Feature Expansion Plan — Fuzzing](../more/feature-expansion-plan.md#fuzzing-4).

---

## Related

- [Live Scanning](live-scanning.md)
- [CLI Reference — mcts fuzz](../platform/cli.md#mcts-fuzz)
- [Architecture — Fuzzing](../analysis/architecture.md#fuzzing-fuzz)
- [Threat Taxonomy — MCTS-T-1009](../reporting/taxonomy.md)
