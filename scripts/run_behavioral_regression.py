#!/usr/bin/env python3
"""Batch behavioral static analysis on example MCP servers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
from mcts.core.config import ScanConfig
from mcts.mcp.client import MCPClient

_DEFAULT_EXAMPLES = (
    "examples/vulnerable-mcp-server/server.py",
    "examples/baseline-mcp-server/server.py",
    "examples/medium-risk-mcp-server/server.py",
)
_VULNERABLE_EXAMPLE = "examples/vulnerable-mcp-server/server.py"


def _default_examples(root: Path) -> list[Path]:
    return [root / rel for rel in _DEFAULT_EXAMPLES]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Run behavioral static analysis on example MCP servers",
    )
    parser.add_argument(
        "--examples",
        action="append",
        type=Path,
        dest="examples",
        help="Example server path (repeatable; default: three bundled examples)",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when the vulnerable example yields no findings or a path is missing",
    )
    parser.add_argument(
        "--min-findings",
        type=int,
        default=None,
        metavar="N",
        help="Exit 1 when total findings across examples is below N",
    )
    parser.add_argument(
        "--min-vulnerable-findings",
        type=int,
        default=1,
        metavar="N",
        help="Exit 1 when vulnerable example findings are below N (default: 1)",
    )
    args = parser.parse_args()

    if args.min_findings is not None and args.min_findings < 0:
        print("--min-findings must be >= 0", file=sys.stderr)
        return 2
    if args.min_vulnerable_findings < 0:
        print("--min-vulnerable-findings must be >= 0", file=sys.stderr)
        return 2

    examples = args.examples if args.examples else _default_examples(root)
    analyzer = BehavioralStaticAnalyzer()
    rows: list[dict] = []
    total = 0
    vulnerable_findings = 0
    failures: list[str] = []

    for path in examples:
        resolved = path if path.is_absolute() else (root / path)
        if not resolved.exists():
            row = {
                "path": str(path),
                "status": "missing",
                "findings_count": 0,
                "findings": [],
            }
            rows.append(row)
            if args.strict:
                failures.append(f"missing example: {path}")
            continue

        server = MCPClient(resolved, ScanConfig(target=resolved)).discover()
        findings = analyzer.analyze(server)
        count = len(findings)
        total += count
        rel = str(resolved.relative_to(root)) if resolved.is_relative_to(root) else str(resolved)
        if rel.replace("\\", "/") == _VULNERABLE_EXAMPLE:
            vulnerable_findings = count
        rows.append(
            {
                "path": rel,
                "status": "ok",
                "findings_count": count,
                "findings": [{"severity": f.severity.value, "title": f.title} for f in findings],
            }
        )
        if not args.json:
            print(f"{resolved.name}: {count} behavioral finding(s)")
            for finding in findings:
                print(f"  - [{finding.severity.value}] {finding.title}")

    if args.strict and vulnerable_findings < args.min_vulnerable_findings:
        failures.append(
            f"vulnerable example findings {vulnerable_findings} "
            f"< {args.min_vulnerable_findings}"
        )
    if args.min_findings is not None and total < args.min_findings:
        failures.append(f"total findings {total} < {args.min_findings}")

    if args.json:
        payload = {
            "total_findings": total,
            "vulnerable_findings": vulnerable_findings,
            "passed": not failures,
            "failures": failures,
            "results": rows,
        }
        print(json.dumps(payload, indent=2))
    elif not args.json:
        print(f"Total findings: {total}")

    if failures:
        for message in failures:
            print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
