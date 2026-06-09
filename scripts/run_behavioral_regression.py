#!/usr/bin/env python3
"""Batch behavioral static analysis on example MCP servers."""

from __future__ import annotations

from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
from mcts.core.config import ScanConfig
from mcts.mcp.client import MCPClient


def main() -> int:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    examples = [
        root / "examples/vulnerable-mcp-server/server.py",
        root / "examples/baseline-mcp-server/server.py",
        root / "examples/medium-risk-mcp-server/server.py",
    ]
    analyzer = BehavioralStaticAnalyzer()
    total = 0
    for path in examples:
        if not path.exists():
            continue
        server = MCPClient(path, ScanConfig(target=path)).discover()
        findings = analyzer.analyze(server)
        total += len(findings)
        print(f"{path.name}: {len(findings)} behavioral finding(s)")
        for f in findings:
            print(f"  - [{f.severity.value}] {f.title}")
    print(f"Total findings: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
