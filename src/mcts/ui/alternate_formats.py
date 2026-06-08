"""Alternate terminal report layouts."""

from __future__ import annotations

from collections import defaultdict

from rich.console import Console
from rich.table import Table

from mcts.reporting.models import Finding, ScanReport, Severity


def render_report(
    report: ScanReport,
    fmt: str,
    console: Console,
    *,
    severity_filter: set[Severity] | None = None,
    tool_filter: set[str] | None = None,
    analyzer_filter: set[str] | None = None,
    hide_safe: bool = False,
) -> None:
    findings = _filter_findings(report.findings, severity_filter, tool_filter, analyzer_filter, hide_safe)
    fmt = fmt.lower()
    if fmt == "table":
        _render_table(findings, console)
    elif fmt == "by_tool":
        _render_grouped(findings, console, key=lambda f: f.tool or "(no tool)")
    elif fmt == "by_analyzer":
        _render_grouped(findings, console, key=lambda f: f.analyzer)
    elif fmt == "by_severity":
        _render_grouped(findings, console, key=lambda f: f.severity.value)
    elif fmt == "summary":
        _render_summary(report, findings, console)
    else:
        raise ValueError(f"Unknown terminal format: {fmt}")


def _filter_findings(
    findings: list[Finding],
    severity_filter: set[Severity] | None,
    tool_filter: set[str] | None,
    analyzer_filter: set[str] | None,
    hide_safe: bool,
) -> list[Finding]:
    rows = findings
    if severity_filter:
        rows = [f for f in rows if f.severity in severity_filter]
    if tool_filter:
        rows = [f for f in rows if f.tool and f.tool in tool_filter]
    if analyzer_filter:
        rows = [f for f in rows if f.analyzer in analyzer_filter]
    if hide_safe and not rows:
        return rows
    return rows


def _render_table(findings: list[Finding], console: Console) -> None:
    table = Table(title="MCTS Findings")
    table.add_column("Severity")
    table.add_column("Analyzer")
    table.add_column("Tool")
    table.add_column("Title")
    for f in findings:
        table.add_row(f.severity.value, f.analyzer, f.tool or "-", f.title)
    console.print(table)


def _render_grouped(findings: list[Finding], console: Console, key) -> None:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[key(f)].append(f)
    for group, items in sorted(groups.items()):
        console.print(f"\n[bold]{group}[/bold] ({len(items)})")
        for f in items:
            console.print(f"  [{f.severity.value}] {f.title}")


def _render_summary(report: ScanReport, findings: list[Finding], console: Console) -> None:
    console.print(f"Score: {report.score.overall}/100 — {len(findings)} finding(s)")
    for f in findings[:10]:
        console.print(f"  [{f.severity.value}] {f.title}")
