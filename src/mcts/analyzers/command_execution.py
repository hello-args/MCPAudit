"""Command execution detection in tool handlers."""

from __future__ import annotations

import ast

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity, SourceLocation
from mcts.scoring.evidence_tags import tag_command_execution_finding

DANGEROUS_CALLS: dict[str, tuple[str, Severity]] = {
    "subprocess": ("subprocess invocation", Severity.CRITICAL),
    "os.system": ("os.system call", Severity.CRITICAL),
    "eval": ("eval() call", Severity.CRITICAL),
    "exec": ("exec() call", Severity.CRITICAL),
}


class CommandExecutionAnalyzer(BaseAnalyzer):
    """Detects shell/command execution in MCP tool handler source."""

    name = "command_execution"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            findings.extend(self._analyze_tool(tool, server.source_files))
        return [tag_command_execution_finding(f) for f in findings]

    def _analyze_tool(self, tool: MCPTool, source_files: dict[str, str]) -> list[Finding]:
        if not tool.source_file or tool.source_file not in source_files:
            if tool.handler_snippet:
                return self._findings_from_snippet(tool, tool.handler_snippet)
            return []

        source = source_files[tool.source_file]
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return self._findings_from_snippet(tool, tool.handler_snippet or source)

        findings: list[Finding] = []
        func_node = _find_function(tree, tool.name)
        if func_node is None:
            return self._findings_from_snippet(tool, tool.handler_snippet or source)

        for node in ast.walk(func_node):
            call_label = _classify_call(node)
            if call_label is None:
                continue
            label, severity = DANGEROUS_CALLS[call_label]
            line = getattr(node, "lineno", tool.source_line)
            findings.append(
                Finding(
                    id=f"cmd-{tool.name}-{call_label.replace('.', '-')}",
                    analyzer=self.name,
                    title=f"Command execution in {tool.name}: {label}",
                    description=f"Tool handler uses {label}, enabling arbitrary command execution.",
                    severity=severity,
                    tool=tool.name,
                    recommendation="Remove shell execution; use allowlisted subprocess with argument lists.",
                    technique_id="MCTS-T-1003",
                    confidence=0.7,
                    location=SourceLocation(file=tool.source_file, line=line),
                    evidence={"call": call_label, "line": line},
                )
            )
        return findings

    def _findings_from_snippet(self, tool: MCPTool, snippet: str) -> list[Finding]:
        findings: list[Finding] = []
        for call, (label, severity) in DANGEROUS_CALLS.items():
            if call.replace(".", "") in snippet.replace(".", "") or call in snippet:
                findings.append(
                    Finding(
                        id=f"cmd-{tool.name}-{call.replace('.', '-')}",
                        analyzer=self.name,
                        title=f"Command execution in {tool.name}: {label}",
                        description=f"Tool handler appears to use {label}.",
                        severity=severity,
                        tool=tool.name,
                        recommendation=(
                            "Remove shell execution; use allowlisted subprocess with argument lists."
                        ),
                        technique_id="MCTS-T-1003",
                        confidence=0.7,
                        location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                        evidence={"call": call, "source": "snippet"},
                    )
                )
        return findings


def _find_function(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return node
    return None


def _classify_call(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            if func.value.id == "subprocess":
                return "subprocess"
            qualified = f"{func.value.id}.{func.attr}"
            if qualified in DANGEROUS_CALLS:
                return qualified
            if func.attr in ("system", "popen") and func.value.id == "os":
                return "os.system"
        if func.attr in DANGEROUS_CALLS:
            return func.attr
    if isinstance(func, ast.Name) and func.id in DANGEROUS_CALLS:
        return func.id
    return None
