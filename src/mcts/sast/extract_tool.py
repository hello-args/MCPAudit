"""Extract MCP tool handlers from Python server source files."""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass
class ExtractedTool:
    name: str
    description: str
    handler_snippet: str
    source_line: int


def extract_first_tool(source: str) -> ExtractedTool | None:
    """Return the first @*.tool() decorated function in a Python module."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    lines = source.splitlines()
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if not _is_tool_decorated(node):
            continue
        start = max(0, node.lineno - 1)
        end = node.end_lineno or node.lineno
        snippet = "\n".join(lines[start:end])
        return ExtractedTool(
            name=node.name,
            description=ast.get_docstring(node) or "",
            handler_snippet=snippet,
            source_line=node.lineno,
        )
    return None


def _is_tool_decorated(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            decorator = decorator.func
        if isinstance(decorator, ast.Attribute) and decorator.attr == "tool":
            return True
    return False
