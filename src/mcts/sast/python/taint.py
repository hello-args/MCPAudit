"""Lightweight Python taint analysis for MCP tool handlers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

SINK_CALLS: dict[str, str] = {
    "subprocess.run": "subprocess",
    "subprocess.Popen": "subprocess",
    "subprocess.call": "subprocess",
    "os.system": "os.system",
    "os.popen": "os.popen",
    "eval": "eval",
    "exec": "exec",
    "open": "open",
    "shutil.rmtree": "shutil.rmtree",
    "cursor.execute": "sql",
    "connection.execute": "sql",
    "os.remove": "os.remove",
    "os.rmdir": "os.remove",
    "os.unlink": "os.remove",
    "shutil.copy": "shutil",
    "shutil.move": "shutil",
    "pickle.loads": "pickle",
    "pickle.load": "pickle",
    "socket.socket": "socket",
    "Template": "Template",
}

NETWORK_ATTRS = frozenset({"get", "post", "put", "delete", "request", "urlopen"})


@dataclass
class TaintResult:
    sinks: list[str] = field(default_factory=list)
    tainted_params: set[str] = field(default_factory=set)


def analyze_handler_taint(source: str) -> TaintResult:
    """Find security sinks reached by function parameters."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return TaintResult()
    params = _collect_params(tree)
    tainted: set[str] = set(params)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and _expr_uses_tainted(node.value, tainted):
                    tainted.add(target.id)
    sinks: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        sink = _call_sink_name(node.func)
        if not sink:
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        if any(_expr_uses_tainted(arg, tainted) for arg in args):
            sinks.append(sink)
    return TaintResult(sinks=list(dict.fromkeys(sinks)), tainted_params=set(params))


def _collect_params(tree: ast.AST) -> list[str]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return [arg.arg for arg in node.args.args]
    return []


def _expr_uses_tainted(node: ast.AST | None, tainted: set[str]) -> bool:
    if node is None:
        return False
    return any(isinstance(child, ast.Name) and child.id in tainted for child in ast.walk(node))


def _call_sink_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return SINK_CALLS.get(func.id)
    if isinstance(func, ast.Attribute):
        dotted = _attr_dotted(func)
        if dotted in SINK_CALLS:
            return SINK_CALLS[dotted]
        if func.attr in NETWORK_ATTRS:
            base = _attr_dotted(func.value)
            if base in ("requests", "httpx", "urllib.request", "aiohttp"):
                return f"{base}.{func.attr}"
        if func.attr == "from_string":
            base = _attr_dotted(func.value)
            if base in ("Environment", "jinja2.Environment"):
                return "Template"
    return None


def _attr_dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attr_dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""
