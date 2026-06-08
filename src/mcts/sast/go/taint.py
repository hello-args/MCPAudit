"""Go parameter-to-sink flow analysis."""

from __future__ import annotations

import re

from mcts.sast.go.sinks import detect_go_sinks
from mcts.sast.python.taint import TaintResult

_PARAM_PATTERN = re.compile(r"func\s+\w+\s*\(([^)]*)\)")


def analyze_go_taint(source: str) -> TaintResult:
    params = _extract_params(source)
    tainted = set(params)
    for match in re.finditer(r"(\w+)\s*:=\s*(\w+)", source):
        if match.group(2) in tainted:
            tainted.add(match.group(1))
    sinks: list[str] = []
    for sink in detect_go_sinks(source):
        if any(re.search(rf"\b{re.escape(param)}\b", source) for param in tainted):
            sinks.append(sink)
    return TaintResult(sinks=list(dict.fromkeys(sinks)), tainted_params=params)


def _extract_params(source: str) -> set[str]:
    params: set[str] = set()
    match = _PARAM_PATTERN.search(source)
    if not match:
        return params
    for part in match.group(1).split(","):
        chunk = part.strip()
        if chunk:
            params.add(chunk.split()[0])
    return params
