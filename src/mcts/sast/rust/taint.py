"""Rust parameter-to-sink flow analysis."""

from __future__ import annotations

import re

from mcts.sast.python.taint import TaintResult
from mcts.sast.rust.sinks import detect_rust_sinks

_FN_PATTERN = re.compile(r"fn\s+\w+\s*\(([^)]*)\)")


def analyze_rust_taint(source: str) -> TaintResult:
    params = _extract_params(source)
    tainted = set(params)
    sinks: list[str] = []
    for sink in detect_rust_sinks(source):
        if any(re.search(rf"\b{re.escape(param)}\b", source) for param in tainted):
            sinks.append(sink)
    return TaintResult(sinks=list(dict.fromkeys(sinks)), tainted_params=params)


def _extract_params(source: str) -> set[str]:
    params: set[str] = set()
    match = _FN_PATTERN.search(source)
    if not match:
        return params
    for part in match.group(1).split(","):
        chunk = part.strip()
        if not chunk or chunk.startswith("&"):
            chunk = chunk.lstrip("&mut ").strip()
        name = chunk.split(":")[0].strip()
        if name:
            params.add(name)
    return params
