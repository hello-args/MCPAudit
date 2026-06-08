"""Rust security sink detection for MCP handlers."""

from __future__ import annotations

import re

_RUST_SINK_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bCommand::new\s*\("), "Command::new"),
    (re.compile(r"\bstd::process::Command\s*::"), "std::process::Command"),
    (re.compile(r"\bstd::fs::remove_file\s*\("), "fs::remove_file"),
    (re.compile(r"\bstd::fs::write\s*\("), "fs::write"),
    (re.compile(r"\breqwest::"), "reqwest"),
    (re.compile(r"\bstd::process::exit\s*\("), "process::exit"),
)


def detect_rust_sinks(source: str) -> list[str]:
    sinks: list[str] = []
    for pattern, label in _RUST_SINK_PATTERNS:
        if pattern.search(source):
            sinks.append(label)
    return list(dict.fromkeys(sinks))
