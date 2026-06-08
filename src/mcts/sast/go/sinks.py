"""Go security sink detection for MCP handlers."""

from __future__ import annotations

import re

_GO_SINK_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bexec\.Command\s*\("), "exec.Command"),
    (re.compile(r"\bos/exec\.Command\s*\("), "exec.Command"),
    (re.compile(r"\bsyscall\.Exec\s*\("), "syscall.Exec"),
    (re.compile(r"\bhttp\.Get\s*\("), "http.Get"),
    (re.compile(r"\bhttp\.Post\s*\("), "http.Post"),
    (re.compile(r"\bioutil\.WriteFile\s*\("), "ioutil.WriteFile"),
    (re.compile(r"\bos\.Remove\s*\("), "os.Remove"),
    (re.compile(r"\bos\.RemoveAll\s*\("), "os.RemoveAll"),
)


def detect_go_sinks(source: str) -> list[str]:
    sinks: list[str] = []
    for pattern, label in _GO_SINK_PATTERNS:
        if pattern.search(source):
            sinks.append(label)
    return list(dict.fromkeys(sinks))
