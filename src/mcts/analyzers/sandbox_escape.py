"""Container sandbox escape via runc exec (MCTS-T-1033)."""

from __future__ import annotations

import re
from typing import Any

_RUNC = re.compile(r"runc", re.I)
_EXEC = re.compile(r"\sexec\b")
_CWD_TRAVERSAL = re.compile(r"""(^|\s)--cwd(?:=|\s+)["']?\.\.(?:[/\\])""")


def detect_sandbox_escape(event: dict[str, Any]) -> bool:
    """Detect MCTS-T-1033 indicators in process creation telemetry."""
    log = event.get("log_entry", event)
    if not isinstance(log, dict):
        return False
    image = str(log.get("Image", ""))
    command = str(log.get("CommandLine", ""))
    if not _RUNC.search(image) and not _RUNC.search(command):
        return False
    if not _EXEC.search(command):
        return False
    return bool(_CWD_TRAVERSAL.search(command))
