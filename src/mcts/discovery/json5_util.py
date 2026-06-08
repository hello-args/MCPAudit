"""Lightweight JSON5 / commented JSON loader (no external dependency)."""

from __future__ import annotations

import json
import re
from pathlib import Path

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//.*?$", re.MULTILINE)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def loads_json5(text: str) -> object:
    """Parse JSON with // and /* */ comments and trailing commas."""
    cleaned = _BLOCK_COMMENT.sub("", text)
    cleaned = _LINE_COMMENT.sub("", cleaned)
    cleaned = _TRAILING_COMMA.sub(r"\1", cleaned)
    return json.loads(cleaned)


def load_json5(path: Path) -> object:
    return loads_json5(path.read_text(encoding="utf-8"))
