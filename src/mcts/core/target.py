"""Scan target resolution."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path


class TargetKind(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"


class ScanTarget:
    """Resolved scan target — single file or repository directory."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        if self.path.is_dir():
            self.kind = TargetKind.DIRECTORY
        else:
            self.kind = TargetKind.FILE

    def __str__(self) -> str:
        return str(self.path)
