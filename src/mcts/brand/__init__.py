"""Canonical MCTS brand assets."""

from __future__ import annotations

import base64
from pathlib import Path

BRAND_DIR = Path(__file__).resolve().parent
LOGO_PATH = BRAND_DIR / "Logo 2.jpg"
LOGO_JPG_PATH = LOGO_PATH


def logo_data_uri(*, for_report: bool = True) -> str:
    """Return a data URI for embedding the logo in HTML.

    Uses ``Logo 2.jpg`` for terminal headers, HTML dashboard sidebar, and exports.
    """
    del for_report
    payload = base64.b64encode(LOGO_PATH.read_bytes()).decode("ascii")
    return f"data:image/jpeg;base64,{payload}"
