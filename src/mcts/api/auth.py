"""Optional API key authentication for the REST server."""

from __future__ import annotations

import os

from fastapi import HTTPException, Request


def require_api_key(request: Request) -> None:
    """Validate X-API-Key when MCTS_API_KEY is set."""
    expected = os.environ.get("MCTS_API_KEY", "").strip()
    if not expected:
        return
    provided = request.headers.get("X-API-Key", "").strip()
    if provided != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
