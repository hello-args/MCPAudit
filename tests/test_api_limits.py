"""Tests for REST API rate limits and fan-out pagination."""

from __future__ import annotations

import pytest

from mcts.api.limits import paginate_fanout, reset_rate_limits_for_tests
from mcts.mcp.models import MCPServerInfo, MCPTool


def test_paginate_fanout_truncates_with_warning() -> None:
    items = [object() for _ in range(5)]
    page = paginate_fanout(items, offset=0, limit=2, label="tools")
    assert len(page.items) == 2
    assert page.truncated is True
    meta = page.metadata(label="tools")
    assert meta["total_tools"] == 5
    assert meta["returned"] == 2
    assert "fanout_offset=2" in meta["truncation_warning"]


def test_paginate_fanout_second_page() -> None:
    items = [object() for _ in range(5)]
    page = paginate_fanout(items, offset=2, limit=2, label="tools")
    assert len(page.items) == 2
    assert page.offset == 2


def test_paginate_fanout_rejects_offset_past_total() -> None:
    pytest.importorskip("fastapi")
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        paginate_fanout([1, 2], offset=5, limit=1, label="tools")
    assert exc.value.status_code == 400


def test_api_scan_all_tools_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api import app as app_module

    tools = [MCPTool(name=f"tool_{index}") for index in range(4)]
    server = MCPServerInfo(name="mock", tools=tools)

    async def fake_discover(_req):  # noqa: ANN001
        return server

    monkeypatch.setattr(app_module, "_discover_async", fake_discover)
    client = TestClient(app_module.app)
    response = client.post(
        "/scan-all-tools",
        json={"target": ".", "fanout_offset": 0, "fanout_limit": 2},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["tool_count"] == 4
    assert payload["returned"] == 2
    assert payload["truncated"] is True
    assert len(payload["reports"]) == 2


def test_api_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api.app import app

    monkeypatch.setenv("MCTS_API_RATE_LIMIT_PER_MINUTE", "2")
    reset_rate_limits_for_tests()
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.post("/readiness", json={"target": "."}).status_code == 200
    assert client.post("/readiness", json={"target": "."}).status_code == 200
    blocked = client.post("/readiness", json={"target": "."})
    assert blocked.status_code == 429
    reset_rate_limits_for_tests()
