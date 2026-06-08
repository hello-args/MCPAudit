"""Tests for readiness heuristics, MIME filtering, and API routes."""

from __future__ import annotations

import pytest

from mcts.analyzers.surface_context import scan_surfaces
from mcts.mcp.models import MCPResource, MCPServerInfo, MCPTool, SurfaceScanOptions
from mcts.readiness.heuristics import check_tool_readiness, readiness_score
from mcts.sast.typescript.sinks import detect_typescript_sinks


def test_readiness_heur_001_missing_timeout():
    tool = MCPTool(name="fetch", description="Fetch remote data from an external API service")
    findings = check_tool_readiness(tool)
    assert any(f.evidence.get("readiness_rule") == "HEUR-001" for f in findings)


def test_readiness_heur_009_short_description():
    tool = MCPTool(name="x", description="short")
    findings = check_tool_readiness(tool)
    assert any(f.evidence.get("readiness_rule") == "HEUR-009" for f in findings)


def test_readiness_score_deductions():
    tool = MCPTool(name="x", description="short")
    findings = check_tool_readiness(tool)
    assert readiness_score(findings) < 100


def test_resource_mime_allowlist_filters_surfaces():
    server = MCPServerInfo(
        resources=[
            MCPResource(uri="a", name="text", mime_type="text/plain", description="ok"),
            MCPResource(uri="b", name="img", mime_type="image/png", description="binary"),
        ],
        surface_scan=SurfaceScanOptions(
            surfaces=["resource"],
            resource_mime_allowlist=["text/plain"],
        ),
    )
    surfaces = scan_surfaces(server)
    assert len(surfaces) == 1
    assert surfaces[0].mime_type == "text/plain"


def test_typescript_sink_detection():
    source = "import { exec } from 'child_process';\nexport function run(cmd: string) { exec(cmd); }\n"
    assert "child_process" in detect_typescript_sinks(source)


def test_api_health_and_readiness_endpoints():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api.app import app

    client = TestClient(app)
    assert client.get("/health").json() == {"status": "ok"}
    response = client.post("/readiness", json={"target": "."})
    assert response.status_code == 200
    payload = response.json()
    assert "readiness_score" in payload
    assert "findings" in payload


def test_api_requires_key_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api.app import app

    monkeypatch.setenv("MCTS_API_KEY", "secret-token")
    client = TestClient(app)
    denied = client.post("/scan", json={"target": "."})
    assert denied.status_code == 401
    allowed = client.post("/scan", json={"target": "."}, headers={"X-API-Key": "secret-token"})
    assert allowed.status_code == 200
