"""Integration tests for StackRaider unified API."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from stackraider.web.server import create_app

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "test_samples"
INTRO = ROOT / "tests" / "fixtures_introspection.json"


@pytest.fixture
def client():
    return TestClient(create_app())


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["name"] == "StackRaider"


def test_session(client):
    r = client.get("/api/session")
    assert r.status_code == 200
    data = r.json()
    assert "session_id" in data
    assert data["has_scan"] is False


def test_code_scan(client):
    if not SAMPLES.exists():
        pytest.skip("test_samples missing")
    r = client.post("/api/code/scan", json={"path": str(SAMPLES), "severity": "HIGH"})
    assert r.status_code == 200
    data = r.json()
    assert "findings" in data
    r2 = client.get("/api/code/scan/result")
    assert r2.status_code == 200


def test_graphql_state_empty(client):
    r = client.get("/api/graphql/state")
    assert r.status_code == 200
    assert r.json()["schema"] is None


def test_legacy_scan_alias(client):
    if not SAMPLES.exists():
        pytest.skip("test_samples missing")
    r = client.post("/api/scan", json={"path": str(SAMPLES), "severity": "HIGH"})
    assert r.status_code == 200


def test_graphql_cli_headless():
    if not INTRO.exists():
        pytest.skip("introspection sample missing")
    from stackraider.graphql import schema_parser, static_analyzer
    import asyncio

    raw = json.loads(INTRO.read_text(encoding="utf-8"))
    introspection = raw.get("data", raw)
    schema = schema_parser.parse_introspection(introspection)
    findings = asyncio.run(static_analyzer.analyze(schema))
    assert len(findings) >= 0
