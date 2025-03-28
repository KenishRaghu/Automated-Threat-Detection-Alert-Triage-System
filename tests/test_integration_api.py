import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from triage import pipeline as pipeline_mod


ROOT = Path(__file__).resolve().parents[1]


def test_health():
    pipeline_mod._DEFAULT_DEDUPE.clear()
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"


def test_siem_webhook_unauthorized_without_secret():
    pipeline_mod._DEFAULT_DEDUPE.clear()
    client = TestClient(app)
    r = client.post("/webhooks/siem", json={"alert_id": "a", "title": "t"})
    assert r.status_code == 401


def test_siem_webhook_ingest_sample():
    pipeline_mod._DEFAULT_DEDUPE.clear()
    with (ROOT / "sample_alerts" / "siem_login_failures.json").open(encoding="utf-8") as f:
        body = json.load(f)
    client = TestClient(app)
    r = client.post(
        "/webhooks/siem",
        json=body,
        headers={"X-Siem-Secret": "dev-shared-secret"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["triage"]["priority_band"] in ("medium", "high", "critical", "low")
    assert data["orchestration"]["case_id"]
