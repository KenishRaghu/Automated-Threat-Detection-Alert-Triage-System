"""FastAPI entrypoint: SIEM webhooks, triage pipeline, workflow orchestration."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from app.queue import enqueue_job, get_redis
from app.settings import settings
from storage.opensearch_store import get_client, index_triage
from triage.models import TriageContext, TriageResult
from triage.normalize import normalize_cloudflare_style, normalize_siem_webhook
from triage.pipeline import run_triage_pipeline
from workflows.audit import AuditLog
from workflows.orchestrator import OrchestrationResult, Orchestrator

_audit = AuditLog()
_es_client = None
_redis = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _es_client, _redis
    try:
        _es_client = get_client(settings.opensearch_url, verify_certs=settings.opensearch_verify_certs)
        _es_client.ping()
    except Exception:
        _es_client = None
    try:
        _redis = get_redis(settings.redis_url)
        _redis.ping()
    except Exception:
        _redis = None
    yield
    if _es_client:
        _es_client.close()


app = FastAPI(title=settings.app_name, lifespan=lifespan)


def get_orchestrator() -> Orchestrator:
    return Orchestrator(settings, audit=_audit)


class IngestResponse(BaseModel):
    triage: dict[str, Any]
    orchestration: dict[str, Any] | None = None
    indexed: bool
    queued: bool


def verify_siem_secret(x_siem_secret: str | None = Header(default=None)) -> None:
    if settings.siem_shared_secret and x_siem_secret != settings.siem_shared_secret:
        raise HTTPException(status_code=401, detail="invalid SIEM webhook secret")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "opensearch": bool(_es_client),
        "redis": bool(_redis),
    }


@app.post("/webhooks/siem", response_model=IngestResponse)
def ingest_siem(
    body: dict[str, Any],
    _: None = Depends(verify_siem_secret),
    orchestrator: Orchestrator = Depends(get_orchestrator),
):
    alert = normalize_siem_webhook(body)
    return _process_alert(alert, orchestrator)


@app.post("/webhooks/edge", response_model=IngestResponse)
def ingest_edge(
    body: dict[str, Any],
    _: None = Depends(verify_siem_secret),
    orchestrator: Orchestrator = Depends(get_orchestrator),
):
    alert = normalize_cloudflare_style(body)
    return _process_alert(alert, orchestrator)


def _triage_result_to_dict(t: TriageResult) -> dict[str, Any]:
    return {
        "alert_id": t.normalized.alert_id,
        "category": t.category,
        "techniques": t.techniques,
        "severity_score": t.severity_score,
        "confidence": t.confidence,
        "priority_band": t.priority_band,
        "suppressed": t.suppressed,
        "suppression_reason": t.suppression_reason,
        "duplicate_of": t.duplicate_of,
        "analyst_summary": t.analyst_summary,
        "workload_metrics": t.workload_metrics,
    }


def _orch_to_dict(o: OrchestrationResult) -> dict[str, Any]:
    return {
        "case_id": o.case.case_id,
        "case_status": o.case.status.value,
        "ticket_id": o.ticket_id,
        "escalated": o.escalated,
        "escalation_tier": o.escalation_tier,
        "notifications": o.notifications,
        "playbook": {
            "ip_block_rule_id": o.playbook.ip_block_rule_id,
            "user_disabled": o.playbook.user_disabled,
            "vendor_requests": o.playbook.vendor_requests,
        },
        "timeline": o.timeline,
    }


def _process_alert(alert, orchestrator: Orchestrator) -> IngestResponse:
    ctx = TriageContext()
    if alert.src_ip:
        ctx.ip_alert_counts[alert.src_ip] = ctx.ip_alert_counts.get(alert.src_ip, 0) + 1
    if alert.user:
        k = alert.user.lower()
        ctx.user_alert_counts[k] = ctx.user_alert_counts.get(k, 0) + 1

    triage = run_triage_pipeline(alert, ctx=ctx)
    orch = orchestrator.handle_triage_result(triage)

    indexed = index_triage(_es_client, "security-triage", triage, orch.case.case_id)
    job = {
        "alert_id": alert.alert_id,
        "case_id": orch.case.case_id,
        "priority": triage.priority_band,
    }
    queued = enqueue_job(_redis, job)

    return IngestResponse(
        triage=_triage_result_to_dict(triage),
        orchestration=_orch_to_dict(orch),
        indexed=indexed,
        queued=queued,
    )
