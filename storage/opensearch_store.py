"""Index triage documents in Elasticsearch/OpenSearch-compatible clusters."""

from __future__ import annotations

import json
from typing import Any

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ApiError

from triage.models import TriageResult


def get_client(url: str, verify_certs: bool = False) -> Elasticsearch:
    return Elasticsearch(url, verify_certs=verify_certs, request_timeout=5)


def index_triage(es: Elasticsearch | None, index: str, triage: TriageResult, case_id: str | None) -> bool:
    if es is None:
        return False
    doc: dict[str, Any] = {
        "alert_id": triage.normalized.alert_id,
        "case_id": case_id,
        "priority_band": triage.priority_band,
        "category": triage.category,
        "techniques": triage.techniques,
        "severity_score": triage.severity_score,
        "confidence": triage.confidence,
        "suppressed": triage.suppressed,
        "summary": triage.analyst_summary,
        "timestamp": triage.normalized.timestamp.isoformat(),
    }
    try:
        es.index(index=index, document=doc, id=triage.normalized.alert_id or None)
        return True
    except (ApiError, OSError, ValueError):
        return False


def triage_to_json(triage: TriageResult, case_id: str | None) -> str:
    return json.dumps(
        {
            "alert_id": triage.normalized.alert_id,
            "case_id": case_id,
            "priority_band": triage.priority_band,
            "category": triage.category,
            "techniques": triage.techniques,
            "severity_score": triage.severity_score,
            "confidence": triage.confidence,
        }
    )
