"""End-to-end triage pipeline."""

from __future__ import annotations

from triage.dedupe import DedupeStore
from triage.mitre import classify_from_text, techniques_for_category
from triage.models import NormalizedAlert, TriageContext, TriageResult
from triage.scoring import compute_confidence, compute_severity, priority_band
from triage.summary import build_analyst_summary
from triage.suppression import should_suppress
from triage.workload import estimate_workload_reduction_pct

_DEFAULT_DEDUPE = DedupeStore()


def run_triage_pipeline(
    alert: NormalizedAlert,
    ctx: TriageContext | None = None,
    dedupe: DedupeStore | None = None,
) -> TriageResult:
    ctx = ctx or TriageContext()
    dedupe = dedupe or _DEFAULT_DEDUPE

    category = classify_from_text(
        alert.title,
        alert.description,
        alert.raw_vendor_type or alert.raw.get("alert_type"),
    )
    techniques = techniques_for_category(category)

    sup, reason = should_suppress(alert)
    dup_key = dedupe.check_duplicate(alert.fingerprint()) if not sup else None
    duplicate = dup_key is not None and not sup

    severity = compute_severity(category, alert, ctx)
    confidence = compute_confidence(category, alert, ctx)
    band = priority_band(severity, confidence)

    result = TriageResult(
        normalized=alert,
        category=category,
        techniques=techniques,
        severity_score=severity,
        confidence=confidence,
        priority_band=band if not sup else "low",
        suppressed=sup,
        suppression_reason=reason,
        duplicate_of=(alert.fingerprint() if duplicate else None),
        analyst_summary="",
        workload_metrics=estimate_workload_reduction_pct(
            suppressed=sup, duplicate=duplicate
        ),
    )
    result.analyst_summary = build_analyst_summary(result)
    return result
