"""Escalation rules: map triage band → response tier."""

from __future__ import annotations

from triage.models import TriageResult


def should_auto_escalate(result: TriageResult) -> bool:
    if result.suppressed or result.duplicate_of:
        return False
    return result.priority_band in ("critical", "high")


def escalation_tier(result: TriageResult) -> str:
    if result.priority_band == "critical":
        return "sev1_oncall"
    if result.priority_band == "high":
        return "sev2_ir_lead"
    return "queue_review"
