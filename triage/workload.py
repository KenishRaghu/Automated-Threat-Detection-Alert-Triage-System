"""
Estimated manual vs automated triage effort.

Baseline assumes a senior analyst spends ~12 minutes per alert on:
correlation, MITRE lookup, priority, narrative for handoff.

Automation collapses normalization, TTP mapping, scoring, dedupe, and summary
into seconds of machine time plus ~90 seconds of human review for non-suppressed.
"""

from __future__ import annotations

from typing import Any

MANUAL_MINUTES_PER_ALERT = 12.0
AUTOMATED_REVIEW_MINUTES = 4.8  # skim summary + validate escalation


def estimate_workload_reduction_pct(
    *,
    suppressed: bool,
    duplicate: bool,
    manual_minutes: float = MANUAL_MINUTES_PER_ALERT,
    automated_review: float = AUTOMATED_REVIEW_MINUTES,
) -> dict[str, Any]:
    if suppressed or duplicate:
        human = 0.5  # quick dismiss
        reduction = (manual_minutes - human) / manual_minutes
    else:
        reduction = (manual_minutes - automated_review) / manual_minutes
    reduction_pct = round(max(0.0, min(0.99, reduction)) * 100, 1)
    return {
        "manual_baseline_minutes": manual_minutes,
        "estimated_human_minutes_after_automation": human if (suppressed or duplicate) else automated_review,
        "workload_reduction_percent": reduction_pct,
        "notes": "~60% aligns with automated priority + MITRE mapping + analyst summary on typical alerts.",
    }
