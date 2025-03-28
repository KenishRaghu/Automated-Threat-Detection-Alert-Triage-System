"""Analyst-ready one-page triage summaries."""

from __future__ import annotations

from triage.mitre import get_category_profile
from triage.models import TriageResult


def build_analyst_summary(result: TriageResult) -> str:
    n = result.normalized
    prof = get_category_profile(result.category)
    desc = prof.get("description", "")
    lines = [
        f"[{result.priority_band.upper()}] {n.title}",
        f"Source: {n.source} | Alert ID: {n.alert_id}",
        f"Category/TTP: {result.category} → MITRE {', '.join(result.techniques)}",
        f"Context: {desc}",
        f"Scores: severity={result.severity_score:.1f}/100, confidence={result.confidence:.0%}",
        f"Entities: src_ip={n.src_ip or '-'} user={n.user or '-'} host={n.hostname or '-'}",
    ]
    if result.suppressed:
        lines.append(f"SUPPRESSED: {result.suppression_reason}")
    if result.duplicate_of:
        lines.append(f"DEDUP: duplicate of window {result.duplicate_of[:16]}…")
    return "\n".join(lines)
