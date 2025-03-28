"""Incident timeline generation from audit + milestones."""

from __future__ import annotations

from workflows.audit import AuditEntry


def build_timeline(entries: list[AuditEntry]) -> list[dict[str, str]]:
    return [
        {
            "timestamp": e.ts.isoformat(),
            "action": e.action,
            "detail": str(e.details),
        }
        for e in sorted(entries, key=lambda x: x.ts)
    ]
