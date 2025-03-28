"""Structured audit log for workflow actions (append-only, in-memory for demo)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class AuditEntry:
    ts: datetime
    action: str
    case_id: str
    details: dict[str, Any]


class AuditLog:
    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record(self, action: str, case_id: str, **details: Any) -> None:
        self._entries.append(
            AuditEntry(
                ts=datetime.now(timezone.utc),
                action=action,
                case_id=case_id,
                details=details,
            )
        )

    def entries_for_case(self, case_id: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.case_id == case_id]

    def tail(self, n: int = 50) -> list[AuditEntry]:
        return self._entries[-n:]
