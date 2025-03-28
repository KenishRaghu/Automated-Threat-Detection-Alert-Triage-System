"""Case creation and escalation state."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid


class CaseStatus(str, Enum):
    OPEN = "open"
    ESCALATED = "escalated"
    CONTAINED = "contained"
    CLOSED = "closed"


@dataclass
class IncidentCase:
    case_id: str
    title: str
    priority: str
    techniques: list[str]
    status: CaseStatus = CaseStatus.OPEN
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


def new_case_from_triage(
    title: str,
    priority_band: str,
    techniques: list[str],
    extra: dict[str, Any] | None = None,
) -> IncidentCase:
    return IncidentCase(
        case_id=str(uuid.uuid4()),
        title=title,
        priority=priority_band,
        techniques=list(techniques),
        metadata=dict(extra or {}),
    )
