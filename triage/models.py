from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class NormalizedAlert(BaseModel):
    """Common schema after SIEM/vendor normalization."""

    alert_id: str
    source: str
    title: str
    description: str = ""
    severity_vendor: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    hostname: str | None = None
    public_facing: bool = False
    service_tier: str | None = None  # e.g. critical, production, dev
    raw_vendor_type: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable key for deduplication."""
        parts = [
            self.title.strip().lower()[:120],
            (self.src_ip or "").strip(),
            (self.user or "").strip().lower(),
        ]
        return "|".join(parts)


class TriageContext(BaseModel):
    """Cross-alert context (e.g. repeat offender IP, correlated signals)."""

    ip_alert_counts: dict[str, int] = Field(default_factory=dict)
    user_alert_counts: dict[str, int] = Field(default_factory=dict)


class TriageResult(BaseModel):
    normalized: NormalizedAlert
    category: str
    techniques: list[str]
    severity_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    priority_band: str  # critical | high | medium | low
    suppressed: bool = False
    suppression_reason: str | None = None
    duplicate_of: str | None = None
    analyst_summary: str
    workload_metrics: dict[str, Any] = Field(default_factory=dict)
