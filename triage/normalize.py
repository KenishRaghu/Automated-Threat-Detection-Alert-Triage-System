"""Map vendor/SIEM payloads into NormalizedAlert."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from triage.models import NormalizedAlert


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            # ISO 8601
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def normalize_siem_webhook(payload: dict[str, Any]) -> NormalizedAlert:
    """Normalize a generic SIEM-style webhook body."""
    ts = _parse_ts(payload.get("timestamp") or payload.get("time") or payload.get("@timestamp"))
    entity = payload.get("entity") or {}
    network = payload.get("network") or {}
    return NormalizedAlert(
        alert_id=str(payload.get("alert_id") or payload.get("id") or payload.get("event_id", "")),
        source=str(payload.get("source") or payload.get("vendor") or "siem"),
        title=str(payload.get("title") or payload.get("rule_name") or "Security alert"),
        description=str(payload.get("description") or payload.get("message") or ""),
        severity_vendor=payload.get("severity"),
        timestamp=ts or datetime.now(timezone.utc),
        src_ip=(network.get("src_ip") or entity.get("src_ip") or payload.get("src_ip")),
        dst_ip=(network.get("dst_ip") or entity.get("dst_ip") or payload.get("dst_ip")),
        user=(entity.get("user") or payload.get("user") or payload.get("username")),
        hostname=(entity.get("host") or payload.get("hostname")),
        public_facing=bool(payload.get("public_facing") or entity.get("public_facing")),
        service_tier=str(payload.get("service_tier") or entity.get("service_tier") or "") or None,
        raw_vendor_type=payload.get("alert_type") or payload.get("category"),
        raw=dict(payload),
    )


def normalize_cloudflare_style(payload: dict[str, Any]) -> NormalizedAlert:
    """Normalize an edge/WAF-style sample (Cloudflare-ish field names)."""
    merged = dict(payload)
    merged.setdefault("source", "cloudflare_edge")
    if "client_ip" in payload and "network" not in payload:
        merged["network"] = {"src_ip": payload["client_ip"]}
    return normalize_siem_webhook(merged)
