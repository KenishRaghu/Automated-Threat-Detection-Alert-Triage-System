"""Severity and confidence scoring (TTP + context)."""

from __future__ import annotations

from triage.mitre import get_category_profile, techniques_for_category
from triage.models import NormalizedAlert, TriageContext


def compute_severity(
    category: str,
    alert: NormalizedAlert,
    ctx: TriageContext,
) -> float:
    profile = get_category_profile(category)
    score = float(profile.get("base_severity", 50))
    if alert.public_facing or profile.get("public_facing"):
        score += 8
    if profile.get("credential_access"):
        score += 6
    if profile.get("edge_traffic"):
        score += 4
    if profile.get("critical_service_risk"):
        score += 10
    if (alert.service_tier or "").lower() == "critical":
        score += 12
    if alert.src_ip:
        repeats = ctx.ip_alert_counts.get(alert.src_ip, 0)
        score += min(15, repeats * 3)
    if alert.user:
        u = ctx.user_alert_counts.get(alert.user.lower(), 0)
        score += min(10, u * 2)
    return max(0.0, min(100.0, score))


def compute_confidence(
    category: str,
    alert: NormalizedAlert,
    ctx: TriageContext,
) -> float:
    """0..1 confidence from corroboration (multi-alert / repeat IP / vendor severity)."""
    base = 0.55
    if alert.severity_vendor and str(alert.severity_vendor).lower() in ("high", "critical", "severe"):
        base += 0.15
    if alert.src_ip and ctx.ip_alert_counts.get(alert.src_ip, 0) >= 2:
        base += 0.15
    if alert.user and ctx.user_alert_counts.get(alert.user.lower(), 0) >= 2:
        base += 0.1
    techs = techniques_for_category(category)
    if len(techs) > 1:
        base += 0.05
    return round(max(0.0, min(1.0, base)), 3)


def priority_band(severity: float, confidence: float) -> str:
    adjusted = severity * (0.65 + 0.35 * confidence)
    if adjusted >= 85:
        return "critical"
    if adjusted >= 70:
        return "high"
    if adjusted >= 45:
        return "medium"
    return "low"
