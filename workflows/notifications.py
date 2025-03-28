"""Slack + PagerDuty-style notifications (simulated payloads)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class NotificationResult:
    slack_sent: bool
    pagerduty_event_id: str | None
    payloads: dict[str, Any]


def send_slack(webhook_url: str, text: str) -> bool:
    if not webhook_url:
        return False
    try:
        r = httpx.post(webhook_url, json={"text": text}, timeout=3.0)
        return r.is_success
    except (httpx.HTTPError, OSError):
        return False


def simulate_pagerduty_event(routing_key: str, summary: str, severity: str) -> str | None:
    """Return synthetic event id (Events API v2 shape for documentation)."""
    if not routing_key:
        return None
    # In production this would POST to events.pagerduty.com; we only build the payload.
    _ = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "severity": severity,
            "source": "siem-triage-bridge",
        },
    }
    return "pd-sim-" + str(hash(summary))[:12]


def notify_escalation(
    *,
    slack_webhook_url: str,
    pagerduty_routing_key: str,
    message: str,
    pd_severity: str,
) -> NotificationResult:
    slack_ok = send_slack(slack_webhook_url, message)
    pd_id = simulate_pagerduty_event(pagerduty_routing_key, message, pd_severity)
    return NotificationResult(
        slack_sent=slack_ok,
        pagerduty_event_id=pd_id,
        payloads={"slack_message": message, "pagerduty_severity": pd_severity},
    )
