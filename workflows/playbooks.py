"""Automated containment playbooks (simulated API calls to edge / IdP)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class PlaybookResult:
    ip_block_rule_id: str | None
    user_disabled: bool
    vendor_requests: list[dict[str, Any]]


def run_ip_block_playbook(api_base: str, src_ip: str, case_id: str) -> tuple[str | None, dict[str, Any]]:
    """Simulate WAF/firewall block via internal automation API."""
    payload = {"action": "block_ip", "ip": src_ip, "case_id": case_id, "ttl_hours": 24}
    try:
        r = httpx.post(f"{api_base.rstrip('/')}/automation/block", json=payload, timeout=2.0)
        if r.is_success:
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            return str(body.get("rule_id", f"rule-{src_ip.replace('.', '-')}")), payload
    except (httpx.HTTPError, OSError, ValueError):
        pass
    return f"sim-rule-{src_ip.replace('.', '-')}", payload


def run_disable_user_playbook(api_base: str, username: str, case_id: str) -> tuple[bool, dict[str, Any]]:
    payload = {"action": "disable_user", "user": username, "case_id": case_id}
    try:
        r = httpx.post(f"{api_base.rstrip('/')}/automation/disable_user", json=payload, timeout=2.0)
        return r.is_success, payload
    except (httpx.HTTPError, OSError):
        return True, payload  # simulated success when API unreachable (demo)
