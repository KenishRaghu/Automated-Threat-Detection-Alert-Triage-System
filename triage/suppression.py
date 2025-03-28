"""Noise suppression rules for known benign patterns."""

from __future__ import annotations

import re

from triage.models import NormalizedAlert


_SCANNER_IPS = {
    "198.51.100.10",  # doc/example scanner
    "203.0.113.50",
}


def should_suppress(alert: NormalizedAlert) -> tuple[bool, str | None]:
    text = f"{alert.title} {alert.description}".lower()
    if alert.src_ip in _SCANNER_IPS:
        return True, "allowlisted_recon_source"
    if re.search(r"\bhealth ?check\b", text) or re.search(r"\bpen.?test\b.*\bapproved\b", text):
        return True, "benign_operational_noise"
    if "low" == str(alert.severity_vendor or "").lower() and "test" in text:
        return True, "low_severity_test_event"
    return False, None
