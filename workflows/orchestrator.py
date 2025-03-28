"""Wire triage results into SIEM-style IR workflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.settings import Settings
from triage.models import TriageResult
from workflows.audit import AuditLog
from workflows.case import CaseStatus, IncidentCase, new_case_from_triage
from workflows.escalation import escalation_tier, should_auto_escalate
from workflows.notifications import notify_escalation
from workflows.playbooks import PlaybookResult, run_disable_user_playbook, run_ip_block_playbook
from workflows.tickets import TicketClient
from workflows.timeline import build_timeline


@dataclass
class OrchestrationResult:
    case: IncidentCase
    ticket_id: str | None
    escalated: bool
    escalation_tier: str
    notifications: dict[str, Any]
    playbook: PlaybookResult
    timeline: list[dict[str, str]]


class Orchestrator:
    def __init__(self, settings: Settings, audit: AuditLog | None = None) -> None:
        self.settings = settings
        self.audit = audit or AuditLog()
        self.tickets = TicketClient(settings.ticket_system_url)

    def handle_triage_result(self, triage: TriageResult) -> OrchestrationResult:
        n = triage.normalized
        extra = {
            "src_ip": n.src_ip,
            "user": n.user,
            "alert_id": n.alert_id,
            "techniques": triage.techniques,
        }
        case = new_case_from_triage(
            title=n.title,
            priority_band=triage.priority_band,
            techniques=triage.techniques,
            extra=extra,
        )
        self.audit.record("case_created", case.case_id, title=case.title, priority=case.priority)
        if triage.suppressed:
            case.status = CaseStatus.CLOSED
            self.audit.record(
                "suppressed_no_escalation",
                case.case_id,
                reason=triage.suppression_reason,
            )
        if triage.duplicate_of:
            case.status = CaseStatus.CLOSED
            self.audit.record(
                "duplicate_no_escalation",
                case.case_id,
                fingerprint=triage.duplicate_of,
            )

        ticket_id = None
        if not triage.suppressed and not triage.duplicate_of:
            t = self.tickets.create(
                subject=f"[{triage.priority_band.upper()}] {n.title}",
                body=triage.analyst_summary,
            )
            ticket_id = t.ticket_id
            self.audit.record("ticket_created", case.case_id, ticket_id=ticket_id)

        escalated = should_auto_escalate(triage)
        tier = escalation_tier(triage)
        notif_info: dict[str, Any] = {}
        if escalated:
            case.status = CaseStatus.ESCALATED
            msg = f"ESCALATED ({tier}): {n.title}\n{triage.analyst_summary}"
            pd_sev = "critical" if triage.priority_band == "critical" else "error"
            nr = notify_escalation(
                slack_webhook_url=self.settings.slack_webhook_url,
                pagerduty_routing_key=self.settings.pagerduty_routing_key,
                message=msg,
                pd_severity=pd_sev,
            )
            notif_info = {
                "slack_sent": nr.slack_sent,
                "pagerduty_event_id": nr.pagerduty_event_id,
                "payload": nr.payloads,
            }
            self.audit.record(
                "escalation_sent",
                case.case_id,
                tier=tier,
                pagerduty_event_id=nr.pagerduty_event_id,
            )

        playbook = PlaybookResult(ip_block_rule_id=None, user_disabled=False, vendor_requests=[])
        automation_base = self.settings.ticket_system_url.replace("/api", "/automation")
        if escalated and n.src_ip:
            rule_id, req = run_ip_block_playbook(automation_base, n.src_ip, case.case_id)
            playbook.ip_block_rule_id = rule_id
            playbook.vendor_requests.append(req)
            self.audit.record("playbook_ip_block", case.case_id, rule_id=rule_id, ip=n.src_ip)
        if escalated and triage.category in ("malware_ioc", "valid_account_abuse", "impossible_travel") and n.user:
            ok, req = run_disable_user_playbook(automation_base, n.user, case.case_id)
            playbook.user_disabled = ok
            playbook.vendor_requests.append(req)
            self.audit.record("playbook_disable_user", case.case_id, user=n.user, success=ok)

        timeline = build_timeline(self.audit.entries_for_case(case.case_id))
        return OrchestrationResult(
            case=case,
            ticket_id=ticket_id,
            escalated=escalated,
            escalation_tier=tier,
            notifications=notif_info,
            playbook=playbook,
            timeline=timeline,
        )
