from triage.dedupe import DedupeStore
from triage.models import TriageContext
from triage.normalize import normalize_siem_webhook
from triage.pipeline import run_triage_pipeline
from app.settings import Settings
from workflows.orchestrator import Orchestrator


def test_orchestrator_creates_case_ticket_timeline():
    settings = Settings(
        ticket_system_url="https://example.test/api",
        slack_webhook_url="",
        pagerduty_routing_key="demo-key",
    )
    payload = {
        "alert_id": "x-1",
        "title": "Critical malware IOC",
        "description": "hash matched known trojan",
        "alert_type": "malware_ioc",
        "severity": "critical",
        "entity": {"user": "victim"},
        "network": {"src_ip": "10.0.0.5"},
        "service_tier": "critical",
    }
    alert = normalize_siem_webhook(payload)
    ctx = TriageContext(ip_alert_counts={alert.src_ip: 2} if alert.src_ip else {})
    triage = run_triage_pipeline(alert, ctx=ctx, dedupe=DedupeStore())
    orch = Orchestrator(settings).handle_triage_result(triage)

    assert orch.case.case_id
    assert orch.ticket_id
    assert orch.escalated is True
    assert any(e["action"] == "case_created" for e in orch.timeline)
    assert orch.playbook.ip_block_rule_id


def test_suppressed_skips_ticket():
    settings = Settings(ticket_system_url="https://example.test/api")
    payload = {
        "alert_id": "x-2",
        "title": "low priority test event",
        "description": "test dashboard",
        "severity": "low",
    }
    alert = normalize_siem_webhook(payload)
    triage = run_triage_pipeline(alert, dedupe=DedupeStore())
    orch = Orchestrator(settings).handle_triage_result(triage)
    assert triage.suppressed
    assert orch.ticket_id is None
    assert orch.escalated is False
