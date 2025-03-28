import json
from pathlib import Path


from triage.dedupe import DedupeStore
from triage.models import TriageContext
from triage.normalize import normalize_siem_webhook
from triage.pipeline import run_triage_pipeline
from triage.workload import MANUAL_MINUTES_PER_ALERT, estimate_workload_reduction_pct


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str) -> dict:
    with (ROOT / "sample_alerts" / name).open(encoding="utf-8") as f:
        return json.load(f)


def test_brute_force_maps_t1110_and_prioritizes():
    alert = normalize_siem_webhook(_load("siem_brute_force.json"))
    r = run_triage_pipeline(alert, dedupe=DedupeStore())
    assert "T1110" in r.techniques
    assert r.category == "brute_force"
    assert r.priority_band in ("high", "critical")


def test_waf_attack_public_facing_edge():
    from triage.normalize import normalize_cloudflare_style

    alert = normalize_cloudflare_style(_load("edge_waf_attack.json"))
    r = run_triage_pipeline(alert, dedupe=DedupeStore())
    assert "T1190" in r.techniques
    assert r.category == "waf_attack"


def test_malware_ioc_critical_band():
    alert = normalize_siem_webhook(_load("siem_malware_ioc.json"))
    r = run_triage_pipeline(alert, dedupe=DedupeStore())
    assert r.category == "malware_ioc"
    assert r.priority_band == "critical"


def test_workload_reduction_near_sixty_percent():
    m = estimate_workload_reduction_pct(suppressed=False, duplicate=False)
    expected = round(
        (MANUAL_MINUTES_PER_ALERT - m["estimated_human_minutes_after_automation"])
        / MANUAL_MINUTES_PER_ALERT
        * 100,
        1,
    )
    assert m["workload_reduction_percent"] == expected
    assert 59.0 <= m["workload_reduction_percent"] <= 61.0


def test_suppression_allowlisted_ip():
    alert = normalize_siem_webhook(_load("siem_brute_force.json"))
    alert.src_ip = "198.51.100.10"
    r = run_triage_pipeline(alert, dedupe=DedupeStore())
    assert r.suppressed is True


def test_deduplication_second_is_duplicate():
    alert = normalize_siem_webhook(_load("siem_api_abuse.json"))
    d = DedupeStore()
    first = run_triage_pipeline(alert, dedupe=d)
    second = run_triage_pipeline(alert, dedupe=d)
    assert first.duplicate_of is None
    assert second.duplicate_of is not None


def test_impossible_travel_valid_account_context():
    alert = normalize_siem_webhook(_load("siem_impossible_travel.json"))
    ctx = TriageContext(ip_alert_counts={"198.51.100.201": 3})
    r = run_triage_pipeline(alert, ctx=ctx, dedupe=DedupeStore())
    assert r.category == "impossible_travel"
    assert "T1078" in r.techniques
