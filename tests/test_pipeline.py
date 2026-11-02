from datetime import datetime, timedelta

import numpy as np
import pytest

from services.common.db import session_scope
from services.common.models import Analysis, Event, Outbox
from services.engine.pipeline import Pipeline


@pytest.fixture(scope="module")
def pipe():
    return Pipeline()


def raw(i, ts, **kw):
    d = {"id": str(i), "timestamp": ts.isoformat() + "Z", "signature": "Scheduled vulnerability scan monitoring probe", "src_ip": "10.0.4.30",
         "dst_ip": "10.0.9.9", "dst_port": 443, "count": 1, "severity": "low"}
    d.update(kw)
    return d


def feed(pipe, session, prefix, start, hours, rng, **kw):
    last = None
    for h in range(hours):
        n = int(rng.poisson(20 * (1 + 0.8 * np.sin(2 * np.pi * (h - 8) / 24))))
        ts = start + timedelta(hours=h, minutes=5)
        last, _ = pipe.process(session, raw(f"{prefix}-{h}", ts, count=max(n, 1), **kw), "generic", "default")
    return last


def test_periodic_low_risk_is_filtered(pipe):
    rng = np.random.default_rng(1)
    with session_scope() as s:
        last = feed(pipe, s, "A", datetime(2026, 10, 1), 24 * 7, rng)
        assert last.noise_info["periodic"] and last.disposition == "filtered"
        assert last.analysis_status == "not_requested"


def test_periodic_but_high_risk_is_NOT_removed(pipe):
    """Inti paper: periodik + bukti berisiko (aset core) -> dipertahankan/dieskalasi, bukan dibuang."""
    rng = np.random.default_rng(2)
    with session_scope() as s:
        last = feed(pipe, s, "B", datetime(2026, 10, 1), 24 * 7, rng, dst_ip="10.0.1.10", src_ip="10.0.4.31")
        assert last.noise_info["periodic"]
        assert last.disposition == "retained" and "risk gate" in last.disposition_reason.lower()
        assert last.orchestration["risk_gate"]["G"] == 1


def test_idempotent_ingest_and_outbox(pipe):
    with session_scope() as s:
        e1, c1 = pipe.process(s, raw("dup-1", datetime(2026, 10, 20), src_ip="203.0.113.45", dst_ip="10.0.1.10"), "generic", "default")
        e2, c2 = pipe.process(s, raw("dup-1", datetime(2026, 10, 20), src_ip="203.0.113.45", dst_ip="10.0.1.10"), "generic", "default")
        assert c1 and not c2 and e1.event_id == e2.event_id
        assert s.query(Outbox).filter_by(event_id=e1.event_id).count() == 1
        assert s.get(Analysis, e1.event_id).status == "pending"


def test_tenant_isolation_in_event_id(pipe):
    with session_scope() as s:
        a, _ = pipe.process(s, raw("same", datetime(2026, 10, 21)), "generic", "t1")
        b, _ = pipe.process(s, raw("same", datetime(2026, 10, 21)), "generic", "t2")
        assert a.event_id != b.event_id


def test_missing_enrichment_never_filters_blindly(pipe):
    with session_scope() as s:
        e, _ = pipe.process(s, raw("unk-1", datetime(2026, 10, 22), src_ip="192.0.2.99", dst_ip="10.77.0.1", signature="weird thing", severity="medium"), "generic", "default")
        assert e.disposition in ("retained", "manual_review")


def test_secret_masked_in_payload(pipe):
    with session_scope() as s:
        e, _ = pipe.process(s, raw("sec-1", datetime(2026, 10, 23), password="hunter2", message="login password=abc123 failed"), "generic", "default")
        assert e.payload["password"] == "[REDACTED]" and "abc123" not in e.payload["message"]


def test_regression_brute_force_not_misclassified_as_web_attack():
    from services.engine.normalizer.core import classify
    assert classify(None, "SSH brute force multiple failed login", "") == "brute_force"
    assert classify(None, "Malware C2 beacon", "") == "malware_comm"
    assert classify(None, "Web attack: remote code execution CVE-2024-3400", "") == "web_attack"


def test_exfil_to_ioc_destination_triggers_gate_and_killchain(pipe):
    t = datetime(2026, 9, 1, 8)
    with session_scope() as s:
        pipe.process(s, {"id": "kc1", "timestamp": t.isoformat() + "Z", "signature": "port scan nmap", "src_ip": "203.0.113.45", "dst_ip": "10.0.1.10", "technique_id": "T1595"}, "generic", "kc")
        e, _ = pipe.process(s, {"id": "kc2", "timestamp": (t + timedelta(hours=5)).isoformat() + "Z", "signature": "data exfiltration over c2",
                                "src_ip": "10.0.1.20", "dst_ip": "203.0.113.45", "technique_id": "T1041"}, "generic", "kc")
        assert e.orchestration["risk_gate"]["indicators"]["confirmed_ioc"]           # IOC ada di dst_ip
        assert e.orchestration["risk_gate"]["indicators"]["killchain_progression"]   # entitas bertukar peran
        assert e.risk_level == "high", e.risk_score
