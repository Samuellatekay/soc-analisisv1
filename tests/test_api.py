import pytest
from fastapi.testclient import TestClient

from app.main import app

A = {"Authorization": "Bearer t-analyst"}
V = {"Authorization": "Bearer t-viewer"}
AD = {"Authorization": "Bearer t-admin"}
OTHER = {"Authorization": "Bearer t-other"}
IK = {"X-Ingest-Key": "ingest-key"}


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as cl:
        yield cl


def ingest(c, n=1, **kw):
    ev = [{"id": f"api-{kw.get('p', '')}{i}", "timestamp": "2026-10-30T10:00:00Z", "signature": "SSH brute force failed login",
           "src_ip": "203.0.113.45", "dst_ip": "10.0.1.10", "count": 300} for i in range(n)]
    return c.post("/api/v1/ingest/generic", json={"events": ev}, headers=IK)


def test_auth_required(c):
    assert c.get("/api/v1/alerts").status_code == 401
    assert c.post("/api/v1/ingest/generic", json={"events": []}).status_code == 401
    assert c.get("/api/v1/health").status_code == 200


def test_ingest_list_detail_and_tenant_isolation(c):
    r = ingest(c, 3)
    assert r.json()["accepted"] == 3
    assert ingest(c, 3).json()["duplicates"] == 3          # idempoten
    lst = c.get("/api/v1/alerts?risk_level=medium&page_size=2", headers=V).json()
    assert lst["total"] >= 1 and len(lst["items"]) <= 2
    eid = c.get("/api/v1/alerts", headers=V).json()["items"][0]["event_id"]
    d = c.get(f"/api/v1/alerts/{eid}", headers=V).json()
    assert d["score_components"]["scoring_version"] == "ahp-paper-v1.0" and d["orchestration"]["risk_gate"]["G"] == 1
    assert c.get(f"/api/v1/alerts/{eid}", headers=OTHER).status_code == 404          # lintas tenant
    assert c.get("/api/v1/alerts", headers=OTHER).json()["total"] == 0


def test_validation_and_sort_whitelist(c):
    r = c.post("/api/v1/ingest/generic", json={"events": [{"id": "", "timestamp": "x"}]}, headers=IK).json()
    assert r["rejected"]
    assert c.get("/api/v1/alerts?sort=payload", headers=V).status_code == 422
    assert c.get("/api/v1/alerts?page_size=9999", headers=V).status_code == 422


def test_alert_search_includes_domain_and_hash(c):
    from services.common.util import stable_event_id

    ev = {"id": "entity-search-1", "timestamp": "2026-10-30T10:00:00Z", "signature": "Suspicious file",
          "domain": "malicious.example", "hash": "a" * 64}
    assert c.post("/api/v1/ingest/generic", json={"events": [ev]}, headers=IK).json()["accepted"] == 1
    for query in ("malicious.example", "a" * 64):
        result = c.get("/api/v1/alerts", params={"q": query}, headers=V).json()
        assert any(row["event_id"] == stable_event_id("default", "generic", "entity-search-1") for row in result["items"])


def test_rbac_and_case_workflow(c):
    eid = c.get("/api/v1/alerts", headers=V).json()["items"][0]["event_id"]
    assert c.post("/api/v1/cases", json={"title": "Investigasi SSH"}, headers=V).status_code == 403
    cs = c.post("/api/v1/cases", json={"title": "Investigasi SSH", "event_ids": [eid]}, headers=A).json()
    cid = cs["case_id"]
    assert cs["event_ids"] == [eid] and cs["status"] == "New"
    assert c.patch(f"/api/v1/cases/{cid}", json={"status": "Resolved"}, headers=A).status_code == 409      # lompat status
    for st in ("Triage", "Investigating", "Resolved", "Closed"):
        assert c.patch(f"/api/v1/cases/{cid}", json={"status": st}, headers=A).status_code == 200
    assert c.patch(f"/api/v1/cases/{cid}", json={"status": "New"}, headers=A).status_code == 409
    c.post(f"/api/v1/cases/{cid}/notes", json={"text": "catatan"}, headers=A)
    d = c.get(f"/api/v1/cases/{cid}", headers=V).json()
    assert len(d["notes"]) == 1 and any(h["action"] == "case.update" for h in d["history"])
    assert c.get(f"/api/v1/cases/{cid}", headers=OTHER).status_code == 404
    assert c.post(f"/api/v1/cases", json={"title": "x" * 5, "event_ids": [eid]}, headers=OTHER).status_code == 404  # alert milik tenant lain


def test_analysis_worker_completes_with_sources(c):
    from services.rag_worker.worker import process_one
    while process_one():
        pass
    eid = c.get("/api/v1/alerts?analysis_status=completed", headers=V).json()["items"][0]["event_id"]
    a = c.get(f"/api/v1/alerts/{eid}/analysis", headers=V).json()
    assert a["status"] == "completed" and a["sources"] and a["model"].startswith("template")
    allowed = {"event"} | {s["source_id"] for s in a["sources"]}
    assert all(x["source"] in allowed for x in a["result"]["supporting_evidence"])


def test_dashboard_audit_and_scoring_verify(c):
    s = c.get("/api/v1/dashboard/summary", headers=V).json()
    assert s["total"] >= 1 and "noise_reduction_rate" in s
    assert c.get("/api/v1/audit", headers=A).status_code == 403
    assert c.get("/api/v1/audit", headers=AD).status_code == 200
    v = c.get("/api/v1/config/scoring/verify", headers=A).json()
    assert v["consistency_ratio_recomputed"] < 0.1 and len(v["criteria"]) == 6


def test_dashboard_outbox_counts_are_tenant_scoped(c):
    from sqlalchemy import func, select
    from services.common.db import session_scope
    from services.common.models import Event, Outbox
    from services.common.util import utcnow

    with session_scope() as db:
        db.add(Event(event_id="other-tenant-event", tenant_id="other", source="test", source_event_id="other-tenant-event",
                     event_time=utcnow(), triplet_key="other-tenant"))
        db.add(Outbox(event_id="other-tenant-event", status="pending"))
    expected = None
    with session_scope() as db:
        expected = db.scalar(select(func.count()).select_from(Outbox).join(Event, Event.event_id == Outbox.event_id)
                             .where(Event.tenant_id == "default", Outbox.status == "pending"))
    response = c.get("/api/v1/dashboard/summary", headers=V).json()
    assert response["outbox_pending"] == expected


def test_indexer_marks_indexed(c):
    from services.indexer.main import run_once
    run_once(None)
    assert c.get("/api/v1/alerts?processing_status=indexed", headers=V).json()["total"] >= 1


def test_connectors_api_hides_params_and_respects_tenant(tmp_path):
    import json
    from services.common.config import get_settings
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"connectors": [
        {"name": "cs-a", "type": "crowdstrike", "tenant_id": "default", "enabled": False, "params": {"client_id": "TOPSECRET-ID", "client_secret_env": "X", "base_url": "https://internal-host"}},
        {"name": "cs-b", "type": "crowdstrike", "tenant_id": "other", "enabled": False, "params": {}}]}))
    s = get_settings(); old = s.connectors_config; s.connectors_config = str(cfg)
    try:
        with TestClient(app) as c:
            r = c.get("/api/v1/connectors", headers=A)
            assert [x["name"] for x in r.json()] == ["cs-a"] and "TOPSECRET-ID" not in r.text and "internal-host" not in r.text
            assert c.get("/api/v1/connectors", headers=V).status_code == 403
            assert c.post("/api/v1/connectors/cs-b/test", headers=AD).status_code == 404       # milik tenant lain
            assert c.post("/api/v1/connectors/cs-a/test", headers=A).status_code == 403        # hanya admin
    finally:
        s.connectors_config = old


def test_search_matches_vendor_event_id(c):
    ingest(c, 1, p="vend")
    r = c.get("/api/v1/alerts?q=api-vend0", headers=V).json()
    assert r["total"] >= 1 and r["items"][0]["event_id"] != "api-vend0"       # dicari dengan ID asli vendor, hasil memakai event_id internal
