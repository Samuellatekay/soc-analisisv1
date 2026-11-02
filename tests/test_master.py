import os
import tempfile

_d = tempfile.mkdtemp()
os.environ["MASTER_DATABASE_URL"] = f"sqlite:///{_d}/master.db"
os.environ["MASTER_API_TOKENS"] = "m-admin:admin,m-view:viewer"
os.environ["MASTER_EMBEDDED_POLLER"] = "false"

import base64  # noqa: E402
import json  # noqa: E402
from datetime import timedelta  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import ValidationError  # noqa: E402
from sqlalchemy import select  # noqa: E402

from services.common.db import session_scope  # noqa: E402
from services.common.models import AuditLog, PolicyState  # noqa: E402
from services.common.util import utcnow  # noqa: E402
from services.engine.policy_agent import PolicyAgent  # noqa: E402
from services.master import db as mdb  # noqa: E402
from services.master import poller  # noqa: E402
from services.master.policy import PolicyRejected, gen_keypair, sign, validate_policy, verify_bundle  # noqa: E402

PRIV, PUB = gen_keypair()
os.environ["MASTER_SIGNING_KEY"] = PRIV
A, V = {"Authorization": "Bearer m-admin"}, {"Authorization": "Bearer m-view"}


# ---------------------------------------------------------------- skema & batas keamanan
@pytest.mark.parametrize("bad", [
    {"noise": {"pcc_threshold": 0.5}}, {"noise": {"pcc_threshold": 1.0}}, {"fusion": {"retain": 0.4}}, {"fusion": {"filter": 0.9}},
    {"fusion": {"retain": 0.6, "filter": 0.6}}, {"scoring": {"level_high_min": 60}}, {"scoring": {"level_high_min": 80, "level_medium_min": 85}},
    {"scoring": {"criteria_weights": {"target_criticality": 1.0}}},
    {"scoring": {"criteria_weights": dict(target_criticality=.5, attack_stage_hazard=.5, threat_intel_match=.1, attack_feasibility=.1, attack_persistence=.0, environmental=.0)}},
    {"scoring": {"tactic_policy_weight": {"Bukan Taktik": 0.5}}}, {"scoring": {"tactic_policy_weight": {"Impact": 1.5}}},
    {"enrichment": {"timeout_seconds": 0.01}}, {"kb_stale_days": 90},
    {"risk_gate": {"enabled": False}}, {"noise": {"disable_risk_gate": True}}, {"fusion": {"retain": 0.6, "bypass": 1}},   # field tak dikenal ditolak
])
def test_unsafe_or_unknown_policy_rejected(bad):
    with pytest.raises(ValidationError):
        validate_policy(bad)


def test_valid_partial_policy_ok():
    p = validate_policy({"noise": {"pcc_threshold": 0.9}, "fusion": {"retain": 0.65, "filter": 0.25}, "scoring": {"level_high_min": 75}})
    assert p.noise.pcc_threshold == 0.9 and p.scoring.level_medium_min is None


# ---------------------------------------------------------------- tanda tangan
def test_signature_binds_cluster_version_and_content():
    b = sign(PRIV, "c1", 5, {"noise": {"pcc_threshold": 0.9}})
    assert verify_bundle(b, PUB, "c1", 4).noise.pcc_threshold == 0.9
    with pytest.raises(PolicyRejected, match="tanda tangan"):
        verify_bundle({**b, "policy": {"noise": {"pcc_threshold": 0.76}}}, PUB, "c1", 4)           # isi diubah
    with pytest.raises(PolicyRejected, match="tanda tangan"):
        verify_bundle({**b, "version": 9}, PUB, "c1", 4)                                           # versi diubah
    with pytest.raises(PolicyRejected, match="cluster lain"):
        verify_bundle(b, PUB, "c2", 4)                                                             # replay ke cluster lain
    with pytest.raises(PolicyRejected, match="lebih baru"):
        verify_bundle(b, PUB, "c1", 5)                                                             # anti-rollback / replay versi sama
    with pytest.raises(PolicyRejected, match="tanda tangan"):
        verify_bundle(b, gen_keypair()[1], "c1", 4)                                                # kunci Master palsu
    evil = sign(PRIV, "c1", 6, {"noise": {"pcc_threshold": 0.2}})                                  # ditandatangani sah TAPI melanggar batas
    with pytest.raises(PolicyRejected, match="batas keamanan"):
        verify_bundle(evil, PUB, "c1", 5)


# ---------------------------------------------------------------- API Master
@pytest.fixture(scope="module")
def master():
    from apps.master.app.main import app
    with TestClient(app) as c:
        yield c


def reg(c, cid, **kw):
    r = c.post("/api/v1/clusters", json={"id": cid, "name": cid.upper(), "api_url": f"https://{cid}.example", "status_token_env": f"TOK_{cid.upper().replace('-', '_')}", **kw}, headers=A)
    assert r.status_code == 201, r.text
    return r.json()["pull_token"]


def test_master_rbac_and_registry(master):
    assert master.get("/api/v1/clusters").status_code == 401
    assert master.post("/api/v1/clusters", json={"id": "x1", "name": "x", "api_url": "https://x"}, headers=V).status_code == 403
    t1 = reg(master, "dc-a")
    assert reg(master, "dc-b") != t1
    assert master.post("/api/v1/clusters", json={"id": "dc-a", "name": "x", "api_url": "https://x"}, headers=A).status_code == 409
    assert master.post("/api/v1/clusters", json={"id": "Bad ID!", "name": "x", "api_url": "https://x"}, headers=A).status_code == 422
    assert [c["id"] for c in master.get("/api/v1/clusters", headers=V).json()] == ["dc-a", "dc-b"]
    assert "pull_token" not in master.get("/api/v1/clusters", headers=A).text                    # token tidak pernah dibaca ulang


@pytest.fixture(scope="module")
def tokens(master):
    return {"dc-a": master.post("/api/v1/clusters", json={"id": "dc-tok-a", "name": "a", "api_url": "https://a"}, headers=A).json()["pull_token"],
            "dc-b": master.post("/api/v1/clusters", json={"id": "dc-tok-b", "name": "b", "api_url": "https://b"}, headers=A).json()["pull_token"]}


def test_publish_validates_and_targets_canary(master, tokens):
    assert master.post("/api/v1/policies", json={"policy": {"noise": {"pcc_threshold": 0.1}}, "targets": ["*"]}, headers=A).status_code == 422
    assert master.post("/api/v1/policies", json={"policy": {}, "targets": ["nope"]}, headers=A).status_code == 422
    assert master.post("/api/v1/policies", json={"policy": {}, "targets": ["*"]}, headers=V).status_code == 403
    v1 = master.post("/api/v1/policies", json={"policy": {"noise": {"pcc_threshold": 0.9}}, "targets": ["dc-tok-a"], "note": "kanari"}, headers=A).json()["version"]
    ha, hb = {"Authorization": f"Bearer {tokens['dc-a']}"}, {"Authorization": f"Bearer {tokens['dc-b']}"}
    ra = master.get("/api/v1/policy/dc-tok-a", headers=ha)
    assert ra.status_code == 200 and ra.json()["version"] == v1 and verify_bundle(ra.json(), PUB, "dc-tok-a", 0).noise.pcc_threshold == 0.9
    assert master.get("/api/v1/policy/dc-tok-b", headers=hb).status_code == 304                    # di luar target kanari
    assert master.get("/api/v1/policy/dc-tok-a", headers={**ha, "If-None-Match": str(v1)}).status_code == 304
    assert master.get("/api/v1/policy/dc-tok-a", headers=hb).status_code == 401                    # token cluster lain
    assert master.get("/api/v1/policy/dc-tok-a", headers=A).status_code == 401                     # token admin bukan token cluster
    v2 = master.post("/api/v1/policies", json={"policy": {"noise": {"pcc_threshold": 0.9}}, "targets": ["*"], "note": "rollout penuh"}, headers=A).json()["version"]
    assert master.get("/api/v1/policy/dc-tok-b", headers=hb).json()["version"] == v2


def test_rollback_is_republish_with_new_version(master, tokens):
    pols = master.get("/api/v1/policies", headers=V).json()
    old = pols[-1]["version"]
    new = master.post(f"/api/v1/policies/{old}/republish", json=["*"], headers=A).json()["version"]
    assert new > pols[0]["version"]
    assert any("rollback" in p["note"] for p in master.get("/api/v1/policies", headers=V).json())
    assert master.get("/api/v1/audit", headers=V).status_code == 403 and master.get("/api/v1/audit", headers=A).json()


# ---------------------------------------------------------------- agent di cluster
@pytest.fixture
def clean_policy():
    def wipe():
        with session_scope() as s:
            s.query(PolicyState).delete()
    wipe(); yield; wipe()


def agent_for(master, cid, token):
    a = PolicyAgent("http://testserver", cid, token, PUB)
    a.http = master; a.http.headers.update({"Authorization": f"Bearer {token}"})
    return a


def test_agent_applies_policy_and_pipeline_picks_it_up_without_calling_master(master, tokens, clean_policy):
    from services.engine.pipeline import Pipeline
    master.post("/api/v1/policies", json={"policy": {"scoring": {"level_high_min": 70, "level_medium_min": 50}, "fusion": {"retain": 0.7, "filter": 0.2}}, "targets": ["dc-tok-a"]}, headers=A)
    pipe = Pipeline()
    assert pipe.policy_version == 0 and pipe.risk.level(72) == "medium"
    ag = agent_for(master, "dc-tok-a", tokens["dc-a"])
    res = ag.check()
    assert res["status"] == "applied"
    assert ag.check()["status"] == "up_to_date"
    pipe._policy_checked = 0                                             # lewati TTL 30 dtk pada uji
    with session_scope() as s:
        ev, _ = pipe.process(s, {"id": "pol-1", "timestamp": "2026-09-02T10:00:00Z", "signature": "SSH brute force", "src_ip": "203.0.113.45", "dst_ip": "10.0.1.10", "count": 400}, "generic", "pol")
        assert pipe.policy_version == res["version"] and pipe.risk.level(72) == "high" and (pipe.retain, pipe.flt) == (0.7, 0.2)
        assert ev.score_components["policy_version"] == res["version"]    # tiap keputusan mencatat versi kebijakan (audit)


def test_agent_rejects_tampered_wrong_cluster_and_replayed_bundles(master, tokens, clean_policy):
    ag = agent_for(master, "dc-tok-a", tokens["dc-a"])
    assert ag.check()["status"] == "applied"
    applied = ag.check()
    good = master.get("/api/v1/policy/dc-tok-a", headers={"Authorization": f"Bearer {tokens['dc-a']}", "If-None-Match": "0"}).json()
    def serve(bundle):
        a = PolicyAgent("http://m", "dc-tok-a", "t", PUB, transport=httpx.MockTransport(lambda r: httpx.Response(200, json=bundle)))
        return a.check()
    tampered = {**good, "version": good["version"] + 1, "policy": {"noise": {"pcc_threshold": 0.76}}}
    assert serve(tampered)["status"] == "rejected"
    other = sign(PRIV, "dc-tok-b", good["version"] + 1, {})
    assert serve(other)["status"] == "rejected" and "cluster lain" in serve(other)["reason"]
    assert serve(good)["status"] == "rejected" and "lebih baru" in serve(good)["reason"]                   # replay versi lama
    unsafe = sign(PRIV, "dc-tok-a", good["version"] + 1, {"noise": {"pcc_threshold": 0.1}})
    assert serve(unsafe)["reason"].startswith("kebijakan melanggar batas")
    with session_scope() as s:
        st = s.get(PolicyState, 1)
        assert st.version == good["version"] and st.policy == validate_policy(good["policy"]).model_dump(exclude_none=True)   # tidak ada yang berubah
        assert s.scalars(select(AuditLog).where(AuditLog.action == "policy.rejected")).all()


def test_master_down_cluster_keeps_last_policy_and_keeps_processing(master, tokens, clean_policy):
    from services.engine.pipeline import Pipeline
    ag = agent_for(master, "dc-tok-a", tokens["dc-a"]); assert ag.check()["status"] == "applied"
    dead = PolicyAgent("http://master.invalid", "dc-tok-a", "t", PUB, transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("down"))))
    assert dead.check()["status"] == "master_unreachable"
    pipe = Pipeline(); pipe._policy_checked = 0
    with session_scope() as s:
        ev, created = pipe.process(s, {"id": "down-1", "timestamp": "2026-09-02T11:00:00Z", "signature": "scan probe", "src_ip": "10.1.1.1", "dst_ip": "10.0.9.9"}, "generic", "pol")
        assert created and pipe.policy_version > 0                       # event tetap diproses dengan kebijakan terakhir
        st = s.get(PolicyState, 1)
        assert "tidak terjangkau" in st.last_error


# ---------------------------------------------------------------- kesehatan armada
def st(**kw):
    base = {"version": "1.0.0", "policy": {"version": 3}, "outbox_failed": 0, "queue": {"length": 10, "dlq": 0, "pending": 0}, "kb": {"stale": False}, "connectors": {"failing": 0}, "analysis_pending": 0}
    base.update(kw); return base


def test_health_classification():
    now = utcnow()
    c = lambda s, ok=now, tp=3: poller.classify(s, ok, ok, now, 30, tp)  # noqa: E731
    assert c(st())["state"] == "healthy"
    assert c(st(), ok=now - timedelta(seconds=200))["state"] == "unreachable"                      # status basi > 3x interval
    assert poller.classify(None, now, None, now, 30)["state"] == "unreachable"
    r = c(st(outbox_failed=2, queue={"length": 99999, "dlq": 4}, kb={"stale": True}, connectors={"failing": 1}))
    assert r["state"] == "degraded" and len(r["reasons"]) == 5
    assert "kebijakan v3 < target v5" in c(st(), tp=5)["reasons"][0]


def test_poller_stores_status_and_keeps_last_known_on_failure(master, monkeypatch):
    monkeypatch.setenv("TOK_DC_A", "svc-token")
    seen = {}
    def ok(verify):
        def h(req):
            seen["auth"], seen["path"] = req.headers["Authorization"], req.url.path
            return httpx.Response(200, json=st())
        return httpx.Client(transport=httpx.MockTransport(h))
    assert poller.poll_all(ok) >= 1 and seen == {"auth": "Bearer svc-token", "path": "/api/v1/cluster/status"}
    f = {c["id"]: c for c in master.get("/api/v1/clusters", headers=V).json()}
    assert f["dc-a"]["health"]["state"] in ("healthy", "degraded") and f["dc-a"]["app_version"] == "1.0.0"
    assert f["dc-b"]["health"]["state"] == "unreachable" and "token status tidak tersedia" in f["dc-b"]["last_error"]
    def down(verify):
        return httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    poller.poll_all(down)
    f = {c["id"]: c for c in master.get("/api/v1/clusters", headers=V).json()}
    assert f["dc-a"]["last_error"] and f["dc-a"]["app_version"] == "1.0.0"                       # status terakhir diketahui dipertahankan
    summ = master.get("/api/v1/fleet/summary", headers=V).json()
    assert summ["clusters"] >= 2 and "by_state" in summ


def test_cluster_status_endpoint_on_cluster_api():
    from app.main import app as api
    with TestClient(api) as c:
        assert c.get("/api/v1/cluster/status", headers={"Authorization": "Bearer t-viewer"}).status_code == 403
        j = c.get("/api/v1/cluster/status", headers={"Authorization": "Bearer t-admin"}).json()
    assert j["db_ok"] and {"policy", "outbox_failed", "kb", "connectors", "scoring_version"} <= set(j) and "src_ip" not in json.dumps(j)
