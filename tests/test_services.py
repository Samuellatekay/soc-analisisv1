from datetime import timedelta
from pathlib import Path

import fakeredis

from services.backup.config import BackupConfig
from services.backup.main import run_backup
from services.backup.retention import prune
from services.backup.verify import verify_artifact
from services.common.db import session_scope
from services.common.models import KBItem, Lease
from services.common.util import utcnow
from services.engine.consumers.queue import RedisStreamQueue
from services.kb_sync import scheduler
from services.kb_sync.importer import import_items, rollback
from services.kb_sync.sources.mitre_attack import parse_stix


def test_queue_retry_dlq_replay():
    q = RedisStreamQueue(fakeredis.FakeRedis(), max_attempts=2)
    q.push({"raw": {}, "source": "x", "tenant_id": "t"})
    m = q.read(block_ms=10)[0]
    q.fail(m, "e1")
    m = q.read(block_ms=10)[0]
    assert m.data["_attempts"] == 1
    q.fail(m, "e2")
    assert q.lag()["dlq"] == 1 and q.replay_dlq() == 1 and q.lag()["length"] == 1


def test_engine_batch_size_is_bounded_and_configurable(monkeypatch):
    from services.engine.main import _batch_size

    monkeypatch.delenv("ENGINE_BATCH_SIZE", raising=False)
    assert _batch_size() == 10
    monkeypatch.setenv("ENGINE_BATCH_SIZE", "1")
    assert _batch_size() == 1
    monkeypatch.setenv("ENGINE_BATCH_SIZE", "101")
    try:
        _batch_size()
    except SystemExit as exc:
        assert "1..100" in str(exc)
    else:
        raise AssertionError("out-of-range batch size must stop the worker")


def test_lease_failover():
    with session_scope() as s:
        assert scheduler.acquire_lease(s, "t", "A")
    with session_scope() as s:
        assert not scheduler.acquire_lease(s, "t", "B")          # A masih memegang
        s.get(Lease, "t").expires_at = utcnow() - timedelta(seconds=1)   # A mati, lease kedaluwarsa
    with session_scope() as s:
        assert scheduler.acquire_lease(s, "t", "B")              # B mengambil alih


def test_importer_idempotent_validate_rollback():
    item = {"item_id": "T9999", "kind": "technique", "data": {"id": "T9999", "name": "X", "tactics": ["Impact"]}}
    bad = {"item_id": "bogus", "kind": "technique", "data": {}}
    with session_scope() as s:
        r1 = import_items(s, [item], "t", "v1")
        r2 = import_items(s, [item], "t", "v1")
        assert (r1.added, r2.unchanged) == (1, 1)
        item2 = {**item, "data": {**item["data"], "name": "Y"}}
        r3 = import_items(s, [item2], "t", "v2")
        assert r3.updated == 1 and s.get(KBItem, "T9999").data["name"] == "Y"
        rollback(s, r3.id)
        assert s.get(KBItem, "T9999").data["name"] == "X"
        r4 = import_items(s, [item] + [bad] * 10, "t", "v3")
        assert r4.status == "failed"                              # terlalu banyak item invalid -> rilis ditolak


def test_kb_retrieval_enforces_tenant_scope_and_freshness():
    from datetime import timedelta
    from services.common.models import KBItem
    from services.rag_worker.retrieval.graph import DBRetriever

    with session_scope() as s:
        s.add_all([
            KBItem(item_id="T9876", kind="technique", data={"id": "T9876", "name": "Alpha only", "tactics": ["Discovery"],
                   "tenant_ids": ["alpha"]}, source="test", version="1"),
            KBItem(item_id="T9877", kind="technique", data={"id": "T9877", "name": "Shared", "tactics": ["Discovery"]},
                   source="test", version="1"),
            KBItem(item_id="T9878", kind="technique", data={"id": "T9878", "name": "Stale", "tactics": ["Discovery"]},
                   source="test", version="1", updated_at=utcnow() - timedelta(days=4)),
        ])

    retriever = DBRetriever(stale_days=3)
    assert {d.source_id for d in retriever.retrieve("alpha", "T9876", "test", None)} == {"T9876"}
    assert not retriever.retrieve("beta", "T9876", "test", None)
    assert {d.source_id for d in retriever.retrieve("alpha", "T9877", "test", None)} == {"T9877"}
    assert {d.source_id for d in retriever.retrieve("beta", "T9877", "test", None)} == {"T9877"}


def test_kb_import_rejects_invalid_tenant_scope():
    from services.kb_sync.importer import validate

    item = {"item_id": "T9879", "kind": "technique", "data": {"id": "T9879", "name": "Scoped",
            "tactics": ["Discovery"], "tenant_ids": []}}
    assert validate(item) == "tenant_ids harus berupa daftar tenant yang tidak kosong"


def test_parse_stix_skips_revoked():
    b = {"objects": [
        {"type": "attack-pattern", "name": "A", "external_references": [{"source_name": "mitre-attack", "external_id": "T1001"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]},
        {"type": "attack-pattern", "revoked": True, "name": "B", "external_references": [{"source_name": "mitre-attack", "external_id": "T1002"}]}]}
    items, _ = parse_stix(b)
    assert [i["item_id"] for i in items] == ["T1001"] and items[0]["data"]["tactics"] == ["Command And Control"]


def test_backup_verify_and_retention(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    cfg = BackupConfig(True, "0 2 * * *", "Asia/Jakarta", ["postgres", "redis"], 30, str(repo), True, "")
    from services.common.config import get_settings
    res = run_backup(cfg, get_settings().database_url)
    art = repo / res["artifacts"][0]
    assert verify_artifact(art)[0] and "redis" in res["skipped"]
    art.write_bytes(art.read_bytes() + b"x")                       # korupsi -> terdeteksi
    assert not verify_artifact(art)[0]
    assert prune(repo, 30, now=utcnow().timestamp() + 40 * 86400)


def test_migration_sql_matches_models():
    """migrations/0001_init.sql harus memuat semua tabel model (cegah migrasi basi)."""
    import re
    from pathlib import Path
    from services.common.models import Base
    sql = (Path(__file__).resolve().parents[1] / "migrations" / "0001_init.sql").read_text()
    assert set(re.findall(r"CREATE TABLE (\w+)", sql)) == set(Base.metadata.tables)


def _mk_msgs(q, items):
    for it in items:
        q.push({"raw": it, "source": "generic", "tenant_id": "bat"})
    return q.read(count=50, block_ms=10)


def _ev(i, **kw):
    return {"id": f"b-{i}", "timestamp": "2026-09-01T10:00:00Z", "signature": "scan probe", "src_ip": "10.1.1.1", "dst_ip": "10.0.9.9", **kw}


def test_engine_batch_acks_after_commit_and_isolates_bad_events():
    from sqlalchemy import select
    from services.common.models import Event
    from services.engine import main as eng
    from services.engine.pipeline import Pipeline
    q = RedisStreamQueue(fakeredis.FakeRedis(), max_attempts=2)
    msgs = _mk_msgs(q, [_ev(1), {"id": "", "timestamp": "x"}, _ev(2), _ev(3)])
    eng.handle_batch(Pipeline(), q, msgs)
    with session_scope() as s:
        assert {e.source_event_id for e in s.scalars(select(Event).where(Event.tenant_id == "bat"))} == {"b-1", "b-2", "b-3"}
    assert q.lag() == {"length": 0, "dlq": 1, "pending": 0}          # event tak valid -> DLQ; 3 lainnya ter-ack


def test_engine_batch_commit_failure_falls_back_per_event_without_loss(monkeypatch):
    from sqlalchemy import select
    from services.common.models import Event
    from services.engine import main as eng
    from services.engine.pipeline import Pipeline
    q = RedisStreamQueue(fakeredis.FakeRedis(), max_attempts=3)
    msgs = _mk_msgs(q, [_ev(10), _ev(11), _ev(12)])
    real, calls = eng.session_scope, {"n": 0}
    from contextlib import contextmanager
    @contextmanager
    def flaky():
        calls["n"] += 1
        with real() as s:
            yield s
            if calls["n"] == 1:
                raise RuntimeError("deadlock detected (simulasi)")     # gagal tepat saat commit batch
    monkeypatch.setattr(eng, "session_scope", flaky)
    eng.handle_batch(Pipeline(), q, msgs)
    with session_scope() as s:
        assert {e.source_event_id for e in s.scalars(select(Event).where(Event.tenant_id == "bat"))} >= {"b-10", "b-11", "b-12"}
    assert q.lag() == {"length": 0, "dlq": 0, "pending": 0}              # tidak ada yang hilang / salah masuk DLQ
