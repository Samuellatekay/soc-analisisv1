import json

import pytest
import redis

from services.backup import crypto
from services.backup.config import BackupConfig
from services.backup.jobs import neo4j_export as nx
from services.backup.jobs import redis_dump
from services.backup.main import restore as restore_artifact
from services.backup.main import run_backup
from services.common.config import get_settings

RURL = "redis://127.0.0.1:6379/15"


@pytest.fixture
def r():
    c = redis.Redis.from_url(RURL)
    try:
        c.ping()
    except redis.ConnectionError:
        pytest.skip("redis-server tidak tersedia")
    c.flushdb()
    yield c
    c.flushdb()


def seed_stream(c):
    c.xgroup_create("soc:events", "engine", id="0", mkstream=True)
    ids = [c.xadd("soc:events", {"d": json.dumps({"n": i})}) for i in range(5)]
    c.xreadgroup("engine", "w1", {"soc:events": ">"}, count=2)       # 2 pesan pending (PEL) milik w1
    c.set("soc:flag", "x", px=600_000)
    c.set("other:key", "tidak ikut")
    return ids


def test_redis_dump_restore_roundtrip_with_real_redis(r, tmp_path):
    ids = seed_stream(r)
    f = redis_dump.run(RURL, tmp_path)
    r.flushdb()
    assert r.dbsize() == 0
    assert redis_dump.restore(RURL, f) == 2                           # hanya soc:* (other:key tidak ikut)
    assert [i for i, _ in r.xrange("soc:events")] == ids               # isi stream identik (termasuk ID)
    assert r.xpending("soc:events", "engine")["pending"] == 2          # consumer group + PEL ikut pulih
    assert 0 < r.pttl("soc:flag") <= 600_000 and r.exists("other:key") == 0
    with pytest.raises(redis.ResponseError):                           # tanpa replace: tidak menimpa key yang ada
        redis_dump.restore(RURL, f)
    assert redis_dump.restore(RURL, f, replace=True) == 2


def test_redis_dump_empty_pattern_fails_loudly(r, tmp_path):
    with pytest.raises(RuntimeError):
        redis_dump.run(RURL, tmp_path, pattern="nomatch:*")


def test_redis_truncated_dump_detected(r, tmp_path):
    seed_stream(r)
    f = redis_dump.run(RURL, tmp_path)
    f.write_bytes(f.read_bytes()[:-7])
    r.flushdb()
    with pytest.raises(Exception):
        redis_dump.restore(RURL, f)


def test_redis_backup_encrypted_through_main_pipeline(r, tmp_path, monkeypatch):
    seed_stream(r)
    s = get_settings(); monkeypatch.setattr(s, "redis_url", RURL)
    kf = tmp_path / "k"; crypto.genkey(str(kf))
    cfg = BackupConfig(True, "0 2 * * *", "Asia/Jakarta", ["redis", "neo4j"], 30, str(tmp_path / "repo"), True, str(kf))
    res = run_backup(cfg, s.database_url)
    assert res["artifacts"][0].endswith(".rdsdump.enc") and "neo4j" in res["skipped"]
    out = restore_artifact(cfg, tmp_path / "repo" / res["artifacts"][0], tmp_path / "plain.rdsdump")
    r.flushdb()
    assert redis_dump.restore(RURL, out) == 2 and r.xlen("soc:events") == 5


def test_neo4j_logical_export_restore_is_idempotent(tmp_path):
    a = nx.MemoryStore()
    a.merge_node("Technique", {"id": "T1110", "name": "Brute Force", "description": "d"})
    a.merge_node("Tactic", {"name": "Credential Access"})
    a.merge_node("Playbook", {"id": "playbook:brute_force", "title": "PB", "steps": ["a", "b"]})
    a.merge_rel("IN_TACTIC", {"label": "Technique", "key": "T1110"}, {"label": "Tactic", "key": "Credential Access"})
    f = nx.export(a, tmp_path)
    b = nx.MemoryStore()
    assert nx.restore(b, f) == {"nodes": 3, "rels": 1}
    assert nx.restore(b, f) == {"nodes": 3, "rels": 1}                 # ulang: tetap sama (MERGE)
    assert sorted(map(json.dumps, b.nodes())) == sorted(map(json.dumps, a.nodes())) and b.rels() == a.rels()


def test_neo4j_export_rejects_empty_graph_and_bad_files(tmp_path):
    with pytest.raises(RuntimeError):
        nx.export(nx.MemoryStore(), tmp_path)
    bad = tmp_path / "x.json"; bad.write_text(json.dumps({"format": "other"}))
    with pytest.raises(RuntimeError):
        nx.restore(nx.MemoryStore(), bad)
    evil = tmp_path / "y.json"; evil.write_text(json.dumps({"format": "soc-kg-v1", "nodes": [{"label": "Admin) DETACH DELETE (n", "props": {"id": "x"}}], "rels": []}))
    with pytest.raises(RuntimeError):                                   # label di luar allowlist ditolak (anti injeksi Cypher)
        nx.restore(nx.MemoryStore(), evil)
