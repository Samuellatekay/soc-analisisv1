import json
import os
import sqlite3

import httpx
import pytest

from services.backup import crypto
from services.backup.config import BackupConfig
from services.backup.jobs import elasticsearch as es_job
from services.backup.main import restore, run_backup
from services.common.config import get_settings


@pytest.fixture
def key(tmp_path):
    p = tmp_path / "k"; crypto.genkey(str(p)); return crypto.load_key(str(p))


def test_roundtrip_multichunk(tmp_path, key):
    src = tmp_path / "a.bin"; data = os.urandom(crypto.CHUNK * 2 + 123); src.write_bytes(data)
    enc, dec = tmp_path / "a.enc", tmp_path / "a.dec"
    crypto.encrypt_file(src, enc, key); crypto.decrypt_file(enc, dec, key)
    assert dec.read_bytes() == data and data[:64] not in enc.read_bytes()


def test_empty_file_roundtrip(tmp_path, key):
    src = tmp_path / "e"; src.write_bytes(b""); crypto.encrypt_file(src, tmp_path / "e.enc", key); crypto.decrypt_file(tmp_path / "e.enc", tmp_path / "e.d", key)
    assert (tmp_path / "e.d").read_bytes() == b""


@pytest.mark.parametrize("attack", ["bitflip", "truncate_chunk", "drop_last_chunk", "wrong_key", "append"])
def test_tamper_detected(tmp_path, key, attack):
    src = tmp_path / "a"; src.write_bytes(os.urandom(crypto.CHUNK * 2 + 10))
    enc = tmp_path / "a.enc"; crypto.encrypt_file(src, enc, key)
    b = bytearray(enc.read_bytes())
    k = key
    if attack == "bitflip":
        b[len(b) // 2] ^= 1
    elif attack == "truncate_chunk":
        b = b[:-5]
    elif attack == "drop_last_chunk":   # potong tepat pada batas chunk: tanpa penanda 'last' harus ditolak
        n1 = int.from_bytes(b[11:15], "big"); b = b[: 11 + 4 + n1 + 4 + int.from_bytes(b[15 + n1: 19 + n1], "big")]
    elif attack == "wrong_key":
        k = os.urandom(32)
    elif attack == "append":
        b += b"\x00\x00\x00\x01x"
    enc.write_bytes(bytes(b))
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_file(enc, tmp_path / "o", k)
    assert not (tmp_path / "o").exists()          # tidak meninggalkan plaintext parsial


def test_genkey_refuses_overwrite_and_bad_key(tmp_path):
    p = tmp_path / "k"; crypto.genkey(str(p))
    with pytest.raises(crypto.CryptoError):
        crypto.genkey(str(p))
    assert oct(p.stat().st_mode)[-3:] == "600"
    (tmp_path / "bad").write_text("AAAA")
    with pytest.raises(crypto.CryptoError):
        crypto.load_key(str(tmp_path / "bad"))


def test_encrypted_backup_and_restore_end_to_end(tmp_path):
    kf = tmp_path / "key"; crypto.genkey(str(kf))
    repo = tmp_path / "repo"
    cfg = BackupConfig(True, "0 2 * * *", "Asia/Jakarta", ["postgres"], 30, str(repo), True, str(kf))
    res = run_backup(cfg, get_settings().database_url)
    files = sorted(p.name for p in repo.iterdir())
    assert res["artifacts"][0].endswith(".enc") and not any(f.endswith((".sqlite", ".pgdump")) for f in files)   # plaintext tidak tersisa
    out = restore(cfg, repo / res["artifacts"][0], tmp_path / "restored.bin")
    if res["artifacts"][0].endswith(".sqlite.enc"):
        assert sqlite3.connect(out).execute("select count(*) from sqlite_master").fetchone()[0] > 0
    else:   # PostgreSQL: hasil dekripsi harus berupa dump yang dapat dibaca pg_restore
        import subprocess
        lst = subprocess.run(["pg_restore", "--list", str(out)], capture_output=True, text=True)
        assert lst.returncode == 0 and "events" in lst.stdout
    (repo / res["artifacts"][0]).write_bytes((repo / res["artifacts"][0]).read_bytes()[:-3])
    with pytest.raises(RuntimeError):
        restore(cfg, repo / res["artifacts"][0], tmp_path / "x")


def test_es_snapshot_job_success_and_failure():
    seen = []

    def ok(request):
        seen.append(request)
        return httpx.Response(200, json={"snapshot": {"state": "SUCCESS", "shards": {"total": 3, "failed": 0, "successful": 3}}})

    r = es_job.run("http://es:9200", "repo1", transport=httpx.MockTransport(ok), api_key="encoded-api-key")
    assert r["state"] == "SUCCESS" and r["snapshot"].startswith("soc-")
    assert seen[0].headers["Authorization"] == "ApiKey encoded-api-key"
    bad = lambda r: httpx.Response(200, json={"snapshot": {"state": "PARTIAL", "shards": {"total": 3, "failed": 1}}})  # noqa: E731
    with pytest.raises(RuntimeError):
        es_job.run("http://es:9200", "repo1", transport=httpx.MockTransport(bad))
