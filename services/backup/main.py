"""Worker backup terjadwal (cron dari .env) -> artefak + manifest checksum -> verifikasi -> retensi.
python -m services.backup.main [--once]"""
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from croniter import croniter

from services.common.config import get_settings
from services.backup.config import BackupConfig
from services.backup import crypto
from services.backup.jobs import elasticsearch as es_job
from services.backup.jobs import neo4j_export, redis_dump
from services.backup.jobs import sql
from services.backup.retention import prune
from services.backup.verify import verify_artifact, write_manifest

log = logging.getLogger("backup")


def _produce(comp: str, cfg: BackupConfig, repo: Path, database_url: str) -> Path | None:
    """Hasilkan artefak plaintext per komponen; None = komponen dilewati."""
    st = get_settings()
    if comp in ("postgres", "sql", "sqlite"):
        return sql.run(database_url, repo)
    if comp == "redis":
        return redis_dump.run(st.redis_url, repo) if st.redis_url else None
    if comp == "neo4j":
        if not (st.neo4j_uri and st.neo4j_password):
            return None
        return neo4j_export.export(neo4j_export.Neo4jStore(st.neo4j_uri, st.neo4j_user, st.neo4j_password), repo)
    return None


def run_backup(cfg: BackupConfig, database_url: str) -> dict:
    errs = cfg.validate()
    if errs:
        raise RuntimeError("; ".join(errs))
    repo = Path(cfg.repository)
    result: dict = {"artifacts": [], "skipped": {}}
    for comp in cfg.components:
        if comp == "elasticsearch":
            if os.getenv("BACKUP_ES_REPOSITORY"):
                result.setdefault("snapshots", []).append(es_job.run(get_settings().es_url, os.environ["BACKUP_ES_REPOSITORY"]))
            else:
                result["skipped"][comp] = "BACKUP_ES_REPOSITORY belum diset (snapshot repository ES harus didaftarkan lebih dulu)"
            continue
        if comp not in ("postgres", "sql", "sqlite", "redis", "neo4j"):
            result["skipped"][comp] = "komponen tidak dikenal"
            continue
        art = _produce(comp, cfg, repo, database_url)
        if art is None:
            result["skipped"][comp] = "tidak dikonfigurasi (REDIS_URL / NEO4J_URI+NEO4J_PASSWORD kosong)"
            continue
        meta = {"component": comp, "created": datetime.utcnow().isoformat() + "Z", "encrypted": None}
        if cfg.key_file:   # enkripsi at-rest: plaintext dihapus setelah ciphertext tertulis
            from services.backup.verify import sha256_file
            meta.update(encrypted="AES-256-GCM", plaintext_sha256=sha256_file(art))
            enc = art.with_suffix(art.suffix + ".enc")
            crypto.encrypt_file(art, enc, crypto.load_key(cfg.key_file))
            art.unlink()
            art = enc
        write_manifest(art, meta)
        if cfg.verify_after_run:
            ok, msg = verify_artifact(art)
            if not ok:
                raise RuntimeError(f"verifikasi backup gagal: {msg}")
        result["artifacts"].append(art.name)
    result["pruned"] = prune(repo, cfg.retention_days)
    return result


def restore(cfg: BackupConfig, artifact: Path, out: Path) -> Path:
    """Verifikasi checksum -> dekripsi (bila .enc) -> verifikasi checksum plaintext. SQLite: salin ke `out`; PostgreSQL: jalankan pg_restore pada hasilnya."""
    from services.backup.verify import sha256_file
    ok, msg = verify_artifact(artifact)
    if not ok:
        raise RuntimeError(f"artefak tidak valid: {msg}")
    if artifact.suffix != ".enc":
        out.write_bytes(artifact.read_bytes())
        return out
    if not cfg.key_file:
        raise RuntimeError("artefak terenkripsi; set BACKUP_ENCRYPTION_KEY_FILE")
    crypto.decrypt_file(artifact, out, crypto.load_key(cfg.key_file))
    meta = json.loads(artifact.with_suffix(artifact.suffix + ".manifest.json").read_text())
    if meta.get("plaintext_sha256") and sha256_file(out) != meta["plaintext_sha256"]:
        out.unlink(missing_ok=True)
        raise RuntimeError("checksum plaintext tidak cocok setelah dekripsi")
    return out


def loop(cfg: BackupConfig):
    errs = cfg.validate()
    if errs:
        raise ValueError("; ".join(errs))
    s = get_settings()
    tz = ZoneInfo(cfg.timezone)
    it = croniter(cfg.cron, datetime.now(tz))
    nxt = it.get_next(datetime)
    while True:
        if datetime.now(tz) >= nxt:
            try:
                log.info("backup selesai: %s", run_backup(cfg, s.database_url))
            except Exception:  # noqa: BLE001  gagal -> log error (hubungkan ke alerting Anda)
                log.exception("BACKUP GAGAL")
            nxt = it.get_next(datetime)
        time.sleep(20)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ap = argparse.ArgumentParser(); ap.add_argument("--once", action="store_true")
    ap.add_argument("--restore", metavar="ARTEFAK"); ap.add_argument("--out", metavar="TUJUAN"); a = ap.parse_args()
    cfg = BackupConfig.from_env()
    if a.restore:
        print(restore(cfg, Path(a.restore), Path(a.out or "restored.bin"))); raise SystemExit(0)
    if not cfg.enabled and not a.once:
        raise SystemExit("BACKUP_ENABLED=false")
    print(run_backup(cfg, get_settings().database_url)) if a.once else loop(cfg)
