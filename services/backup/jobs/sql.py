"""Backup basis data kanonis. SQLite: online backup API (konsisten). PostgreSQL: pg_dump -Fc.
Backup base+WAL/PITR, snapshot Elasticsearch, dump Neo4j, dan persistence Redis harus dikonfigurasi di level infrastruktur
(lihat README bagian Backup) — job di bawah hanya menandai komponen tersebut sebagai belum diimplementasikan."""
from __future__ import annotations

import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def run(database_url: str, out_dir: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    if database_url.startswith("sqlite:///"):
        src = database_url.replace("sqlite:///", "", 1)
        dst = out_dir / f"soc-{stamp}.sqlite"
        with sqlite3.connect(src) as a, sqlite3.connect(dst) as b:
            a.backup(b)
        return dst
    if database_url.startswith("postgresql"):
        if not shutil.which("pg_dump"):
            raise RuntimeError("pg_dump tidak ditemukan di PATH")
        dst = out_dir / f"soc-{stamp}.pgdump"
        url = database_url.replace("+psycopg2", "").replace("+psycopg", "")
        subprocess.run(["pg_dump", "-Fc", "--dbname", url, "-f", str(dst)], check=True, timeout=3600)
        return dst
    raise RuntimeError(f"DATABASE_URL tidak didukung: {database_url.split(':')[0]}")


NOT_IMPLEMENTED = {
    "elasticsearch": "gunakan snapshot repository ES (PUT _snapshot/...) — indeks dapat dibangun ulang dari PostgreSQL/outbox",
    "neo4j": "gunakan `neo4j-admin database dump` / backup enterprise; KB juga dapat dibangun ulang dari kb_sync",
    "redis": "aktifkan AOF + salin dump.rdb; antrean bukan data kanonis",
}
