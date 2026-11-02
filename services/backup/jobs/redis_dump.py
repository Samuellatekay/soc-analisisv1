"""Backup/restore Redis lewat DUMP/RESTORE (remote-safe, tanpa akses filesystem server). Mencakup stream + consumer group + PEL.
Batasan: key di-dump berurutan (BUKAN snapshot point-in-time yang konsisten antar-key). Antrean bukan data kanonis (event ada di PostgreSQL);
yang dilindungi di sini terutama pesan yang belum diproses. Alternatif konsisten: AOF/RDB di level server."""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

MAGIC = b"SOCRDS1\n"


def run(redis_url: str, out_dir: Path, pattern: str = "soc:*", client=None) -> Path:
    if client is None:
        import redis
        client = redis.Redis.from_url(redis_url)
    out_dir.mkdir(parents=True, exist_ok=True)
    dst = out_dir / f"redis-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.rdsdump"
    n = 0
    with dst.open("wb") as f:
        f.write(MAGIC)
        for key in client.scan_iter(match=pattern, count=500):
            data = client.dump(key)
            if data is None:          # key kedaluwarsa/terhapus saat scan
                continue
            ttl = client.pttl(key)
            ttl = ttl if ttl and ttl > 0 else 0
            f.write(struct.pack(">I", len(key)) + key + struct.pack(">qI", ttl, len(data)) + data)
            n += 1
    if n == 0:
        dst.unlink()
        raise RuntimeError(f"tidak ada key cocok '{pattern}' untuk di-backup")
    return dst


def restore(redis_url: str, src: Path, replace: bool = False, client=None) -> int:
    if client is None:
        import redis
        client = redis.Redis.from_url(redis_url)
    n = 0
    with src.open("rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise RuntimeError("format dump Redis tidak dikenal")
        while True:
            h = f.read(4)
            if not h:
                break
            key = f.read(struct.unpack(">I", h)[0])
            ttl, dl = struct.unpack(">qI", f.read(12))
            data = f.read(dl)
            if len(data) != dl:
                raise RuntimeError("dump terpotong")
            client.restore(key, ttl, data, replace=replace)   # replace=False: gagal bila key sudah ada (aman dari menimpa)
            n += 1
    return n
