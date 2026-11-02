"""Jalankan seluruh stack development (API + worker tertanam + UI hasil build) dengan satu perintah.

    python run_dev.py            # http://localhost:8000
Env dari .env (jika ada). Tidak butuh Docker/Redis/PostgreSQL: memakai SQLite + antrean in-process.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(ROOT / "apps" / "api")]
envf = ROOT / ".env"
if envf.exists():
    for line in envf.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            v = v.split(" #")[0].strip().strip('"')   # buang komentar inline
            if v:
                os.environ.setdefault(k.strip(), v)
os.environ.setdefault("API_TOKENS", "dev-admin-token:admin:default,dev-analyst-token:analyst:default,dev-viewer-token:viewer:default")
os.environ.setdefault("INGEST_API_KEY", "dev-ingest-key:default")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")), log_level="info")
