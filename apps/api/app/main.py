"""SOC API (FastAPI) — satu-satunya jalur frontend ke data store."""
from __future__ import annotations

import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select

from app.api.v1 import admin, alerts, cases, connectors, ingest
from services.common.config import ROOT, get_settings
from services.common.db import init_db, session_scope
from services.common.models import KBItem

log = logging.getLogger("api")
WEB_DIST = ROOT / "apps" / "web" / "dist"


def _bootstrap_kb():
    from services.kb_sync.importer import import_items
    from services.kb_sync.sources.mitre_attack import load_seed
    s = get_settings()
    with session_scope() as db:
        if not db.scalar(select(func.count()).select_from(KBItem)) and Path(s.kb_seed_file).exists():
            items, ver = load_seed(s.kb_seed_file)
            import_items(db, items, "seed", ver, s)


def _embedded_loop(stop: threading.Event):
    from services.indexer.main import run_once
    from services.rag_worker.worker import process_one
    while not stop.is_set():
        try:
            busy = process_one() | bool(run_once(None))
        except Exception:  # noqa: BLE001
            log.exception("embedded worker error")
            busy = False
        if not busy:
            time.sleep(0.5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _bootstrap_kb()
    stop = threading.Event()
    s = get_settings()
    if s.embedded_workers and not s.es_url:  # dengan ES, jalankan services.indexer.main sebagai proses terpisah
        threading.Thread(target=_embedded_loop, args=(stop,), daemon=True, name="embedded-workers").start()
    if s.embedded_workers and s.embedded_connectors:
        from services.engine.adapters import runner
        conns = runner.load_connectors(s)
        if conns:
            threading.Thread(target=runner.loop, args=(conns, runner.default_sink(s), stop), daemon=True, name="connectors").start()
            log.info("konektor aktif: %s", [c.name for c, _ in conns])
    if os.getenv("MASTER_URL") and s.embedded_workers:   # cluster terkelola Master: tarik kebijakan (opsional)
        from services.engine.policy_agent import PolicyAgent, loop as policy_loop
        try:
            threading.Thread(target=policy_loop, args=(PolicyAgent.from_env(), float(os.getenv("POLICY_POLL_SECONDS", "60")), stop), daemon=True, name="policy-agent").start()
        except ValueError as e:
            log.error("policy agent tidak aktif: %s", e)
    yield
    stop.set()


app = FastAPI(title="SOC Analisis API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])


@app.get("/api/v1/health")
def health():
    s = get_settings()
    return {"status": "ok", "ingest_mode": s.ingest_mode, "redis": bool(s.redis_url), "elasticsearch": bool(s.es_url),
            "neo4j": bool(s.neo4j_uri), "llm": s.ollama_model or "template-v1(no-llm)"}


for r in (ingest.router, alerts.router, cases.router, admin.router, connectors.router):
    app.include_router(r, prefix="/api/v1")

if WEB_DIST.exists():
    app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        f = (WEB_DIST / path).resolve()
        return FileResponse(f if f.is_file() and WEB_DIST in f.parents else WEB_DIST / "index.html")
