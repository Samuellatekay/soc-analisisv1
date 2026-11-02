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
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError

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


def _start_policy_agent(stop: threading.Event) -> None:
    enabled = os.getenv("MASTER_POLICY_AGENT_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
    if not os.getenv("MASTER_URL") or not enabled:
        return
    from services.engine.policy_agent import PolicyAgent, loop as policy_loop

    try:
        agent = PolicyAgent.from_env()
    except ValueError as e:
        log.error("policy agent tidak aktif: %s", e)
        return
    threading.Thread(
        target=policy_loop,
        args=(agent, float(os.getenv("POLICY_POLL_SECONDS", "60")), stop),
        daemon=True,
        name="policy-agent",
    ).start()


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
        threading.Thread(
            target=runner.loop,
            args=(conns, runner.default_sink(s), stop),
            kwargs={"reload_connectors": lambda: runner.load_connectors(s)},
            daemon=True,
            name="connectors",
        ).start()
        log.info("pemantau konfigurasi konektor aktif: %s", [c.name for c, _ in conns])
    _start_policy_agent(stop)
    yield
    stop.set()


app = FastAPI(title="SOC Analisis API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])


@app.get("/api/v1/health")
def health():
    s = get_settings()
    return {"status": "ok", "ingest_mode": s.ingest_mode, "redis": bool(s.redis_url), "elasticsearch": bool(s.es_url),
            "neo4j": bool(s.neo4j_uri), "llm": s.ollama_model or "template-v1(no-llm)"}


def _check_database() -> dict:
    try:
        from services.common.db import get_engine
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
    except SQLAlchemyError:
        log.warning("readiness check failed for database")
        return {"status": "unavailable", "error": "database connection failed"}
    return {"status": "ok"}


def _check_redis(url: str) -> dict:
    if not url:
        return {"status": "not_configured"}
    import redis
    try:
        client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
        client.ping()
        client.close()
    except redis.exceptions.RedisError:
        log.warning("readiness check failed for redis")
        return {"status": "unavailable", "error": "redis connection failed"}
    return {"status": "ok"}


def _check_elasticsearch(url: str, api_key: str = "") -> dict:
    if not url:
        return {"status": "not_configured"}
    import httpx
    try:
        headers = {"Authorization": f"ApiKey {api_key}"} if api_key else None
        response = httpx.get(f"{url.rstrip('/')}/_cluster/health", headers=headers, timeout=2)
        response.raise_for_status()
    except httpx.HTTPError:
        log.warning("readiness check failed for elasticsearch")
        return {"status": "unavailable", "error": "elasticsearch connection failed"}
    return {"status": "ok"}


def _check_neo4j(uri: str, user: str, password: str) -> dict:
    if not uri:
        return {"status": "not_configured"}
    from neo4j import GraphDatabase
    from neo4j.exceptions import Neo4jError
    try:
        with GraphDatabase.driver(uri, auth=(user, password), connection_timeout=2) as driver:
            driver.verify_connectivity()
    except (Neo4jError, OSError):
        log.warning("readiness check failed for neo4j")
        return {"status": "unavailable", "error": "neo4j connection failed"}
    return {"status": "ok"}


@app.get("/api/v1/ready")
def readiness():
    """Readiness check; liveness remains available at /api/v1/health."""
    s = get_settings()
    checks = {
        "database": _check_database(),
        "redis": _check_redis(s.redis_url),
        "elasticsearch": _check_elasticsearch(s.es_url, s.es_api_key),
        "neo4j": _check_neo4j(s.neo4j_uri, s.neo4j_user, s.neo4j_password),
    }
    required = {"database"}
    if s.ingest_mode == "queue":
        required.add("redis")
    if checks["redis"]["status"] == "not_configured" and "redis" in required:
        checks["redis"] = {"status": "unavailable", "error": "REDIS_URL is required for queue ingest"}
    ready = all(checks[name]["status"] == "ok" for name in required)
    return JSONResponse({"status": "ready" if ready else "not_ready", "checks": checks},
                        status_code=200 if ready else 503)


for r in (ingest.router, alerts.router, cases.router, admin.router, connectors.router):
    app.include_router(r, prefix="/api/v1")

if WEB_DIST.exists():
    app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        f = (WEB_DIST / path).resolve()
        return FileResponse(f if f.is_file() and WEB_DIST in f.parents else WEB_DIST / "index.html")
