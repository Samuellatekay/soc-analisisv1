"""Runner konektor: poll -> serahkan ke pipeline (inline) atau Redis Streams -> baru majukan cursor (checkpoint).

  python -m services.engine.adapters.runner            # loop semua konektor yang enabled
  python -m services.engine.adapters.runner --once     # satu siklus
  python -m services.engine.adapters.runner --test NAMA  # uji koneksi tanpa menyimpan data
Cursor HANYA maju setelah seluruh event pada halaman diterima pipeline/antrean (at-least-once; duplikat dibuang oleh event_id idempoten).
"""
from __future__ import annotations

import argparse
import json
import logging
import threading
import time
from pathlib import Path
from typing import Callable

from services.common.config import Settings, get_settings, read_secret
from services.common.db import init_db, session_scope
from services.common.models import ConnectorConfig, ConnectorState
from services.common.util import utcnow

from .base import Connector
from .http import AdapterError
from .vendors import REGISTRY

log = logging.getLogger("connectors")
Sink = Callable[[list[dict], str, str], tuple[int, int, list[str]]]  # (events, source, tenant) -> (accepted, duplicates, rejected msgs)


def _record_config_error(c: dict, msg: str) -> None:
    try:
        with session_scope() as db:
            st = db.get(ConnectorState, c["name"]) or ConnectorState(name=c["name"], tenant_id=c.get("tenant_id", "default"), type=c["type"])
            st.last_error, st.consecutive_failures = f"konfigurasi tidak valid: {msg}"[:300], max(1, st.consecutive_failures or 0)
            db.merge(st)
    except Exception:  # noqa: BLE001  DB belum siap: cukup log
        log.exception("gagal mencatat error konfigurasi konektor %s", c.get("name"))


def connector_configs(s: Settings) -> list[dict]:
    """Merge DB-managed configurations over file-based defaults."""
    p = Path(s.connectors_config)
    configs = json.loads(p.read_text()).get("connectors", []) if p.exists() else []
    merged = {(c.get("tenant_id", "default"), c["name"]): c for c in configs}
    with session_scope() as db:
        for saved in db.query(ConnectorConfig).all():
            merged[(saved.tenant_id, saved.name)] = {
                "name": saved.name,
                "type": saved.type,
                "tenant_id": saved.tenant_id,
                "enabled": saved.enabled,
                "poll_seconds": saved.poll_seconds,
                "batch_size": saved.batch_size,
                "initial_lookback_hours": saved.initial_lookback_hours,
                "params": saved.params or {},
            }
    return list(merged.values())


def load_connectors(s: Settings, secret=read_secret, only_enabled: bool = True, name: str | None = None) -> list[tuple[Connector, dict]]:
    """Load DB-managed configs over file defaults; skip invalid params without stopping other connectors."""
    out = []
    for c in connector_configs(s):
        if (only_enabled and not c.get("enabled", False)) or (name and c["name"] != name):
            continue
        cls = REGISTRY.get(c["type"])
        if not cls:
            raise ValueError(f"tipe konektor tidak dikenal: {c['type']} (tersedia: {sorted(REGISTRY)})")
        try:
            out.append((cls(c["name"], c.get("params", {}), secret), c))
        except AdapterError as e:
            log.error("konektor %s dilewati: %s", c["name"], e)
            if only_enabled:
                _record_config_error(c, str(e))
    return out


def inline_sink(pipeline) -> Sink:
    from services.engine.normalizer.core import ValidationError

    def sink(events, source, tenant):
        acc = dup = 0
        rej: list[str] = []
        with session_scope() as db:
            for raw in events:
                try:
                    with db.begin_nested():
                        _, created = pipeline.process(db, raw, source, tenant)
                    acc, dup = acc + created, dup + (not created)
                except ValidationError as e:
                    rej.append(str(e))
        return acc, dup, rej
    return sink


def queue_sink(queue) -> Sink:
    def sink(events, source, tenant):
        for raw in events:
            queue.push({"raw": raw, "source": source, "tenant_id": tenant})
        return len(events), 0, []
    return sink


def default_sink(s: Settings) -> Sink:
    if s.ingest_mode == "queue" and s.redis_url:
        from services.engine.consumers.queue import get_queue
        return queue_sink(get_queue(s.redis_url, consumer="connectors"))
    from services.engine.pipeline import Pipeline
    return inline_sink(Pipeline(s))


def _state(db, conn: Connector, cfg: dict) -> ConnectorState:
    st = db.get(ConnectorState, conn.name)
    if not st:
        st = ConnectorState(name=conn.name, tenant_id=cfg.get("tenant_id", "default"), type=conn.type,
                            cursor=conn.initial_cursor(int(cfg.get("initial_lookback_hours", 24))), mapping_version=conn.mapping_version)
        db.add(st)
    return st


def run_once(conn: Connector, cfg: dict, sink: Sink, max_pages: int = 20, batch_size: int | None = None) -> dict:
    tenant, limit = cfg.get("tenant_id", "default"), batch_size or int(cfg.get("batch_size", 500))
    with session_scope() as db:
        st = _state(db, conn, cfg)
        cursor = st.cursor
    summary = {"name": conn.name, "accepted": 0, "duplicates": 0, "rejected": 0, "pages": 0, "error": None}
    base_overlap = conn.overlap
    try:
        for _ in range(max_pages):
            page = conn.fetch(cursor, limit)
            acc, dup, rej = sink(page.events, conn.source(), tenant) if page.events else (0, 0, [])
            # event sudah diterima pipeline/antrean -> baru boleh majukan checkpoint
            with session_scope() as db:
                st = db.get(ConnectorState, conn.name)
                st.cursor, st.last_success, st.last_error, st.consecutive_failures = page.cursor, utcnow(), None, 0
                st.events_total += acc
                st.rejected_total += len(rej)
                st.last_warning = f"{len(rej)} event ditolak, contoh: {rej[0][:150]}" if rej else st.last_warning
                st.mapping_version = conn.mapping_version
            summary["accepted"] += acc; summary["duplicates"] += dup; summary["rejected"] += len(rej); summary["pages"] += 1
            stuck = page.cursor == cursor
            cursor = page.cursor
            if not page.more:
                break
            if stuck:  # >= limit event di jendela overlap: lanjut tanpa overlap agar tidak berputar
                if conn.overlap == 0:
                    raise AdapterError("tidak ada kemajuan cursor meski halaman penuh; naikkan batch_size")
                conn.overlap = 0
    except Exception as e:  # noqa: BLE001  cursor TIDAK maju untuk halaman yang gagal
        summary["error"] = f"{type(e).__name__}: {e}"[:300]
        with session_scope() as db:
            st = db.get(ConnectorState, conn.name)
            st.last_error, st.consecutive_failures = summary["error"], st.consecutive_failures + 1
        log.warning("konektor %s gagal: %s", conn.name, summary["error"])
    finally:
        conn.overlap = base_overlap
    return summary


def loop(
    conns: list[tuple[Connector, dict]],
    sink: Sink,
    stop: threading.Event | None = None,
    reload_connectors: Callable[[], list[tuple[Connector, dict]]] | None = None,
) -> None:
    stop = stop or threading.Event()
    nxt = {c.name: 0.0 for c, _ in conns}
    current = {c.name: (c, cfg, json.dumps(cfg, sort_keys=True, default=str)) for c, cfg in conns}
    reload_at = time.time() + 5
    while not stop.is_set():
        now = time.time()
        if reload_connectors and now >= reload_at:
            reload_at = now + 5
            try:
                refreshed = reload_connectors()
                updated = {}
                for new, cfg in refreshed:
                    name = new.name
                    signature = json.dumps(cfg, sort_keys=True, default=str)
                    existing = current.get(name)
                    if existing and existing[2] == signature:
                        new.client.http.close()
                        updated[name] = existing
                    else:
                        updated[name] = (new, cfg, signature)
                if {key: value[2] for key, value in updated.items()} != {key: value[2] for key, value in current.items()}:
                    for name, (old, _, signature) in current.items():
                        replacement = updated.get(name)
                        if replacement is None or replacement[2] != signature:
                            old.client.http.close()
                    nxt = {name: nxt.get(name, 0.0) if name in current and current[name][2] == value[2] else 0.0
                           for name, value in updated.items()}
                    current = updated
                    log.info("konfigurasi konektor diperbarui: %s", sorted(current))
            except Exception:  # noqa: BLE001
                log.exception("gagal memuat ulang konfigurasi konektor; konfigurasi aktif dipertahankan")
        now = time.time()
        for name, (conn, cfg, _) in list(current.items()):
            if now < nxt.get(name, 0):
                continue
            res = run_once(conn, cfg, sink)
            poll = int(cfg.get("poll_seconds", 60))
            with session_scope() as db:
                state = db.get(ConnectorState, conn.name)
                fails = state.consecutive_failures if state else 0
            nxt[name] = time.time() + min(900, poll * (2 ** min(fails, 4))) if res["error"] else time.time() + poll
        stop.wait(1.0)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--test", metavar="NAMA")
    a = ap.parse_args()
    s = get_settings()
    init_db()
    if a.test:
        conns = load_connectors(s, only_enabled=False, name=a.test)
        if not conns:
            raise SystemExit(f"konektor '{a.test}' tidak ada di {s.connectors_config}")
        try:
            print(json.dumps(conns[0][0].test()))
        except Exception as e:  # noqa: BLE001
            raise SystemExit(f"GAGAL: {e}")
        return
    conns = load_connectors(s)
    sink = default_sink(s)
    if a.once:
        if not conns:
            raise SystemExit("tidak ada konektor enabled di " + s.connectors_config)
        for conn, cfg in conns:
            print(run_once(conn, cfg, sink))
    else:
        loop(conns, sink, reload_connectors=lambda: load_connectors(s))


if __name__ == "__main__":
    main()
