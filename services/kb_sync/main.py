"""Worker sinkronisasi KB. python -m services.kb_sync.main  [--once] [--source seed|mitre]"""
from __future__ import annotations

import argparse
import logging
import time

from services.common.config import get_settings
from services.common.db import init_db, session_scope
from services.kb_sync import scheduler
from services.kb_sync.importer import import_items
from services.kb_sync.sources import mitre_attack

log = logging.getLogger("kb_sync")


def run_sync(source: str = "mitre") -> dict:
    s = get_settings()
    me = scheduler.holder_id()
    with session_scope() as db:
        if not scheduler.acquire_lease(db, scheduler.LEASE, me):
            return {"status": "skipped", "reason": "lease dipegang worker lain"}
    try:
        try:
            items, ver = mitre_attack.fetch() if source == "mitre" else mitre_attack.load_seed(s.kb_seed_file)
            src = "mitre-attack" if source == "mitre" else "seed"
        except Exception as e:  # noqa: BLE001  gagal unduh -> fallback seed, tandai
            log.warning("unduh MITRE gagal (%s); memakai seed lokal", e)
            items, ver = mitre_attack.load_seed(s.kb_seed_file)
            src = "seed"
        with session_scope() as db:
            run = import_items(db, items, src, ver, s)
            return {"status": run.status, "added": run.added, "updated": run.updated, "unchanged": run.unchanged, "version": ver, "error": run.error}
    finally:
        with session_scope() as db:
            scheduler.release_lease(db, scheduler.LEASE, me)


def loop(source: str = "mitre"):
    s = get_settings()
    while True:
        with session_scope() as db:
            due = scheduler.is_due(db, s)
        if due:
            log.info("sinkronisasi KB: %s", run_sync(source))
        time.sleep(30)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--source", default="mitre", choices=["mitre", "seed"])
    a = ap.parse_args()
    init_db()
    print(run_sync(a.source)) if a.once else loop(a.source)
