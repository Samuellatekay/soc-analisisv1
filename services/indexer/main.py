"""Indexer internal (bukan Logstash): outbox PostgreSQL -> Elasticsearch, retry + idempoten (upsert by event_id)."""
from __future__ import annotations

import logging
import time

from services.common.config import get_settings
from services.common.db import init_db, session_scope
from services.common.models import Event
from services.indexer import outbox_reader as ob

log = logging.getLogger("indexer")


def run_once(es=None) -> int:
    """Tanpa ES (dev): pencarian dilayani langsung dari SQL; outbox ditandai selesai dan status -> indexed."""
    n = 0
    with session_scope() as db:
        for row in ob.fetch_batch(db):
            try:
                doc = ob.projection(db, row.event_id)
                if doc and es is not None:
                    es.upsert(row.event_id, doc)
                ev = db.get(Event, row.event_id)
                if ev and ev.processing_status in ("scored", "normalized", "received"):
                    ev.processing_status = "indexed"
                row.status = "done"
                n += 1
            except Exception as e:  # noqa: BLE001
                ob.mark_failed(row, repr(e))
    return n


def run():
    logging.basicConfig(level=logging.INFO)
    s = get_settings()
    init_db()
    es = None
    if s.es_url:
        from .elasticsearch_client import ESClient
        es = ESClient(s.es_url, s.es_index)
        es.ensure_index()
    while True:
        if not run_once(es):
            time.sleep(1.0)


if __name__ == "__main__":
    run()
