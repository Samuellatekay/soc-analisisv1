"""Worker engine: konsumsi Redis Streams -> pipeline -> commit PostgreSQL+outbox -> ack.

Jalankan:  python -m services.engine.main      (butuh REDIS_URL)
Beberapa proses = mode Orkestrasi (consumer group membagi beban; event_id idempoten).
"""
from __future__ import annotations

import logging
import os
import signal
import socket

from services.common.config import get_settings
from services.common.db import init_db, session_scope
from services.engine.consumers.queue import get_queue
from services.engine.normalizer.core import ValidationError
from services.engine.pipeline import Pipeline

log = logging.getLogger("engine")
_stop = False


def _batch_size() -> int:
    raw = os.getenv("ENGINE_BATCH_SIZE", "10")
    try:
        size = int(raw)
    except ValueError as exc:
        raise SystemExit("ENGINE_BATCH_SIZE harus berupa bilangan bulat 1..100") from exc
    if not 1 <= size <= 100:
        raise SystemExit("ENGINE_BATCH_SIZE harus berupa bilangan bulat 1..100")
    return size


def handle(pipe: Pipeline, q, msg) -> None:
    """Satu event, satu transaksi (jalur fallback/isolasi kegagalan)."""
    try:
        with session_scope() as s:  # commit dulu...
            pipe.process(s, msg.data["raw"], msg.data["source"], msg.data["tenant_id"])
        q.ack(msg.id)               # ...baru ack
    except ValidationError as e:
        q.fail(msg, f"validation: {e}", permanent=True)
    except Exception as e:  # noqa: BLE001
        log.exception("gagal memproses %s", msg.id)
        q.fail(msg, repr(e))


def handle_batch(pipe: Pipeline, q, msgs: list) -> None:
    """Satu commit untuk seluruh batch (jauh lebih sedikit fsync/round-trip). Savepoint per event mengisolasi event buruk.
    Ack HANYA setelah commit berhasil. Jika commit gagal (mis. deadlock pada redelivery), ulangi per-event agar tidak ada yang hilang/ke-DLQ keliru."""
    if len(msgs) == 1:
        return handle(pipe, q, msgs[0])
    ok, bad = [], []
    try:
        with session_scope() as s:
            for m in msgs:
                try:
                    with s.begin_nested():
                        pipe.process(s, m.data["raw"], m.data["source"], m.data["tenant_id"])
                    ok.append(m)
                except ValidationError as e:
                    bad.append((m, f"validation: {e}", True))
                except Exception as e:  # noqa: BLE001
                    bad.append((m, repr(e), False))
    except Exception:  # noqa: BLE001  commit/transaksi gagal: tidak ada yang ter-ack -> proses ulang satu per satu
        log.warning("commit batch gagal; fallback per-event (%s pesan)", len(msgs))
        for m in msgs:
            handle(pipe, q, m)
        return
    for m in ok:
        q.ack(m.id)
    for m, err, permanent in bad:
        q.fail(m, err, permanent=permanent)


def run() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    s = get_settings()
    if not s.redis_url:
        raise SystemExit("REDIS_URL belum diset (mode inline tidak memakai worker ini)")
    init_db()
    q = get_queue(s.redis_url, consumer=f"{socket.gethostname()}-{os.getpid()}")
    pipe = Pipeline(s)
    batch_size = _batch_size()
    signal.signal(signal.SIGTERM, lambda *_: globals().__setitem__("_stop", True))
    log.info("engine worker aktif; consumer=%s batch_size=%s", q.consumer, batch_size)
    while not _stop:
        msgs = q.claim_stale(int(os.getenv("ENGINE_CLAIM_IDLE_MS", "60000"))) + q.read(count=batch_size)
        if msgs:
            handle_batch(pipe, q, msgs)


if __name__ == "__main__":
    run()
