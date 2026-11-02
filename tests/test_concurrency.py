"""Konkurensi multi-worker (inti mode Orkestrasi): tanpa lost-update, tanpa double-count saat redelivery, tanpa klaim ganda."""
import threading
from datetime import datetime

import pytest
from sqlalchemy import func, select

from services.common.db import session_scope
from services.common.models import Analysis, Event, Outbox, TripletCount
from services.engine.pipeline import Pipeline

H = datetime(2026, 8, 1, 10)


def run_threads(fns):
    errs, ts = [], []
    def wrap(f):
        def r():
            try:
                f()
            except Exception as e:  # noqa: BLE001
                errs.append(repr(e))
        return r
    for f in fns:
        t = threading.Thread(target=wrap(f)); t.start(); ts.append(t)
    for t in ts:
        t.join()
    return errs


def raw(i, **kw):
    return {"id": i, "timestamp": H.replace(minute=5).isoformat() + "Z", "signature": "scan probe", "src_ip": "10.9.9.9", "dst_ip": "10.0.9.9", "count": 3, **kw}


def test_triplet_counter_has_no_lost_updates():
    pipe = Pipeline()
    def worker(k):
        def f():
            for j in range(10):
                with session_scope() as s:
                    pipe.process(s, raw(f"lu-{k}-{j}"), "generic", "conc")
        return f
    errs = run_threads([worker(k) for k in range(6)])
    assert not errs, errs[:2]
    with session_scope() as s:
        total = s.scalar(select(func.sum(TripletCount.count)).where(TripletCount.tenant_id == "conc"))
        n = s.scalar(select(func.count()).select_from(Event).where(Event.tenant_id == "conc"))
    assert n == 60 and total == 60 * 3          # 60 event x count 3: tidak ada kenaikan yang hilang


def test_concurrent_redelivery_of_same_event_counts_once():
    """At-least-once: dua worker menerima event yang sama bersamaan -> satu baris event, hitungan hanya +1x."""
    pipe = Pipeline()
    def f():
        with session_scope() as s:
            pipe.process(s, raw("same-event"), "generic", "redel")
    errs = run_threads([f] * 8)
    with session_scope() as s:
        n = s.scalar(select(func.count()).select_from(Event).where(Event.tenant_id == "redel"))
        total = s.scalar(select(func.sum(TripletCount.count)).where(TripletCount.tenant_id == "redel"))
        outbox = s.scalar(select(func.count()).select_from(Outbox).join(Event, Event.event_id == Outbox.event_id).where(Event.tenant_id == "redel"))
    assert n == 1 and total == 3 and outbox == 1, (errs[:2], n, total, outbox)


def test_two_rag_workers_never_claim_same_job():
    from services.rag_worker import worker as w
    pipe = Pipeline()
    with session_scope() as s:
        for i in range(12):
            pipe.process(s, raw(f"rag-{i}", signature="SSH brute force failed login", dst_ip="10.0.1.10", src_ip="203.0.113.45"), "generic", "ragc")
    claimed, lock = [], threading.Lock()
    orig = w.get_retriever
    class R:
        def retrieve(self, *a):
            with lock:
                pass
            return orig(w.get_settings()).retrieve(*a)
    def f():
        while w.process_one():
            pass
    errs = run_threads([f] * 4)
    with session_scope() as s:
        done = s.scalars(select(Analysis).where(Analysis.tenant_id == "ragc")).all()
        attempts = [a.attempts for a in done]
    assert not errs, errs[:2]
    assert all(a.status in ("completed", "insufficient_evidence") for a in done) and attempts and max(attempts) == 1   # tiap job diproses tepat sekali
