"""Poller status cluster (PULL) + klasifikasi kesehatan. Master tidak dilalui event; kegagalan poller tidak memengaruhi cluster."""
from __future__ import annotations

import os
import threading
from datetime import timedelta

import httpx

from services.common.util import utcnow
from . import db

QUEUE_LAG_WARN = int(os.getenv("MASTER_QUEUE_LAG_WARN", "5000"))


def classify(status: dict | None, polled_at, ok_at, now, interval: int, target_policy: int = 0) -> dict:
    reasons: list[str] = []
    if not ok_at or now - ok_at > timedelta(seconds=interval * 3):
        return {"state": "unreachable", "reasons": ["status tidak berhasil diambil dalam 3x interval"]}
    s = status or {}
    q = s.get("queue") or {}
    if s.get("outbox_failed"): reasons.append(f"outbox gagal: {s['outbox_failed']}")
    if q.get("dlq"): reasons.append(f"DLQ berisi {q['dlq']} pesan")
    if (q.get("length") or 0) > QUEUE_LAG_WARN: reasons.append(f"antrean menumpuk ({q['length']})")
    if q.get("error"): reasons.append("antrean tidak terbaca")
    if (s.get("analysis_pending") or 0) > 5000: reasons.append("backlog analisis AI besar")
    if (s.get("kb") or {}).get("stale"): reasons.append("knowledge base stale")
    if (s.get("connectors") or {}).get("failing"): reasons.append(f"{s['connectors']['failing']} konektor gagal")
    pol = s.get("policy") or {}
    if pol.get("last_error"): reasons.append(f"policy agent: {pol['last_error']}")
    if target_policy and (pol.get("version") or 0) < target_policy: reasons.append(f"kebijakan v{pol.get('version', 0)} < target v{target_policy}")
    return {"state": "degraded" if reasons else "healthy", "reasons": reasons}


def poll_cluster(cl: db.Cluster, client_factory=None) -> dict:
    token = os.getenv(cl.status_token_env, "") if cl.status_token_env else ""
    now = utcnow()
    try:
        if not token:
            raise RuntimeError("token status tidak tersedia (env kosong)")
        c = (client_factory or (lambda verify: httpx.Client(timeout=5.0, verify=verify)))(cl.verify_tls)
        r = c.get(f"{cl.api_url.rstrip('/')}/api/v1/cluster/status", headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        return {"ok": True, "status": r.json(), "at": now}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:150]}", "at": now}


def poll_all(client_factory=None) -> int:
    with db.scope() as s:
        clusters = list(s.query(db.Cluster))
    n = 0
    for cl in clusters:
        res = poll_cluster(cl, client_factory)
        with db.scope() as s:
            st = s.get(db.StatusRow, cl.id) or db.StatusRow(cluster_id=cl.id)
            st.polled_at = res["at"]
            if res["ok"]:
                st.ok_at, st.status, st.error = res["at"], res["status"], None
            else:
                st.error = res["error"]            # status lama dipertahankan sebagai 'terakhir diketahui'
            s.merge(st)
        n += res["ok"]
    return n


def loop(stop: threading.Event, interval: int = 30):
    while not stop.is_set():
        try:
            poll_all()
        except Exception:  # noqa: BLE001
            pass
        stop.wait(interval)
