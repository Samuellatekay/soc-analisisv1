"""Snapshot Elasticsearch via API snapshot. Prasyarat: snapshot repository SUDAH didaftarkan di cluster (BACKUP_ES_REPOSITORY).
Indeks bukan data kanonis (dapat dibangun ulang dari PostgreSQL/outbox) — snapshot mempercepat pemulihan. BELUM diuji terhadap cluster nyata."""
from __future__ import annotations

from datetime import datetime, timezone

import httpx


def run(es_url: str, repository: str, indices: str = "soc-*", transport=None, timeout: float = 3600.0) -> dict:
    if not (es_url and repository):
        raise RuntimeError("ELASTICSEARCH_URL dan BACKUP_ES_REPOSITORY wajib")
    name = "soc-" + datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%Sz")
    with httpx.Client(timeout=timeout, transport=transport) as c:
        r = c.put(f"{es_url.rstrip('/')}/_snapshot/{repository}/{name}", params={"wait_for_completion": "true"},
                  json={"indices": indices, "include_global_state": False})
        r.raise_for_status()
        snap = r.json().get("snapshot", {})
    if snap.get("state") != "SUCCESS" or snap.get("shards", {}).get("failed", 0):
        raise RuntimeError(f"snapshot tidak sukses: state={snap.get('state')} shards={snap.get('shards')}")
    return {"snapshot": name, "state": snap["state"], "shards": snap.get("shards")}
