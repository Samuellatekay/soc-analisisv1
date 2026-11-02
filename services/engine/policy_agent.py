"""Policy agent (sisi cluster): MENARIK kebijakan bertanda tangan dari Master, memverifikasi, lalu menyimpannya di DB lokal.
Master bukan jalur event: bila Master mati/lambat/salah, cluster tetap berjalan dengan kebijakan terakhir yang valid.
  python -m services.engine.policy_agent [--once]      env: MASTER_URL, CLUSTER_ID, MASTER_CLUSTER_TOKEN(_FILE), MASTER_POLICY_PUBKEY_FILE"""
from __future__ import annotations

import argparse
import logging
import os
import threading
import time
from pathlib import Path

import httpx

from services.common.config import read_secret
from services.common.db import init_db, session_scope
from services.common.models import AuditLog, PolicyState
from services.common.util import utcnow
from services.master.policy import PolicyRejected, verify_bundle

log = logging.getLogger("policy_agent")


class PolicyAgent:
    def __init__(self, master_url: str, cluster_id: str, token: str, pubkey_b64: str, transport=None, timeout: float = 5.0):
        if not (master_url and cluster_id and token and pubkey_b64):
            raise ValueError("MASTER_URL, CLUSTER_ID, MASTER_CLUSTER_TOKEN, MASTER_POLICY_PUBKEY wajib")
        self.url, self.cid, self.pub = master_url.rstrip("/"), cluster_id, pubkey_b64.strip()
        self.http = httpx.Client(timeout=timeout, transport=transport, headers={"Authorization": f"Bearer {token}"})

    @classmethod
    def from_env(cls, transport=None):
        kf = os.getenv("MASTER_POLICY_PUBKEY_FILE", "")
        return cls(os.getenv("MASTER_URL", ""), os.getenv("CLUSTER_ID", ""), read_secret("MASTER_CLUSTER_TOKEN"), Path(kf).read_text() if kf and Path(kf).exists() else os.getenv("MASTER_POLICY_PUBKEY", ""), transport)

    def _record(self, **kw):
        with session_scope() as db:
            st = db.get(PolicyState, 1) or PolicyState(id=1, version=0, policy={})
            st.last_check = utcnow()
            for k, v in kw.items():
                setattr(st, k, v)
            db.merge(st)

    def check(self) -> dict:
        with session_scope() as db:
            st = db.get(PolicyState, 1)
            applied = st.version if st else 0
        try:
            r = self.http.get(f"{self.url}/api/v1/policy/{self.cid}", headers={"If-None-Match": str(applied)})
        except httpx.HTTPError as e:   # Master tidak terjangkau: lanjut dengan kebijakan terakhir
            self._record(last_error=f"master tidak terjangkau: {type(e).__name__}")
            return {"status": "master_unreachable", "applied": applied}
        if r.status_code == 304 or r.status_code == 204:
            self._record(last_error=None)
            return {"status": "up_to_date", "applied": applied}
        if r.status_code != 200:
            self._record(last_error=f"master HTTP {r.status_code}")
            return {"status": "error", "http": r.status_code, "applied": applied}
        try:
            bundle = r.json()
            pol = verify_bundle(bundle, self.pub, self.cid, applied)
        except PolicyRejected as e:   # tanda tangan salah / cluster salah / rollback / melanggar batas -> TIDAK diterapkan
            self._record(last_error=f"ditolak: {e}")
            with session_scope() as db:
                db.add(AuditLog(tenant_id="*", actor="policy_agent", role="system", action="policy.rejected", target=str(bundle.get("version") if isinstance(bundle, dict) else "?"), detail={"reason": str(e)[:300]}))
            return {"status": "rejected", "reason": str(e), "applied": applied}
        except Exception as e:  # noqa: BLE001  respons bukan JSON dsb.
            self._record(last_error=f"respons tidak valid: {type(e).__name__}")
            return {"status": "error", "applied": applied}
        self._record(version=bundle["version"], policy=pol.model_dump(exclude_none=True), signature=bundle["signature"], issued_at=bundle["issued_at"], applied_at=utcnow(), last_error=None)
        with session_scope() as db:
            db.add(AuditLog(tenant_id="*", actor="policy_agent", role="system", action="policy.applied", target=str(bundle["version"]), detail={"issued_at": bundle["issued_at"]}))
        return {"status": "applied", "version": bundle["version"]}


def loop(agent: PolicyAgent, interval: float = 60.0, stop: threading.Event | None = None):
    stop = stop or threading.Event()
    while not stop.is_set():
        try:
            res = agent.check()
            if res["status"] not in ("up_to_date",):
                log.info("policy: %s", res)
        except Exception:  # noqa: BLE001
            log.exception("policy agent error")
        stop.wait(interval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ap = argparse.ArgumentParser(); ap.add_argument("--once", action="store_true"); a = ap.parse_args()
    init_db()
    ag = PolicyAgent.from_env()
    print(ag.check()) if a.once else loop(ag, float(os.getenv("POLICY_POLL_SECONDS", "60")))
