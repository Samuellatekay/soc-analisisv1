from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import Principal, audit, require
from services.common.config import get_settings
from services.common.db import get_session
from services.common.models import ConnectorState
from services.common.util import utcnow

router = APIRouter(prefix="/connectors", tags=["connectors"])


def _configured(tenant: str) -> list[dict]:
    p = Path(get_settings().connectors_config)
    if not p.exists():
        return []
    return [c for c in json.loads(p.read_text()).get("connectors", []) if c.get("tenant_id", "default") == tenant]


@router.get("")
def list_connectors(p: Principal = Depends(require("analyst")), db: Session = Depends(get_session)):
    """Status konektor milik tenant. `params` (host/credential) sengaja TIDAK dikembalikan."""
    out = []
    for c in _configured(p.tenant_id):
        st = db.get(ConnectorState, c["name"])
        lag = None
        if st and st.last_success:
            lag = int((utcnow() - st.last_success).total_seconds())
        out.append({"name": c["name"], "type": c["type"], "enabled": c.get("enabled", False), "poll_seconds": c.get("poll_seconds", 60),
                    "state": None if not st else {"cursor": st.cursor, "last_success": st.last_success.isoformat() if st.last_success else None,
                                                  "seconds_since_success": lag, "last_error": st.last_error, "last_warning": st.last_warning,
                                                  "consecutive_failures": st.consecutive_failures, "events_total": st.events_total,
                                                  "rejected_total": st.rejected_total, "mapping_version": st.mapping_version}})
    return out


@router.post("/{name}/test")
def test_connector(name: str, p: Principal = Depends(require("admin")), db: Session = Depends(get_session)):
    """Uji auth+koneksi+format dengan mengambil <=1 event; tidak menyimpan event maupun memajukan cursor."""
    from services.engine.adapters.runner import load_connectors
    if name not in {c["name"] for c in _configured(p.tenant_id)}:   # cek tenant SEBELUM menginstansiasi apa pun
        raise HTTPException(404, "konektor tidak ditemukan")
    found = [c for c, _ in load_connectors(get_settings(), only_enabled=False, name=name)]
    if not found:
        return {"ok": False, "error": "konfigurasi konektor tidak valid (parameter wajib kurang)"}
    audit(db, p, "connector.test", name)
    db.commit()
    try:
        return found[0].test()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}
