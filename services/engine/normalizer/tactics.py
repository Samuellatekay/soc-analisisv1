"""Resolusi technique ID -> tactic dari knowledge base (DB; fallback ke berkas seed)."""
from __future__ import annotations

import json
import time
from pathlib import Path

from sqlalchemy import select

from services.common.config import Settings
from services.common.db import session_scope
from services.common.models import KBItem


class TacticResolver:
    def __init__(self, settings: Settings, ttl: int = 60):
        self.s, self.ttl = settings, ttl
        self._map: dict[str, str] = {}
        self._loaded = 0.0

    def refresh(self, session=None):
        """Muat ulang peta (TTL). Pakai session pemanggil agar tidak membuka transaksi bersarang."""
        if self._map and time.time() - self._loaded <= self.ttl:
            return
        self._load(session)

    def _load(self, session=None):
        m: dict[str, str] = {}
        try:
            if session is not None:
                rows = session.scalars(select(KBItem).where(KBItem.kind == "technique")).all()
            else:
                with session_scope() as s:
                    rows = s.scalars(select(KBItem).where(KBItem.kind == "technique")).all()
            for it in rows:
                t = it.data.get("tactics") or []
                if t:
                    m[it.item_id] = t[0]
        except Exception:  # noqa: BLE001
            pass
        if not m and Path(self.s.kb_seed_file).exists():
            for it in json.loads(Path(self.s.kb_seed_file).read_text())["items"]:
                if it["kind"] == "technique" and it["data"].get("tactics"):
                    m[it["item_id"]] = it["data"]["tactics"][0]
        self._map, self._loaded = m, time.time()

    def __call__(self, technique_id: str | None) -> str | None:
        if not technique_id:
            return None
        if not self._map:
            self._load()
        t = technique_id.upper()
        return self._map.get(t) or self._map.get(t.split(".")[0])

    def known(self, technique_id: str | None) -> bool:
        return bool(self(technique_id))
