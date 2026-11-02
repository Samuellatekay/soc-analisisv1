"""Scheduler harian (default 01:00 Asia/Jakarta) dengan distributed lease + catch-up job terlewat."""
from __future__ import annotations

import socket
import os
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.common.config import Settings
from services.common.models import KBRun, Lease
from services.common.util import utcnow

LEASE = "kb_sync"
LEASE_TTL = timedelta(minutes=10)


def holder_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}"


def acquire_lease(session: Session, name: str, holder: str, ttl: timedelta = LEASE_TTL) -> bool:
    """Lease berbasis baris DB: satu pemegang aktif; lease kedaluwarsa dapat diambil alih worker sehat lain."""
    now = utcnow()
    row = session.get(Lease, name, with_for_update=True)
    if row is None:
        session.add(Lease(name=name, holder=holder, expires_at=now + ttl))
        try:
            session.flush()
        except Exception:  # noqa: BLE001  balapan: worker lain menang
            session.rollback()
            return False
        return True
    if row.holder == holder or row.expires_at <= now:
        row.holder, row.expires_at = holder, now + ttl
        return True
    return False


def release_lease(session: Session, name: str, holder: str) -> None:
    row = session.get(Lease, name)
    if row and row.holder == holder:
        row.expires_at = utcnow()


def last_due(settings: Settings, now_utc: datetime | None = None) -> datetime:
    """Waktu jadwal terakhir (UTC naive) yang sudah lewat."""
    tz = ZoneInfo(settings.kb_sync_tz)
    now_utc = now_utc or utcnow()
    local = now_utc.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz)
    sched = local.replace(hour=settings.kb_sync_cron_hour, minute=0, second=0, microsecond=0)
    if sched > local:
        sched -= timedelta(days=1)
    return sched.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)


def is_due(session: Session, settings: Settings, now_utc: datetime | None = None) -> bool:
    due = last_due(settings, now_utc)
    ok = session.scalars(select(KBRun).where(KBRun.status == "success", KBRun.finished_at >= due).limit(1)).first()
    return ok is None  # belum ada sukses sejak jadwal terakhir (termasuk job yang terlewat)
