from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.common.models import Analysis, Event, Outbox
from services.common.util import utcnow


def fetch_batch(session: Session, limit: int = 100) -> list[Outbox]:
    q = select(Outbox).where(Outbox.status == "pending", Outbox.next_attempt_at <= utcnow()).order_by(Outbox.id).limit(limit).with_for_update(skip_locked=True)
    return list(session.scalars(q))


def projection(session: Session, event_id: str) -> dict | None:
    ev = session.get(Event, event_id)
    if not ev:
        return None
    an = session.get(Analysis, event_id)
    doc = {c: getattr(ev, c) for c in (
        "event_id", "tenant_id", "source", "severity", "attack_type", "signature", "src_ip", "dst_ip", "dst_port", "host",
        "technique_id", "tactic", "message", "processing_status", "analysis_status", "disposition", "risk_score", "risk_level", "scoring_version")}
    doc["event_time"], doc["received_at"] = ev.event_time.isoformat(), ev.received_at.isoformat()
    if an and an.status == "completed":
        doc["analysis"] = {"summary": an.result.get("summary"), "model": an.model, "prompt_version": an.prompt_version}
    return doc


def mark_failed(row: Outbox, err: str, max_attempts: int = 8) -> None:
    row.attempts += 1
    row.last_error = err[:500]
    row.next_attempt_at = utcnow() + timedelta(seconds=min(300, 2 ** row.attempts))
    if row.attempts >= max_attempts:
        row.status = "failed"
