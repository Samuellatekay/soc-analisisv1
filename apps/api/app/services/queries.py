from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from services.common.models import Event

SORTABLE = {"event_time": Event.event_time, "risk_score": Event.risk_score, "received_at": Event.received_at}


def event_summary(e: Event) -> dict:
    return {
        "event_id": e.event_id, "source": e.source, "event_time": e.event_time.isoformat(), "severity": e.severity,
        "attack_type": e.attack_type, "signature": e.signature, "src_ip": e.src_ip, "dst_ip": e.dst_ip, "host": e.host,
        "technique_id": e.technique_id, "tactic": e.tactic, "risk_score": e.risk_score, "risk_level": e.risk_level,
        "disposition": e.disposition, "processing_status": e.processing_status, "analysis_status": e.analysis_status,
    }


def event_detail(e: Event) -> dict:
    return {**event_summary(e), "message": e.message, "payload": e.payload, "disposition_reason": e.disposition_reason,
            "noise_info": e.noise_info, "orchestration": e.orchestration, "score_components": e.score_components,
            "integrity": e.integrity, "graph_snapshot_id": e.graph_snapshot_id, "scoring_version": e.scoring_version,
            "enrichment_status": e.enrichment_status, "entities": e.entities, "source_event_id": e.source_event_id,
            "received_at": e.received_at.isoformat()}


def search_events(db: Session, tenant: str, *, q: str | None, source: str | None, risk_level: str | None, disposition: str | None,
                  processing_status: str | None, analysis_status: str | None, technique: str | None, time_from: datetime | None,
                  time_to: datetime | None, include_filtered: bool, sort: str, order: str, page: int, page_size: int) -> dict:
    if sort not in SORTABLE or order not in ("asc", "desc"):
        raise HTTPException(422, f"sort harus salah satu {list(SORTABLE)}, order asc|desc")
    c = [Event.tenant_id == tenant]  # filter tenant SELALU diterapkan di backend
    if q:
        q = q.strip()[:128]
        like = f"%{q}%"
        c.append(or_(Event.event_id == q, Event.source_event_id == q, Event.src_ip == q, Event.dst_ip == q, Event.host.ilike(like), Event.signature.ilike(like),
                     Event.message.ilike(like), Event.technique_id == q.upper()))
    for col, val in ((Event.source, source), (Event.risk_level, risk_level), (Event.disposition, disposition),
                     (Event.processing_status, processing_status), (Event.analysis_status, analysis_status), (Event.technique_id, technique)):
        if val:
            c.append(col == val)
    if not include_filtered and not disposition:
        c.append(Event.disposition != "filtered")
    if time_from:
        c.append(Event.event_time >= time_from)
    if time_to:
        c.append(Event.event_time <= time_to)
    total = db.scalar(select(func.count()).select_from(Event).where(*c))
    col = SORTABLE[sort]
    rows = db.scalars(select(Event).where(*c).order_by(col.desc() if order == "desc" else col.asc(), Event.event_id)
                      .limit(page_size).offset((page - 1) * page_size)).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [event_summary(r) for r in rows]}
