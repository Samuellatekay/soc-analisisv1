from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.auth import Principal, audit, require
from app.services.queries import event_detail, search_events
from services.common.db import get_session
from services.common.models import Analysis, Event

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
def list_alerts(q: str | None = None, source: str | None = None, risk_level: str | None = Query(None, pattern="^(low|medium|high)$"),
                disposition: str | None = Query(None, pattern="^(retained|manual_review|filtered)$"), processing_status: str | None = None,
                analysis_status: str | None = None, technique: str | None = None, time_from: datetime | None = None,
                time_to: datetime | None = None, include_filtered: bool = False, sort: str = "event_time", order: str = "desc",
                page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
                p: Principal = Depends(require("viewer")), db: Session = Depends(get_session)):
    if q:  # pencarian entitas = akses sensitif -> audit
        audit(db, p, "alerts.search", detail={"q": q[:64]})
        db.commit()
    return search_events(db, p.tenant_id, q=q, source=source, risk_level=risk_level, disposition=disposition,
                         processing_status=processing_status, analysis_status=analysis_status, technique=technique,
                         time_from=time_from, time_to=time_to, include_filtered=include_filtered, sort=sort, order=order,
                         page=page, page_size=page_size)


def _get(db: Session, p: Principal, event_id: str) -> Event:
    e = db.get(Event, event_id)
    if not e or e.tenant_id != p.tenant_id:  # 404 (bukan 403) agar tidak membocorkan keberadaan lintas tenant
        raise HTTPException(404, "alert tidak ditemukan")
    return e


@router.get("/{event_id}")
def get_alert(event_id: str, p: Principal = Depends(require("viewer")), db: Session = Depends(get_session)):
    return event_detail(_get(db, p, event_id))


@router.get("/{event_id}/analysis")
def get_analysis(event_id: str, p: Principal = Depends(require("viewer")), db: Session = Depends(get_session)):
    _get(db, p, event_id)
    a = db.get(Analysis, event_id)
    if not a:
        return {"status": "not_requested"}
    return {"status": a.status, "result": a.result, "sources": a.sources, "model": a.model, "prompt_version": a.prompt_version,
            "attempts": a.attempts, "error": a.error, "updated_at": a.updated_at.isoformat()}


@router.post("/{event_id}/analysis/retry")
def retry_analysis(event_id: str, p: Principal = Depends(require("analyst")), db: Session = Depends(get_session)):
    e = _get(db, p, event_id)
    a = db.get(Analysis, event_id) or Analysis(event_id=event_id, tenant_id=p.tenant_id)
    a.status, a.attempts, a.error = "pending", 0, None
    db.add(a)
    e.analysis_status = "pending"
    audit(db, p, "analysis.retry", event_id)
    db.commit()
    return {"status": "pending"}
