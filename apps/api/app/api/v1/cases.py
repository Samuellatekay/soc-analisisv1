from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import Principal, audit, require
from app.schemas import CaseCreate, CasePatch, LinkIn, NoteIn
from services.common.db import get_session
from services.common.models import AuditLog, Case, CaseAlert, CaseNote, Event
from services.common.util import utcnow

router = APIRouter(prefix="/cases", tags=["cases"])
# New -> Triage -> Investigating -> Resolved -> Closed ; Resolved boleh dibuka kembali ke Investigating
TRANSITIONS = {"New": {"Triage", "Closed"}, "Triage": {"Investigating", "Closed"}, "Investigating": {"Resolved"},
               "Resolved": {"Closed", "Investigating"}, "Closed": set()}


def _case(db: Session, p: Principal, cid: str) -> Case:
    c = db.get(Case, cid)
    if not c or c.tenant_id != p.tenant_id:
        raise HTTPException(404, "case tidak ditemukan")
    return c


def _dict(db: Session, c: Case) -> dict:
    ev = db.scalars(select(CaseAlert.event_id).where(CaseAlert.case_id == c.case_id)).all()
    return {"case_id": c.case_id, "title": c.title, "description": c.description, "status": c.status, "priority": c.priority,
            "assignee": c.assignee, "created_by": c.created_by, "created_at": c.created_at.isoformat(),
            "updated_at": c.updated_at.isoformat(), "event_ids": list(ev), "allowed_transitions": sorted(TRANSITIONS[c.status])}


def _link(db: Session, p: Principal, c: Case, event_id: str):
    e = db.get(Event, event_id)
    if not e or e.tenant_id != p.tenant_id:
        raise HTTPException(404, f"alert {event_id} tidak ditemukan")
    if not db.get(CaseAlert, (c.case_id, event_id)):
        db.add(CaseAlert(case_id=c.case_id, event_id=event_id))
        audit(db, p, "case.link_alert", c.case_id, {"event_id": event_id})


@router.get("")
def list_cases(status: str | None = None, p: Principal = Depends(require("viewer")), db: Session = Depends(get_session)):
    q = select(Case).where(Case.tenant_id == p.tenant_id).order_by(Case.updated_at.desc()).limit(200)
    if status:
        q = q.where(Case.status == status)
    return [_dict(db, c) for c in db.scalars(q)]


@router.post("", status_code=201)
def create_case(body: CaseCreate, p: Principal = Depends(require("analyst")), db: Session = Depends(get_session)):
    c = Case(case_id=str(uuid.uuid4()), tenant_id=p.tenant_id, title=body.title, description=body.description,
             priority=body.priority, assignee=body.assignee, created_by=p.name)
    db.add(c)
    db.flush()
    audit(db, p, "case.create", c.case_id, {"title": c.title})
    for eid in body.event_ids:
        _link(db, p, c, eid)
    db.commit()
    return _dict(db, c)


@router.get("/{case_id}")
def get_case(case_id: str, p: Principal = Depends(require("viewer")), db: Session = Depends(get_session)):
    c = _case(db, p, case_id)
    notes = db.scalars(select(CaseNote).where(CaseNote.case_id == case_id).order_by(CaseNote.created_at)).all()
    hist = db.scalars(select(AuditLog).where(AuditLog.tenant_id == p.tenant_id, AuditLog.target == case_id).order_by(AuditLog.ts)).all()
    return {**_dict(db, c), "notes": [{"author": n.author, "text": n.text, "created_at": n.created_at.isoformat()} for n in notes],
            "history": [{"ts": h.ts.isoformat(), "actor": h.actor, "action": h.action, "detail": h.detail} for h in hist]}


@router.patch("/{case_id}")
def patch_case(case_id: str, body: CasePatch, p: Principal = Depends(require("analyst")), db: Session = Depends(get_session)):
    c = _case(db, p, case_id)
    changes = {}
    if body.status and body.status != c.status:
        if body.status not in TRANSITIONS[c.status]:
            raise HTTPException(409, f"transisi {c.status} -> {body.status} tidak diizinkan; boleh: {sorted(TRANSITIONS[c.status])}")
        changes["status"] = [c.status, body.status]
        c.status = body.status
    for f in ("title", "description", "priority", "assignee"):
        v = getattr(body, f)
        if v is not None and v != getattr(c, f):
            changes[f] = [getattr(c, f), v]
            setattr(c, f, v)
    c.updated_at = utcnow()
    audit(db, p, "case.update", case_id, changes)
    db.commit()
    return _dict(db, c)


@router.post("/{case_id}/alerts")
def link_alert(case_id: str, body: LinkIn, p: Principal = Depends(require("analyst")), db: Session = Depends(get_session)):
    c = _case(db, p, case_id)
    _link(db, p, c, body.event_id)
    db.commit()
    return _dict(db, c)


@router.delete("/{case_id}/alerts/{event_id}")
def unlink_alert(case_id: str, event_id: str, p: Principal = Depends(require("analyst")), db: Session = Depends(get_session)):
    c = _case(db, p, case_id)
    row = db.get(CaseAlert, (case_id, event_id))
    if row:
        db.delete(row)
        audit(db, p, "case.unlink_alert", case_id, {"event_id": event_id})
    db.commit()
    return _dict(db, c)


@router.post("/{case_id}/notes", status_code=201)
def add_note(case_id: str, body: NoteIn, p: Principal = Depends(require("analyst")), db: Session = Depends(get_session)):
    _case(db, p, case_id)
    db.add(CaseNote(case_id=case_id, author=p.name, text=body.text))
    audit(db, p, "case.note", case_id)
    db.commit()
    return {"ok": True}
