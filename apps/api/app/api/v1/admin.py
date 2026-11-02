from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.auth import Principal, audit, get_principal, require
from app.schemas import CandidateReview
from services.common.config import get_settings
from services.common.db import get_session
from services.common.models import AuditLog, Event, KBCandidate, KBItem, KBRun, Outbox
from services.common.util import utcnow
from services.engine.scoring.ahp import weights_from_matrix

router = APIRouter(tags=["admin"])


@router.get("/auth/config")
def auth_config():
    """Publik: UI memakainya untuk memilih mode login. Hanya berisi nilai publik (client_id publik PKCE, endpoint IdP) — tanpa secret."""
    import json
    import os
    from app.core.auth import get_verifier
    v = get_verifier()
    if v is None:
        return {"mode": "token"}
    cid = os.getenv("OIDC_CLIENT_ID", "")
    if not cid:
        raise HTTPException(503, "OIDC_CLIENT_ID belum diset (client publik PKCE untuk UI)")
    try:
        d = v.discovery() if not (os.getenv("OIDC_AUTH_URL") and os.getenv("OIDC_TOKEN_URL")) else {}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(503, "IdP tidak dapat dijangkau untuk discovery") from e
    return {"mode": "oidc", "client_id": cid, "scope": os.getenv("OIDC_SCOPE", "openid profile email"),
            "authorization_endpoint": os.getenv("OIDC_AUTH_URL") or d.get("authorization_endpoint"),
            "token_endpoint": os.getenv("OIDC_TOKEN_URL") or d.get("token_endpoint"),
            "end_session_endpoint": os.getenv("OIDC_LOGOUT_URL") or d.get("end_session_endpoint"),
            "extra_params": json.loads(os.getenv("OIDC_AUTH_EXTRA_PARAMS", "{}"))}


@router.get("/cluster/status")
def cluster_status(p: Principal = Depends(require("admin")), db: Session = Depends(get_session)):
    """Dibaca Master (pull). Ringkasan kesehatan cluster ini; tanpa data alert/entitas."""
    from datetime import timedelta
    from sqlalchemy import text
    from services.common.models import Analysis, ConnectorState, PolicyState
    from services.common.config import get_settings as gs
    s = gs()
    db.execute(text("select 1"))
    st = db.get(PolicyState, 1)
    last_hour = utcnow() - timedelta(hours=1)
    queue = None
    if s.redis_url:
        try:
            from services.engine.consumers.queue import get_queue
            queue = get_queue(s.redis_url, consumer="status").lag()
        except Exception as e:  # noqa: BLE001
            queue = {"error": type(e).__name__}
    kb = db.scalars(select(KBRun).where(KBRun.status == "success").order_by(KBRun.id.desc()).limit(1)).first()
    conns = db.scalars(select(ConnectorState)).all()
    return {"version": "1.0.0", "db_ok": True, "scoring_version": s.scoring()["scoring_version"],
            "policy": {"version": st.version if st else 0, "applied_at": st.applied_at.isoformat() if st and st.applied_at else None,
                       "last_check": st.last_check.isoformat() if st and st.last_check else None, "last_error": st.last_error if st else None},
            "events_last_hour": db.scalar(select(func.count()).select_from(Event).where(Event.received_at >= last_hour)),
            "outbox_pending": db.scalar(select(func.count()).select_from(Outbox).where(Outbox.status == "pending")),
            "outbox_failed": db.scalar(select(func.count()).select_from(Outbox).where(Outbox.status == "failed")),
            "analysis_pending": db.scalar(select(func.count()).select_from(Analysis).where(Analysis.status == "pending")),
            "queue": queue, "kb": {"last_success": kb.finished_at.isoformat() if kb else None, "version": kb.version if kb else None,
                                   "stale": (not kb) or (utcnow() - kb.finished_at).days >= s.kb_stale_days},
            "connectors": {"total": len(conns), "failing": sum(1 for c in conns if c.consecutive_failures > 0)}}


@router.get("/me")
def me(p: Principal = Depends(get_principal)):
    return {"name": p.name, "role": p.role, "tenant_id": p.tenant_id}


@router.get("/dashboard/summary")
def summary(p: Principal = Depends(require("viewer")), db: Session = Depends(get_session)):
    t = Event.tenant_id == p.tenant_id
    cnt = lambda col: dict(db.execute(select(col, func.count()).where(t).group_by(col)).all())  # noqa: E731
    total = db.scalar(select(func.count()).where(t)) or 0
    disp = cnt(Event.disposition)
    filtered = disp.get("filtered", 0)
    top = db.scalars(select(Event).where(t, Event.disposition != "filtered").order_by(Event.risk_score.desc()).limit(8)).all()
    from app.services.queries import event_summary
    return {"total": total, "by_disposition": disp, "by_level": cnt(Event.risk_level), "by_attack_type": cnt(Event.attack_type),
            "by_analysis_status": cnt(Event.analysis_status), "noise_reduction_rate": round(filtered / total, 4) if total else 0.0,
            "top_alerts": [event_summary(e) for e in top],
            "outbox_pending": db.scalar(select(func.count()).select_from(Outbox).join(Event, Event.event_id == Outbox.event_id)
                                        .where(Event.tenant_id == p.tenant_id, Outbox.status == "pending")),
            "outbox_failed": db.scalar(select(func.count()).select_from(Outbox).join(Event, Event.event_id == Outbox.event_id)
                                       .where(Event.tenant_id == p.tenant_id, Outbox.status == "failed"))}


@router.get("/config/scoring")
def scoring_config(p: Principal = Depends(require("viewer"))):
    c = get_settings().scoring()
    return {"scoring_version": c["scoring_version"], "weights_source": c["weights_source"], "criteria_weights": c["criteria_weights_published"],
            "sub_weights": c["sub_weights"], "levels": c["levels"], "environment": c["environment"]}


@router.get("/config/scoring/verify")
def scoring_verify(p: Principal = Depends(require("analyst"))):
    """Bandingkan bobot terpublikasi di paper dengan bobot hasil perhitungan ulang matriks AHP (Tabel 5)."""
    c = get_settings().scoring()
    w, cr = weights_from_matrix(c["ahp_judgment_matrix"])
    pub = c["criteria_weights_published"]
    order = c["criteria_order"]
    return {"consistency_ratio_recomputed": round(cr, 4), "paper_cr": 0.041,
            "criteria": [{"criterion": k, "published": pub[k], "recomputed": round(float(v), 3), "delta": round(float(v) - pub[k], 3)} for k, v in zip(order, w)],
            "note": "Bobot terpublikasi tidak identik dengan eigenvector matriks. Set weights_source='matrix' untuk memakai hasil hitung, lalu validasi pada data berlabel."}


@router.get("/kb/status")
def kb_status(p: Principal = Depends(require("viewer")), db: Session = Depends(get_session)):
    last = db.scalars(select(KBRun).where(KBRun.status == "success").order_by(KBRun.id.desc()).limit(1)).first()
    stale = (not last) or (utcnow() - last.finished_at).days >= get_settings().kb_stale_days
    return {"items": db.scalar(select(func.count()).select_from(KBItem)), "last_success": last.finished_at.isoformat() if last else None,
            "version": last.version if last else None, "source": last.source if last else None, "stale": stale}


@router.post("/kb/sync")
def kb_sync(source: str = "seed", p: Principal = Depends(require("admin")), db: Session = Depends(get_session)):
    if source not in ("seed", "mitre"):
        raise HTTPException(422, "source: seed|mitre")
    from services.kb_sync.main import run_sync
    audit(db, p, "kb.sync", source)
    db.commit()
    return run_sync(source)


@router.get("/kb/candidates")
def candidates(status: str = "pending", p: Principal = Depends(require("analyst")), db: Session = Depends(get_session)):
    rows = db.scalars(select(KBCandidate).where(KBCandidate.tenant_id == p.tenant_id, KBCandidate.status == status).order_by(KBCandidate.id.desc()).limit(100)).all()
    return [{"id": r.id, "event_id": r.event_id, "hypothesis": r.hypothesis, "confidence": r.confidence, "evidence": r.evidence, "status": r.status} for r in rows]


@router.post("/kb/candidates/{cid}/review")
def review_candidate(cid: int, body: CandidateReview, p: Principal = Depends(require("analyst")), db: Session = Depends(get_session)):
    """Promosi terkontrol: hanya analis; LLM tidak pernah menulis ke KB kanonis."""
    r = db.get(KBCandidate, cid)
    if not r or r.tenant_id != p.tenant_id or r.status != "pending":
        raise HTTPException(404, "kandidat tidak ditemukan / sudah ditinjau")
    if body.decision == "approved":
        from services.kb_sync.importer import import_items
        item = {"item_id": (body.technique_id or "").upper(), "kind": "technique",
                "data": {"id": (body.technique_id or "").upper(), "name": body.name or "", "tactics": [body.tactic] if body.tactic else [], "description": r.hypothesis}}
        run = import_items(db, [item], "analyst-approved", f"cand-{cid}")
        if run.status != "success":
            raise HTTPException(422, f"validasi KB gagal: {run.error}")
    r.status, r.reviewed_by = body.decision, p.name
    audit(db, p, "kb.candidate.review", str(cid), {"decision": body.decision})
    db.commit()
    return {"id": cid, "status": r.status}


@router.get("/audit")
def audit_log(limit: int = 100, p: Principal = Depends(require("admin")), db: Session = Depends(get_session)):
    rows = db.scalars(select(AuditLog).where(AuditLog.tenant_id == p.tenant_id).order_by(AuditLog.id.desc()).limit(min(limit, 500))).all()
    return [{"ts": r.ts.isoformat(), "actor": r.actor, "role": r.role, "action": r.action, "target": r.target, "detail": r.detail} for r in rows]
