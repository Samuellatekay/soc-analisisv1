"""RAG -> LLM worker (asinkron). Tidak menghitung ulang skor, tidak menghapus alert, tidak menulis graph."""
from __future__ import annotations

import json
import logging
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from services.common.config import Settings, get_settings
from services.common.db import session_scope
from services.common.models import Analysis, Event, Outbox
from services.common.util import sanitize, utcnow

from .llm_client import create_llm_client
from .retrieval.graph import Doc, get_retriever

log = logging.getLogger("rag_worker")
MAX_ATTEMPTS = 3
JOB_MAX_AGE = timedelta(hours=24)


def _prompt(s: Settings) -> str:
    return (Path(__file__).parent / "prompts" / f"{s.prompt_version}.txt").read_text()


def build_user_prompt(ev: Event, docs: list[Doc]) -> str:
    sc = ev.score_components
    alert = sanitize({"event_id": ev.event_id, "source": ev.source, "time": ev.event_time.isoformat(), "type": ev.attack_type,
                      "signature": ev.signature, "severity": ev.severity, "src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
                      "host": ev.host, "technique": ev.technique_id, "tactic": ev.tactic, "message": ev.message})
    score = {"R": ev.risk_score, "level": ev.risk_level, "version": ev.scoring_version,
             "criteria": {k: {"W": v["W"], "C": v["C"]} for k, v in sc.get("criteria", {}).items()}}
    evid = {"validated_graph_evidence": (ev.integrity or {}).get("evidence", {}), "disposition": ev.disposition,
            "disposition_reason": ev.disposition_reason}
    return (f"<untrusted_data id=\"event\">{json.dumps(alert, ensure_ascii=False)}</untrusted_data>\n"
            f"<risk_score readonly=\"true\">{json.dumps(score)}</risk_score>\n"
            f"<evidence>\n{json.dumps({'graph_context': evid, 'knowledge_base': [d.to_dict() for d in docs]}, ensure_ascii=False)}\n</evidence>")


def template_analysis(ev: Event, docs: list[Doc]) -> dict:
    """Analisis deterministik (tanpa provider LLM). Selalu diberi label model 'template-v1'."""
    sup = [{"claim": f"Skor risiko {ev.risk_score} ({ev.risk_level}); disposisi: {ev.disposition_reason}", "source": "event"}]
    ioc = (ev.integrity or {}).get("evidence", {}).get("ioc", {})
    if ioc.get("verdict"):
        sup.append({"claim": f"IOC {ioc.get('indicator')} berstatus {ioc['verdict']} (confidence {ioc.get('confidence')})", "source": "event"})
    rec = []
    for d in docs:
        if d.kind == "playbook":
            rec += [{"action": step.strip(), "source": d.source_id} for step in d.text.split(": ", 1)[-1].split(";")]
        else:
            sup.append({"claim": d.text[:200], "source": d.source_id})
    return {"summary": f"Alert {ev.attack_type} dari {ev.src_ip} ke {ev.dst_ip}; risiko {ev.risk_level} ({ev.risk_score}).",
            "supporting_evidence": sup, "contradicting_evidence": [], "hypotheses": [],
            "confidence": "medium" if ev.risk_level in ("medium", "high") else "low", "triage_recommendations": rec}


def validate_output(out: dict, allowed: set[str]) -> dict:
    """Buang klaim yang mengutip sumber di luar bukti yang diambil (anti-halusinasi rujukan)."""
    dropped = 0
    for key in ("supporting_evidence", "contradicting_evidence", "triage_recommendations"):
        keep = []
        for x in out.get(key, []) or []:
            if isinstance(x, dict) and x.get("source") in allowed:
                keep.append(x)
            else:
                dropped += 1
        out[key] = keep
    out["_dropped_unsupported"] = dropped
    out["summary"] = str(out.get("summary", ""))[:2000]
    return out


def _finish(job_id: str, fn) -> None:
    """Tulis hasil (transaksi pendek). fn(db, job, ev) memutasi job/ev."""
    with session_scope() as db:
        job, ev = db.get(Analysis, job_id), db.get(Event, job_id)
        fn(db, job, ev)
        db.add(Outbox(event_id=job_id))  # outbox di transaksi yang sama dengan hasil analisis


def process_one(s: Settings | None = None) -> bool:
    s = s or get_settings()
    now = utcnow()
    # fase 1: klaim job (transaksi pendek). next_attempt_at digeser sebagai 'lease' agar worker lain tidak mengambil job yang sama
    with session_scope() as db:
        job = db.scalars(select(Analysis).where(Analysis.status == "pending", Analysis.next_attempt_at <= now)
                         .order_by(Analysis.created_at).limit(1).with_for_update(skip_locked=True)).first()
        if not job:
            return False
        job.attempts += 1
        job.next_attempt_at = now + timedelta(minutes=5)
        jid, attempts, created = job.event_id, job.attempts, job.created_at
        ev = db.get(Event, jid)
        db.expunge(ev)  # snapshot read-only untuk fase 2
    if now - created > JOB_MAX_AGE:
        def too_old(db, job, ev):
            job.status, job.error, ev.analysis_status = "failed", "job melewati batas umur", "failed"
        _finish(jid, too_old)
        return True
    # fase 2: retrieval + LLM DI LUAR transaksi (tidak menahan lock database)
    try:
        docs = get_retriever(s).retrieve(ev.tenant_id, ev.technique_id, ev.attack_type, ev.tactic)
    except Exception as e:  # noqa: BLE001  kegagalan graph/retrieval harus retry, bukan mematikan worker
        log.warning("retrieval analisis %s gagal (percobaan %s): %s", jid, attempts, e)
        err = repr(e)[:500]
        def retrieval_failed(db, job, ev):
            job.error = err
            if attempts >= MAX_ATTEMPTS:
                job.status, ev.analysis_status = "failed", "failed"
            else:
                job.next_attempt_at = utcnow() + timedelta(seconds=30 * 2 ** attempts)
        _finish(jid, retrieval_failed)
        return True
    if not docs:
        def nodocs(db, job, ev):
            job.status, job.model, job.prompt_version, job.sources = "insufficient_evidence", "none", s.prompt_version, []
            job.result = {"summary": "Bukti knowledge base tidak ditemukan; tinjau manual."}
            ev.analysis_status = "insufficient_evidence"
        _finish(jid, nodocs)
        return True
    try:
        client = create_llm_client(s)
        if client:
            out = client.generate_json(_prompt(s), build_user_prompt(ev, docs))
            model = client.model
        else:
            out, model = template_analysis(ev, docs), "template-v1(no-llm)"
        out = validate_output(out, {"event"} | {d.source_id for d in docs})
    except Exception as e:  # noqa: BLE001  timeout / JSON rusak / model mati
        log.warning("analisis %s gagal (percobaan %s): %s", jid, attempts, e)
        err = repr(e)[:500]
        def failed(db, job, ev):
            job.error = err
            if attempts >= MAX_ATTEMPTS:
                job.status, ev.analysis_status = "failed", "failed"
            else:
                job.next_attempt_at = utcnow() + timedelta(seconds=30 * 2 ** attempts)
        _finish(jid, failed)
        return True
    # fase 3: simpan hasil
    def done(db, job, ev):
        job.status, job.result, job.model, job.prompt_version = "completed", out, model, s.prompt_version
        job.sources, job.error = [d.to_dict() for d in docs], None
        ev.analysis_status = "completed"
    _finish(jid, done)
    return True
