from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import ingest_tenant
from app.schemas import IngestBatch
from services.common.config import get_settings
from services.common.db import get_session
from services.engine.consumers.queue import get_queue
from services.engine.normalizer.core import ValidationError
from services.engine.pipeline import Pipeline

router = APIRouter(prefix="/ingest", tags=["ingest"])
_pipe: Pipeline | None = None
_queue = None


def pipeline() -> Pipeline:
    global _pipe
    if _pipe is None:
        _pipe = Pipeline()
    return _pipe


@router.post("/{source}")
def ingest(source: str, body: IngestBatch, tenant: str = Depends(ingest_tenant), db: Session = Depends(get_session)):
    """Webhook ingest. mode `inline`: proses sinkron (dev). mode `queue`: validasi cepat lalu Redis Streams (produksi)."""
    global _queue
    s = get_settings()
    if not source.replace("_", "").replace("-", "").isalnum() or len(source) > 40:
        raise HTTPException(422, "nama source tidak valid")
    res = {"accepted": 0, "duplicates": 0, "rejected": []}
    if s.ingest_mode == "queue":
        _queue = _queue or get_queue(s.redis_url, consumer="api")
        if _queue is None:
            raise HTTPException(503, "INGEST_MODE=queue tetapi REDIS_URL belum diset")
        for i, raw in enumerate(body.events):
            _queue.push({"raw": raw, "source": source, "tenant_id": tenant})
            res["accepted"] += 1
        return res
    p = pipeline()
    for i, raw in enumerate(body.events):
        try:
            with db.begin_nested():
                _, created = p.process(db, raw, source, tenant)
            res["accepted" if created else "duplicates"] += 1
        except ValidationError as e:
            res["rejected"].append({"index": i, "error": str(e)})
    db.commit()
    return res
