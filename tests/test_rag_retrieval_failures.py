from datetime import timedelta

from sqlalchemy import select

from services.common.db import session_scope
from services.common.models import Analysis, Event
from services.common.util import utcnow
from services.rag_worker import worker


def _pending_analysis(event_id: str) -> None:
    with session_scope() as db:
        db.add(Event(event_id=event_id, tenant_id="rag-retry", source="test", source_event_id=event_id,
                     event_time=utcnow(), triplet_key=event_id, analysis_status="pending"))
        db.add(Analysis(event_id=event_id, tenant_id="rag-retry", created_at=utcnow() - timedelta(minutes=5)))


def test_retrieval_failure_retries_without_crashing_worker(monkeypatch):
    event_id = "rag-retrieval-retry"
    _pending_analysis(event_id)

    def fail(_settings):
        raise RuntimeError("Neo4j unavailable")

    monkeypatch.setattr(worker, "get_retriever", fail)
    assert worker.process_one()
    with session_scope() as db:
        job = db.scalars(select(Analysis).where(Analysis.event_id == event_id)).one()
        event = db.get(Event, event_id)
        assert job.status == "pending"
        assert job.attempts == 1
        assert "Neo4j unavailable" in job.error
        assert job.next_attempt_at > utcnow()
        assert event.analysis_status == "pending"
