"""Model data kanonis (PostgreSQL di produksi, SQLite untuk development)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    from .util import utcnow
    return utcnow()


class Event(Base):
    __tablename__ = "events"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(64))
    source_event_id: Mapped[str] = mapped_column(String(128))
    event_time: Mapped[datetime] = mapped_column(DateTime, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    severity: Mapped[str] = mapped_column(String(16), default="low")
    attack_type: Mapped[str] = mapped_column(String(48), default="other", index=True)
    signature: Mapped[str] = mapped_column(String(256), default="")
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    host: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    entities: Mapped[dict] = mapped_column(JSON, default=dict)
    technique_id: Mapped[str | None] = mapped_column(String(16), index=True, nullable=True)
    tactic: Mapped[str | None] = mapped_column(String(48), nullable=True)
    triplet_key: Mapped[str] = mapped_column(String(300), index=True, default="")
    message: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)  # sudah disanitasi
    # status terpisah (spec): received -> normalized -> scored -> indexed ; analisis AI terpisah
    processing_status: Mapped[str] = mapped_column(String(16), default="received", index=True)
    analysis_status: Mapped[str] = mapped_column(String(24), default="not_requested")
    disposition: Mapped[str] = mapped_column(String(16), default="retained", index=True)  # retained|manual_review|filtered
    disposition_reason: Mapped[str] = mapped_column(Text, default="")
    noise_info: Mapped[dict] = mapped_column(JSON, default=dict)
    orchestration: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float | None] = mapped_column(Float, index=True, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(8), index=True, nullable=True)
    scoring_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    score_components: Mapped[dict] = mapped_column(JSON, default=dict)
    graph_snapshot_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    integrity: Mapped[dict] = mapped_column(JSON, default=dict)
    enrichment_status: Mapped[str] = mapped_column(String(16), default="missing")
    __table_args__ = (
        UniqueConstraint("tenant_id", "source", "source_event_id", name="uq_event_dedupe"),
        Index("ix_events_tenant_time", "tenant_id", "event_time"),
    )


class TripletCount(Base):
    __tablename__ = "triplet_counts"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    triplet_key: Mapped[str] = mapped_column(String(300), primary_key=True)
    hour: Mapped[datetime] = mapped_column(DateTime, primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)


class TripletState(Base):
    __tablename__ = "triplet_state"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    triplet_key: Mapped[str] = mapped_column(String(300), primary_key=True)
    evaluated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)


class Outbox(Base):
    __tablename__ = "outbox"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(24), default="upsert_alert")
    status: Mapped[str] = mapped_column(String(12), default="pending", index=True)  # pending|done|failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Analysis(Base):
    """Hasil RAG->LLM; baris `pending` sekaligus berfungsi sebagai antrean analisis."""
    __tablename__ = "analyses"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)  # pending|completed|failed|insufficient_evidence
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class Case(Base):
    __tablename__ = "cases"
    case_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="New", index=True)
    priority: Mapped[str] = mapped_column(String(8), default="medium")
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class CaseAlert(Base):
    __tablename__ = "case_alerts"
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    linked_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class CaseNote(Base):
    __tablename__ = "case_notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), index=True)
    author: Mapped[str] = mapped_column(String(128))
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(128), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)


class KBItem(Base):
    """Knowledge base kanonis untuk dev (dicerminkan ke Neo4j bila dikonfigurasi)."""
    __tablename__ = "kb_items"
    item_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # technique|playbook
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(64), default="")
    version: Mapped[str] = mapped_column(String(64), default="")
    checksum: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class KBRun(Base):
    __tablename__ = "kb_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(12), default="running")  # running|success|failed
    source: Mapped[str] = mapped_column(String(64), default="")
    version: Mapped[str] = mapped_column(String(64), default="")
    added: Mapped[int] = mapped_column(Integer, default=0)
    updated: Mapped[int] = mapped_column(Integer, default=0)
    unchanged: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    previous_snapshot: Mapped[list] = mapped_column(JSON, default=list)  # untuk rollback


class Lease(Base):
    __tablename__ = "leases"
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    holder: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class KBCandidate(Base):
    """Kandidat teknik baru: harus disetujui analis sebelum masuk graph kanonis."""
    __tablename__ = "kb_candidates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    event_id: Mapped[str] = mapped_column(String(36))
    hypothesis: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(12), default="pending")  # pending|approved|rejected
    reviewed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ConnectorState(Base):
    """Checkpoint + kesehatan per konektor (cursor hanya maju setelah event berhasil diserahkan ke pipeline/antrean)."""
    __tablename__ = "connector_state"
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default")
    type: Mapped[str] = mapped_column(String(32), default="")
    cursor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    last_success: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_warning: Mapped[str | None] = mapped_column(Text, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    events_total: Mapped[int] = mapped_column(Integer, default=0)
    rejected_total: Mapped[int] = mapped_column(Integer, default=0)
    mapping_version: Mapped[str] = mapped_column(String(32), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class ConnectorConfig(Base):
    """Konfigurasi konektor yang dapat dikelola admin dan dibaca seluruh worker."""
    __tablename__ = "connector_configs"
    __table_args__ = (UniqueConstraint("name", name="uq_connector_configs_name"),)
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    type: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(default=False)
    poll_seconds: Mapped[int] = mapped_column(Integer, default=60)
    batch_size: Mapped[int] = mapped_column(Integer, default=500)
    initial_lookback_hours: Mapped[int] = mapped_column(Integer, default=24)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class PolicyState(Base):
    """Kebijakan terpasang di cluster ini (satu baris). Diisi policy agent setelah verifikasi tanda tangan; engine membacanya (TTL) — tidak pernah memanggil Master."""
    __tablename__ = "policy_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    version: Mapped[int] = mapped_column(Integer, default=0)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    signature: Mapped[str] = mapped_column(Text, default="")
    issued_at: Mapped[str] = mapped_column(String(32), default="")
    applied_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_check: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
