"""Basis data Master (TERPISAH dari data cluster; berisi konfigurasi/kebijakan/status — bukan alert)."""
from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from services.common.config import ROOT


class MBase(DeclarativeBase):
    pass


def _now():
    from services.common.util import utcnow
    return utcnow()


class Cluster(MBase):
    __tablename__ = "m_clusters"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    region: Mapped[str] = mapped_column(String(64), default="")
    api_url: Mapped[str] = mapped_column(String(256))
    status_token_env: Mapped[str] = mapped_column(String(64), default="")     # NAMA env var berisi token baca-status cluster (bukan nilainya)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    pull_token_hash: Mapped[str] = mapped_column(String(64))                  # sha256 token tarik-kebijakan milik cluster
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class PolicyRow(MBase):
    __tablename__ = "m_policies"
    version: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy: Mapped[dict] = mapped_column(JSON)
    targets: Mapped[list] = mapped_column(JSON)                                # ["*"] atau daftar id cluster
    note: Mapped[str] = mapped_column(Text, default="")
    issued_at: Mapped[str] = mapped_column(String(32))
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ClusterConfiguration(MBase):
    __tablename__ = "m_cluster_configurations"
    cluster_id: Mapped[str] = mapped_column(ForeignKey("m_clusters.id"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, default=0)
    encrypted_payload: Mapped[str] = mapped_column(Text)
    issued_at: Mapped[str] = mapped_column(String(32))
    updated_by: Mapped[str] = mapped_column(String(128))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class StatusRow(MBase):
    __tablename__ = "m_status"
    cluster_id: Mapped[str] = mapped_column(ForeignKey("m_clusters.id"), primary_key=True)
    polled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ok_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_policy_fetch: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MAudit(MBase):
    __tablename__ = "m_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=_now)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(128), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


def url() -> str:
    return os.getenv("MASTER_DATABASE_URL", f"sqlite:///{ROOT / 'data' / 'master.db'}")


@lru_cache
def engine():
    u = url()
    kw = {"connect_args": {"check_same_thread": False, "timeout": 30}} if u.startswith("sqlite") else {"pool_pre_ping": True}
    if u.startswith("sqlite:///"):
        Path(u.replace("sqlite:///", "", 1)).parent.mkdir(parents=True, exist_ok=True)
    e = create_engine(u, **kw)
    if u.startswith("sqlite"):
        @event.listens_for(e, "connect")
        def _p(c, _):
            c.execute("PRAGMA journal_mode=WAL"); c.isolation_level = None

        @event.listens_for(e, "begin")
        def _b(conn):
            conn.exec_driver_sql("BEGIN IMMEDIATE")
    return e


@lru_cache
def _factory():
    return sessionmaker(bind=engine(), expire_on_commit=False)


def init():
    MBase.metadata.create_all(engine())


@contextmanager
def scope():
    s = _factory()()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def dep():
    s = _factory()()
    try:
        yield s
    finally:
        s.close()
