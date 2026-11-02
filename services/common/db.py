from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings
from .models import Base


@lru_cache
def get_engine():
    url = get_settings().database_url
    kw = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False, "timeout": 30}
    eng = create_engine(url, **kw)
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _pragma(dbapi_conn, _):  # WAL agar API + worker bisa berbagi file
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
            dbapi_conn.isolation_level = None  # kendali transaksi manual (lihat 'begin' di bawah)

        @event.listens_for(eng, "begin")
        def _begin(conn):  # BEGIN IMMEDIATE: pembaca yang naik jadi penulis tidak lagi gagal "database is locked"
            conn.exec_driver_sql("BEGIN IMMEDIATE")
    return eng


@lru_cache
def _factory():
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


def init_db() -> None:
    url = get_settings().database_url
    if url.startswith("sqlite:///"):
        from pathlib import Path
        Path(url.replace("sqlite:///", "", 1)).parent.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(get_engine())


@contextmanager
def session_scope():
    s: Session = _factory()()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_session():
    """Dependency FastAPI."""
    s: Session = _factory()()
    try:
        yield s
    finally:
        s.close()
