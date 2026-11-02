import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "apps" / "api")]
_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{_tmp}/test.db"   # TEST_DATABASE_URL=postgresql+psycopg://... untuk uji PostgreSQL
os.environ["API_TOKENS"] = "t-admin:admin:default,t-analyst:analyst:default,t-viewer:viewer:default,t-other:admin:other"
os.environ["INGEST_API_KEY"] = "ingest-key"
os.environ["EMBEDDED_WORKERS"] = "false"
os.environ["OLLAMA_URL"] = ""

import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _db():
    from services.common.db import get_engine, init_db
    from services.common.models import Base
    if os.environ.get("TEST_DATABASE_URL"):   # DB uji khusus: mulai dari skema bersih
        Base.metadata.drop_all(get_engine())
    init_db()
