"""Hasilkan ulang migrations/0001_init.sql dari model (jalankan setelah mengubah services/common/models.py).
CATATAN: ini bukan pengganti Alembic untuk perubahan skema berurutan di produksi."""
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[1])]
from sqlalchemy.dialects import postgresql  # noqa: E402
from sqlalchemy.schema import CreateIndex, CreateTable  # noqa: E402

from services.common.models import Base  # noqa: E402

out = ["-- 0001_init.sql (dihasilkan oleh scripts/gen_ddl.py dari services/common/models.py untuk PostgreSQL)\n"]
for t in Base.metadata.sorted_tables:
    out.append(str(CreateTable(t).compile(dialect=postgresql.dialect())).strip() + ";\n")
    out += [str(CreateIndex(ix).compile(dialect=postgresql.dialect())).strip() + ";\n" for ix in t.indexes]
Path(__file__).resolve().parents[1].joinpath("migrations/0001_init.sql").write_text("\n".join(out))
print(f"{len(Base.metadata.tables)} tabel")
