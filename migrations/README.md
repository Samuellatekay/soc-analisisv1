# Migrasi

- `0001_init.sql` — skema awal PostgreSQL (dihasilkan dari model SQLAlchemy). Terapkan: `psql "$DATABASE_URL" -f migrations/0001_init.sql`.
- Mode development memakai `Base.metadata.create_all` (otomatis saat API start).
- **Sebelum produksi** adopsi Alembic (`alembic init`, autogenerate dari `services/common/models.py`) agar perubahan skema berikutnya berurutan dan dapat di-rollback. File SQL ini bukan pengganti Alembic.
