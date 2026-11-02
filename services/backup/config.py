"""Konfigurasi backup dari environment (.env). Secret (encryption key) hanya dari file secret."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BackupConfig:
    enabled: bool
    cron: str
    timezone: str
    components: list[str]
    retention_days: int
    repository: str
    verify_after_run: bool
    key_file: str

    @classmethod
    def from_env(cls) -> "BackupConfig":
        g = os.getenv
        return cls(
            enabled=g("BACKUP_ENABLED", "false").lower() == "true", cron=g("BACKUP_SCHEDULE_CRON", "0 2 * * *"),
            timezone=g("BACKUP_TIMEZONE", "Asia/Jakarta"),
            components=[c.strip() for c in g("BACKUP_COMPONENTS", "postgres").split(",") if c.strip()],
            retention_days=int(g("BACKUP_RETENTION_DAYS", "30")), repository=g("BACKUP_REPOSITORY_URI", ""),
            verify_after_run=g("BACKUP_VERIFY_AFTER_RUN", "true").lower() == "true",
            key_file=g("BACKUP_ENCRYPTION_KEY_FILE", ""))

    def validate(self) -> list[str]:
        errs = []
        if not self.repository:
            errs.append("BACKUP_REPOSITORY_URI wajib diisi (direktori lokal/mount repositori terpisah)")
        elif not Path(self.repository).is_absolute():
            errs.append("BACKUP_REPOSITORY_URI harus path absolut")
        if self.key_file and not Path(self.key_file).exists():
            errs.append(f"BACKUP_ENCRYPTION_KEY_FILE tidak ditemukan: {self.key_file}")
        return errs
