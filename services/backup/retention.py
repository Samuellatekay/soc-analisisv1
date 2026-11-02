from __future__ import annotations

import time
from pathlib import Path


def prune(repo: Path, days: int, now: float | None = None) -> list[str]:
    cutoff = (now or time.time()) - days * 86400
    removed = []
    for p in repo.glob("*"):
        if p.is_file() and p.stat().st_mtime < cutoff:
            p.unlink()
            removed.append(p.name)
    return removed
