from __future__ import annotations

import hashlib
import json
from pathlib import Path


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(artifact: Path, meta: dict) -> Path:
    m = {"file": artifact.name, "sha256": sha256_file(artifact), "size": artifact.stat().st_size, **meta}
    mp = artifact.with_suffix(artifact.suffix + ".manifest.json")
    mp.write_text(json.dumps(m, indent=1))
    return mp


def verify_artifact(artifact: Path) -> tuple[bool, str]:
    mp = artifact.with_suffix(artifact.suffix + ".manifest.json")
    if not artifact.exists() or not mp.exists():
        return False, "artefak/manifest tidak ada"
    m = json.loads(mp.read_text())
    if sha256_file(artifact) != m["sha256"]:
        return False, "checksum tidak cocok"
    return True, "ok"
