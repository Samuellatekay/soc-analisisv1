"""Sumber MITRE ATT&CK (STIX 2.1 dari repo resmi mitre-attack/attack-stix-data) + seed offline."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx

STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def parse_stix(bundle: dict) -> tuple[list[dict], str]:
    items: list[dict] = []
    version = ""
    for o in bundle.get("objects", []):
        if o.get("type") == "x-mitre-collection":
            version = str(o.get("x_mitre_version") or version)
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        tactics = [p["phase_name"].replace("-", " ").title() for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        if not tid:
            continue
        items.append({"item_id": tid, "kind": "technique", "data": {
            "id": tid, "name": o.get("name", ""), "tactics": tactics, "description": (o.get("description") or "")[:600]}})
    return items, version or hashlib.sha256(json.dumps(bundle.get("id", ""), sort_keys=True).encode()).hexdigest()[:12]


def fetch(url: str = STIX_URL, timeout: float = 120.0) -> tuple[list[dict], str]:
    r = httpx.get(url, timeout=timeout, follow_redirects=True)
    r.raise_for_status()
    return parse_stix(r.json())


def load_seed(path: str) -> tuple[list[dict], str]:
    d = json.loads(Path(path).read_text())
    return d["items"], d["version"]
