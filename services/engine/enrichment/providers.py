"""Provider enrichment. Setiap provider mengembalikan *kandidat Fact* (belum tervalidasi).

- File*Provider : bekerja offline dari JSON (mis. hasil ekspor GLPI / daftar IOC / hasil scan).
- OpenCTIProvider: GraphQL OpenCTI. BELUM diuji terhadap server live — verifikasi skema query pada versi Anda.
- GLPI: gunakan ekspor inventaris ke ASSET_INVENTORY_FILE, atau implementasikan AssetProvider.lookup via REST GLPI.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

import httpx

from services.common.util import canon_ip, parse_time, utcnow
from services.engine.graph.facts import Fact


def _ts(v, default):
    try:
        return parse_time(v) if v else default
    except Exception:  # noqa: BLE001
        return default


class AssetProvider(Protocol):
    name: str
    def lookup(self, key: str) -> list[Fact]: ...


class IntelProvider(Protocol):
    name: str
    def lookup(self, indicator: str) -> list[Fact]: ...


class VulnProvider(Protocol):
    name: str
    def lookup(self, asset: str) -> list[Fact]: ...


def _load(path: str) -> list[dict]:
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else []


class FileAssetProvider:
    name = "glpi"

    def __init__(self, path: str):
        self.path = path

    def lookup(self, key: str) -> list[Fact]:
        key_l = key.lower()
        out: list[Fact] = []
        now = utcnow()
        for r in _load(self.path):
            ids = {str(r.get("ip", "")).lower(), str(r.get("hostname", "")).lower()}
            if key_l not in ids:
                continue
            aid = canon_ip(r.get("ip")) or str(r.get("hostname", "")).lower()
            upd = _ts(r.get("updated_at"), now)
            for pred in ("criticality", "sensitivity", "exposure", "role"):
                if r.get(pred):
                    out.append(Fact("Asset", aid, pred, None, None, str(r[pred]), self.name, now, upd, float(r.get("confidence", 0.9))))
        return out


class FileIntelProvider:
    name = "opencti"

    def __init__(self, path: str):
        self.path = path

    def lookup(self, indicator: str) -> list[Fact]:
        ind = indicator.lower()
        now = utcnow()
        out: list[Fact] = []
        for r in _load(self.path):
            if str(r.get("indicator", "")).lower() != ind:
                continue
            conf = float(r.get("confidence", 0.5))
            upd = _ts(r.get("updated_at"), now)
            src = r.get("source", self.name)
            out.append(Fact("IOC", ind, "verdict", None, None, r.get("verdict", "suspicious"), src, now, upd, conf))
            if r.get("apt"):
                out.append(Fact("IOC", ind, "attributed_to", "APT", r["apt"], None, src, now, upd, conf,
                                {"threat_level": float(r.get("apt_threat_level", 0.5))}))
        return out


class FileVulnProvider:
    name = "vuln-scanner"

    def __init__(self, path: str):
        self.path = path

    def lookup(self, asset: str) -> list[Fact]:
        now = utcnow()
        out: list[Fact] = []
        for r in _load(self.path):
            if str(r.get("asset", "")).lower() != asset.lower():
                continue
            out.append(Fact("Asset", canon_ip(r["asset"]) or r["asset"].lower(), "has_vulnerability", "CVE", r["cve"], None,
                            r.get("source", self.name), now, _ts(r.get("updated_at"), now), float(r.get("confidence", 0.9)),
                            {"exploit": r.get("exploit", "vuln_only")}))
        return out


class OpenCTIProvider:  # pragma: no cover - butuh server live
    name = "opencti"
    QUERY = """query($s:String){ indicators(search:$s, first:5){ edges{ node{ confidence x_opencti_score updated_at } } } }"""

    def __init__(self, url: str, token: str, timeout: float):
        self.url, self.token, self.timeout = url.rstrip("/"), token, timeout

    def lookup(self, indicator: str) -> list[Fact]:
        r = httpx.post(f"{self.url}/graphql", json={"query": self.QUERY, "variables": {"s": indicator}},
                       headers={"Authorization": f"Bearer {self.token}"}, timeout=self.timeout)
        r.raise_for_status()
        payload = r.json()
        if payload.get("errors"):
            raise RuntimeError("OpenCTI GraphQL query failed")
        indicators = (payload.get("data") or {}).get("indicators")
        if not isinstance(indicators, dict) or not isinstance(indicators.get("edges"), list):
            raise RuntimeError("OpenCTI GraphQL response has an unexpected shape")
        now = utcnow()
        out: list[Fact] = []
        for e in indicators["edges"]:
            n = e.get("node") if isinstance(e, dict) else None
            if not isinstance(n, dict):
                raise RuntimeError("OpenCTI GraphQL indicator has an unexpected shape")
            score = (n.get("x_opencti_score") or 0) / 100.0
            if score >= 0.5:
                out.append(Fact("IOC", indicator.lower(), "verdict", None, None, "malicious" if score >= 0.75 else "suspicious",
                                self.name, now, _ts(n.get("updated_at"), now), float(n.get("confidence", 50)) / 100.0))
        return out
