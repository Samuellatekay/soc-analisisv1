"""Klien Elasticsearch minimal: upsert idempoten berdasarkan event_id. BELUM diuji terhadap cluster live."""
from __future__ import annotations

import httpx

MAPPING = {"mappings": {"properties": {
    "event_id": {"type": "keyword"}, "tenant_id": {"type": "keyword"}, "source": {"type": "keyword"},
    "event_time": {"type": "date"}, "received_at": {"type": "date"}, "severity": {"type": "keyword"},
    "attack_type": {"type": "keyword"}, "risk_score": {"type": "float"}, "risk_level": {"type": "keyword"},
    "disposition": {"type": "keyword"}, "processing_status": {"type": "keyword"}, "analysis_status": {"type": "keyword"},
    "technique_id": {"type": "keyword"}, "src_ip": {"type": "ip", "ignore_malformed": True}, "dst_ip": {"type": "ip", "ignore_malformed": True},
    "host": {"type": "keyword"}, "message": {"type": "text"}, "signature": {"type": "text"}}}}


class ESClient:
    def __init__(self, url: str, index: str, timeout: float = 10.0):
        self.url, self.index, self.http = url.rstrip("/"), index, httpx.Client(timeout=timeout)

    def ensure_index(self):
        if self.http.head(f"{self.url}/{self.index}").status_code == 404:
            self.http.put(f"{self.url}/{self.index}", json=MAPPING).raise_for_status()

    def upsert(self, doc_id: str, doc: dict):
        self.http.put(f"{self.url}/{self.index}/_doc/{doc_id}", json=doc).raise_for_status()

    def search(self, body: dict) -> dict:
        r = self.http.post(f"{self.url}/{self.index}/_search", json=body)
        r.raise_for_status()
        return r.json()
