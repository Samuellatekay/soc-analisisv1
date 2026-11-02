"""Klien Ollama (asinkron terhadap ingest; timeout + retry dikendalikan worker)."""
from __future__ import annotations

import json

import httpx


class OllamaClient:
    def __init__(self, url: str, model: str, timeout: float):
        self.url, self.model, self.timeout = url.rstrip("/"), model, timeout

    def generate_json(self, system: str, user: str) -> dict:
        r = httpx.post(f"{self.url}/api/chat", timeout=self.timeout, json={
            "model": self.model, "stream": False, "format": "json", "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
        r.raise_for_status()
        return json.loads(r.json()["message"]["content"])
