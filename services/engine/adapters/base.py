"""Kontrak konektor: autentikasi, poll+paginasi, checkpoint (cursor), retry/rate-limit, versi mapping, health.
Satu kelas per produk — format, auth, paginasi, dan rate limit tiap vendor berbeda."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from services.common.util import parse_time, utcnow

from .http import ApiClient
from .mappings import MAPPING_VERSION

_FRAC = re.compile(r"(\.\d{6})\d+")


def parse_ts(v: str) -> datetime:
    """Parse ISO8601 termasuk pecahan detik >6 digit (nanodetik, mis. CrowdStrike)."""
    return parse_time(_FRAC.sub(r"\1", v))


def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Page:
    events: list[dict]
    cursor: str          # cursor baru (watermark), aman disimpan SETELAH events berhasil diserahkan
    more: bool = False   # kemungkinan masih ada data langsung tersedia


class Connector:
    type = "base"
    mapping_version = MAPPING_VERSION

    def __init__(self, name: str, params: dict, secret: Callable[[str], str], client: ApiClient | None = None,
                 now: Callable[[], datetime] = utcnow, transport=None, sleep=None):
        self.name, self.p, self.secret, self.now = name, params, secret, now
        self.transport, self._sleep = transport, sleep  # injeksi untuk uji tanpa jaringan
        self.overlap = int(params.get("overlap_seconds", 120))  # baca ulang sedikit ke belakang; duplikat dibuang oleh dedupe event_id
        self.client = client or self.make_client()

    # --- diimplementasikan per vendor
    def make_client(self) -> ApiClient:
        raise NotImplementedError

    def fetch(self, cursor: str, limit: int) -> Page:
        raise NotImplementedError

    def initial_cursor(self, lookback_hours: int) -> str:
        return iso(self.now() - timedelta(hours=lookback_hours))

    def source(self) -> str:
        return f"{self.type}:{self.name}"

    def test(self) -> dict:
        """Uji koneksi+auth+format: ambil <=1 event tanpa menyimpan apa pun."""
        pg = self.fetch(self.initial_cursor(int(self.p.get("initial_lookback_hours", 24))), 1)
        return {"ok": True, "sample_count": len(pg.events)}

    # --- util
    def new_client(self, base_url: str = "", headers: dict | None = None) -> ApiClient:
        kw = {"sleep": self._sleep} if self._sleep else {}
        return ApiClient(base_url, headers, self.verify_tls(), transport=self.transport, **kw)

    def verify_tls(self) -> bool:
        return bool(self.p.get("verify_tls", True))

    def _since(self, cursor: str) -> datetime:
        return parse_ts(cursor) - timedelta(seconds=self.overlap)
