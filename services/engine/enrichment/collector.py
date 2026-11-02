"""Collector enrichment: cache TTL + timeout + status missing/stale. Tidak pernah menahan jalur utama."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FTimeout

from services.common.config import Settings
from services.engine.graph.facts import Fact

from .providers import FileAssetProvider, FileIntelProvider, FileVulnProvider, OpenCTIProvider

_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="enrich")


class EnrichmentCollector:
    def __init__(self, settings: Settings, assets=None, intel=None, vulns=None):
        self.s = settings
        from .glpi import from_settings
        self.assets = assets or from_settings(settings) or FileAssetProvider(settings.inventory_file)
        self.intel = intel or (OpenCTIProvider(settings.opencti_url, settings.opencti_token, settings.enrichment_timeout)
                               if settings.opencti_url and settings.opencti_token else FileIntelProvider(settings.intel_file))
        self.vulns = vulns or FileVulnProvider(settings.vuln_file)
        self._cache: dict[tuple, tuple[float, list[Fact]]] = {}

    def _call(self, kind: str, provider, key: str) -> tuple[list[Fact], str]:
        ck = (kind, provider.name, key)
        hit = self._cache.get(ck)
        now = time.time()
        if hit and now - hit[0] < self.s.enrichment_cache_ttl:
            return [Fact(**{**f.__dict__, "attrs": dict(f.attrs)}) for f in hit[1]], "ok"
        fut = _POOL.submit(provider.lookup, key)
        try:
            facts = fut.result(timeout=self.s.enrichment_timeout)
            self._cache[ck] = (now, facts)
            return list(facts), "ok"
        except (FTimeout, Exception):  # noqa: BLE001
            if hit:  # sumber lambat/mati: pakai cache lama, tandai stale
                return list(hit[1]), "stale"
            return [], "missing"

    def collect(self, entities: dict) -> tuple[list[Fact], str]:
        facts: list[Fact] = []
        statuses: list[str] = []
        for k in ("dst_ip", "host", "src_ip"):
            if entities.get(k):
                f, st = self._call("asset", self.assets, entities[k])
                facts += f; statuses.append(st)
                f, st = self._call("vuln", self.vulns, entities[k])
                facts += f; statuses.append(st)
        from services.common.util import is_private_ip
        for k in ("src_ip", "dst_ip", "domain", "hash"):
            if entities.get(k) and not (k in ("src_ip", "dst_ip") and is_private_ip(entities[k])):
                f, st = self._call("intel", self.intel, entities[k])
                facts += f; statuses.append(st)
        if not statuses:
            return facts, "missing"
        if all(s == "ok" for s in statuses):
            return facts, "ok"
        if "stale" in statuses:
            return facts, "stale"
        return facts, "partial" if "ok" in statuses else "missing"
