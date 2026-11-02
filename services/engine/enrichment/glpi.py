"""Provider aset GLPI (REST /apirest.php). Fakta: criticality/sensitivity/exposure/role dari field GLPI yang DIPETAKAN lewat konfigurasi.

Mengapa konfigurasi: ID search-option GLPI berbeda per instalasi dan kritikalitas/sensitivitas biasanya field kustom (plugin Fields).
Temukan ID dengan:  python -m services.engine.enrichment.glpi --list-options Computer   (memakai GLPI_URL/GLPI_APP_TOKEN/GLPI_USER_TOKEN)
Nilai GLPI yang tidak ada di `map` DIABAIKAN (tidak pernah ditebak/di-default ke 'core'). Endpoint dicocokkan dengan dokumentasi resmi GLPI;
BELUM diuji terhadap instance GLPI nyata (hanya respons tiruan)."""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

import httpx

from services.common.util import canon_ip, parse_time, utcnow
from services.engine.graph.facts import Fact

_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|:")


class GlpiError(RuntimeError):
    pass


class GlpiAssetProvider:
    name = "glpi"

    def __init__(self, base_url: str, app_token: str, user_token: str, cfg: dict, verify: bool = True, timeout: float = 5.0, transport=None):
        if not (base_url and user_token):
            raise GlpiError("GLPI_URL dan GLPI_USER_TOKEN wajib")
        self.base = base_url.rstrip("/") + ("" if base_url.rstrip("/").endswith("apirest.php") else "/apirest.php")
        self.app_token, self.user_token, self.cfg = app_token, user_token, cfg
        self.http = httpx.Client(timeout=timeout, verify=verify, transport=transport)
        self._sess: str | None = None
        self._lock = threading.Lock()

    # ---- sesi
    def _init(self) -> str:
        r = self.http.get(f"{self.base}/initSession", headers={"Authorization": f"user_token {self.user_token}", **({"App-Token": self.app_token} if self.app_token else {})})
        if r.status_code >= 400:
            raise GlpiError(f"initSession gagal: HTTP {r.status_code}")   # tidak menyertakan header/token pada pesan
        self._sess = r.json()["session_token"]
        return self._sess

    def _get(self, path: str, params: dict | None = None):
        for attempt in (0, 1):
            with self._lock:
                sess = self._sess or self._init()
            h = {"Session-Token": sess, **({"App-Token": self.app_token} if self.app_token else {})}
            r = self.http.get(f"{self.base}/{path}", params=params, headers=h)
            if r.status_code == 401 and attempt == 0:   # sesi kedaluwarsa -> buka ulang sekali
                with self._lock:
                    self._sess = None
                continue
            if r.status_code >= 400 and r.status_code != 206:   # 206 = hasil parsial (range), valid
                raise GlpiError(f"GET {path.split('?')[0]} gagal: HTTP {r.status_code}")
            return r.json()
        raise GlpiError("sesi GLPI tidak dapat dibuka")

    def close(self):
        if self._sess:
            try:
                self.http.get(f"{self.base}/killSession", headers={"Session-Token": self._sess, **({"App-Token": self.app_token} if self.app_token else {})})
            except httpx.HTTPError:
                pass
            self._sess = None
        self.http.close()

    def list_options(self, itemtype: str) -> list[tuple[str, str, str]]:
        d = self._get(f"listSearchOptions/{itemtype}")
        return [(k, v.get("name", ""), v.get("uid", "")) for k, v in d.items() if isinstance(v, dict) and "name" in v]

    # ---- lookup
    def lookup(self, key: str) -> list[Fact]:
        c = self.cfg
        is_ip = bool(_IP.search(key))
        field = c["fields"]["ip" if is_ip else "name"]
        attr = c.get("attributes", {})
        display = [str(c["fields"]["name"]), str(c["fields"]["ip"]), str(c["fields"].get("updated", 19))] + [str(a["field"]) for a in attr.values()]
        for itemtype in c.get("itemtypes", ["Computer"]):
            params = {"criteria[0][field]": field, "criteria[0][searchtype]": "equals" if is_ip else "contains", "criteria[0][value]": key, "range": "0-4"}
            params.update({f"forcedisplay[{i}]": f for i, f in enumerate(dict.fromkeys(display))})
            d = self._get(f"search/{itemtype}", params)
            rows = d.get("data") or []
            if not rows:
                continue
            if len(rows) > 1 and c.get("on_ambiguous", "skip") == "skip" and not is_ip:
                return []   # nama ambigu -> tidak menebak aset mana yang benar
            return self._facts(rows[0], key)
        return []

    def _facts(self, row: dict, key: str) -> list[Fact]:
        c, now = self.cfg, utcnow()
        first = lambda v: (v[0] if isinstance(v, list) and v else v)  # noqa: E731
        ips = row.get(str(c["fields"]["ip"]))
        ips = ips if isinstance(ips, list) else [ips] if ips else []
        ip = next((canon_ip(str(i)) for i in ips if canon_ip(str(i))), None)
        name = first(row.get(str(c["fields"]["name"])))
        aid = canon_ip(key) or ip or (str(name).lower() if name else key.lower())
        try:
            upd = parse_time(str(first(row.get(str(c["fields"].get("updated", 19)))).replace(" ", "T")))
        except Exception:  # noqa: BLE001
            upd = now
        conf = float(c.get("confidence", 0.85))
        out = []
        for pred, spec in c.get("attributes", {}).items():
            raw = first(row.get(str(spec["field"])))
            val = spec["map"].get(str(raw)) if raw is not None else None
            if val:   # nilai tak terpetakan diabaikan
                out.append(Fact("Asset", aid, pred, None, None, val, self.name, now, upd, conf))
        return out


def from_settings(s, transport=None):
    if not s.glpi_url:
        return None
    cfg = json.loads(Path(s.glpi_config).read_text())
    return GlpiAssetProvider(s.glpi_url, s.glpi_app_token, s.glpi_user_token, cfg, verify=not s.glpi_insecure_tls, timeout=s.enrichment_timeout, transport=transport)


if __name__ == "__main__":
    import argparse
    from services.common.config import get_settings
    ap = argparse.ArgumentParser(); ap.add_argument("--list-options", metavar="ITEMTYPE", required=True); a = ap.parse_args()
    s = get_settings()
    s.glpi_config = s.glpi_config if Path(s.glpi_config).exists() else "infra/config/glpi.example.json"
    p = from_settings(s)
    if not p:
        raise SystemExit("GLPI_URL belum diset")
    for k, name, uid in sorted(p.list_options(a.list_options), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
        print(f"{k:>5}  {name:<40} {uid}")
    p.close()
