"""Konektor per produk. Detail API diverifikasi terhadap dokumentasi vendor (lihat docs/CONNECTORS.md) tetapi
BELUM diuji terhadap tenant/versi produk Anda — jalankan `test` per konektor dan sesuaikan sebelum diaktifkan."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone

from services.common.util import parse_time

from .base import Connector, Page, iso, parse_ts
from .http import AdapterError, ApiClient, OAuthClientCredentials


def _need(p: dict, *keys: str):
    miss = [k for k in keys if not p.get(k)]
    if miss:
        raise AdapterError(f"parameter konektor kurang: {', '.join(miss)}")


# =============================================================== Splunk Enterprise Security
class SplunkES(Connector):
    """POST /services/search/jobs/export (streaming) atas index `notable`. Auth: Splunk token (Bearer). Cursor = _indextime (epoch)."""
    type = "splunk_es"
    FIELDS = ("_time,ixt,event_id,rule_name,rule_title,search_name,urgency,severity,src,dest,dest_port,transport,user,signature,"
              "security_domain,orig_raw,annotations.mitre_attack.mitre_technique_id")

    def make_client(self):
        _need(self.p, "base_url", "token_env")
        return self.new_client(self.p["base_url"], {"Authorization": f"Bearer {self.secret(self.p['token_env'])}"})

    def initial_cursor(self, lookback_hours):
        return str(int(self.now().replace(tzinfo=timezone.utc).timestamp()) - lookback_hours * 3600)

    def fetch(self, cursor, limit):
        since = int(cursor) - self.overlap
        spl = (f"search index={self.p.get('index', 'notable')} _index_earliest={since} | eval ixt=_indextime | sort 0 ixt | head {limit} | fields {self.FIELDS}")
        r = self.client.request("POST", "/services/search/jobs/export", data={
            "search": spl, "output_mode": "json", "earliest_time": self.p.get("event_window", "-7d"), "latest_time": "now"})
        events = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("result"):
                events.append(obj["result"])
        if not events:
            return Page([], cursor)
        newest = max(int(float(e["ixt"])) for e in events)
        if len(events) >= limit and newest <= int(cursor) - self.overlap:
            raise AdapterError("halaman penuh tanpa kemajuan _indextime; naikkan batch_size agar tidak ada event terlewat")
        return Page(events, str(max(newest, int(cursor))), len(events) >= limit)


# =============================================================== Microsoft Sentinel
class Sentinel(Connector):
    """Azure Resource Manager: Microsoft.SecurityInsights/incidents (api-version 2023-02-01). Auth: Entra ID client-credentials."""
    type = "sentinel"

    def make_client(self):
        _need(self.p, "tenant_id", "client_id", "client_secret_env", "subscription_id", "resource_group", "workspace")
        c = self.new_client("https://management.azure.com")
        self.auth = OAuthClientCredentials(c, f"https://login.microsoftonline.com/{self.p['tenant_id']}/oauth2/v2.0/token", {
            "grant_type": "client_credentials", "client_id": self.p["client_id"], "client_secret": self.secret(self.p["client_secret_env"]),
            "scope": "https://management.azure.com/.default"})
        return c

    def _base(self):
        p = self.p
        return (f"/subscriptions/{p['subscription_id']}/resourceGroups/{p['resource_group']}/providers/Microsoft.OperationalInsights/"
                f"workspaces/{p['workspace']}/providers/Microsoft.SecurityInsights")

    def _get(self, url, params=None):
        return self.client.request("GET", url, params=params, headers_fn=self.auth.headers, on_unauthorized=self.auth.refresh)

    def fetch(self, cursor, limit):
        since = iso(self._since(cursor))
        r = self._get(f"{self._base()}/incidents", {"api-version": "2023-02-01", "$filter": f"properties/lastModifiedTimeUtc ge {since}",
                                                  "$orderby": "properties/lastModifiedTimeUtc asc", "$top": min(limit, 200)})
        items: list[dict] = []
        pages = 0
        while True:
            j = r.json()
            items += j.get("value", [])
            nxt = j.get("nextLink")
            pages += 1
            if not nxt or len(items) >= limit or pages >= int(self.p.get("max_pages", 20)):
                break
            r = self._get(nxt)  # nextLink absolut, sudah membawa query
        items = items[:limit]
        if self.p.get("fetch_entities", True):
            for it in items:
                try:
                    er = self.client.request("POST", f"{self._base()}/incidents/{it['name']}/entities", params={"api-version": "2023-02-01"},
                                             headers_fn=self.auth.headers, on_unauthorized=self.auth.refresh)
                    it["_entities"] = er.json().get("entities", [])
                except AdapterError:
                    it["_entities"] = []  # entitas gagal diambil: event tetap diproses tanpa entitas
        if not items:
            return Page([], cursor)
        newest = max(parse_ts(i["properties"]["lastModifiedTimeUtc"]) for i in items)
        return Page(items, iso(max(newest, parse_ts(cursor))), len(items) >= limit)


# =============================================================== IBM QRadar
class QRadar(Connector):
    """GET /api/siem/offenses (Range header, filter last_updated_time). Auth: header SEC. Cursor = last_updated_time (ms)."""
    type = "qradar"
    FIELDS = "id,description,severity,magnitude,offense_source,offense_type,categories,start_time,last_updated_time,event_count,status"

    def make_client(self):
        _need(self.p, "base_url", "token_env")
        return self.new_client(self.p["base_url"], {"SEC": self.secret(self.p["token_env"]), "Version": str(self.p.get("api_version", "19.0")),
                                               "Accept": "application/json"})

    def initial_cursor(self, lookback_hours):
        return str(int(self.now().replace(tzinfo=timezone.utc).timestamp() * 1000) - lookback_hours * 3600_000)

    def fetch(self, cursor, limit):
        since = int(cursor) - self.overlap * 1000
        r = self.client.request("GET", "/api/siem/offenses", params={"filter": f"last_updated_time > {since}", "sort": "+last_updated_time", "fields": self.FIELDS},
                                headers={"Range": f"items=0-{limit - 1}"})
        items = r.json()
        for it in items:  # start_time (ms) -> ISO agar normalizer seragam
            it["start_time"] = datetime.fromtimestamp(it["start_time"] / 1000, tz=timezone.utc).isoformat()
        if not items:
            return Page([], cursor)
        return Page(items, str(max(int(cursor), max(i["last_updated_time"] for i in items))), len(items) >= limit)


# =============================================================== CrowdStrike Falcon
class CrowdStrike(Connector):
    """OAuth2 client-credentials; GET /alerts/queries/alerts/v2 (FQL) -> POST /alerts/entities/alerts/v2 {composite_ids}. Scope: Alerts: Read."""
    type = "crowdstrike"

    def make_client(self):
        _need(self.p, "client_id", "client_secret_env")
        c = self.new_client(self.p.get("base_url", "https://api.crowdstrike.com"))
        self.auth = OAuthClientCredentials(c, "/oauth2/token", {"client_id": self.p["client_id"], "client_secret": self.secret(self.p["client_secret_env"])})
        return c

    def fetch(self, cursor, limit):
        since = iso(self._since(cursor))
        flt = f"updated_timestamp:>'{since}'" + (f"+{self.p['fql_extra']}" if self.p.get("fql_extra") else "")
        call = lambda m, u, **kw: self.client.request(m, u, headers_fn=self.auth.headers, on_unauthorized=self.auth.refresh, **kw)  # noqa: E731
        ids = call("GET", "/alerts/queries/alerts/v2", params={"filter": flt, "sort": "updated_timestamp.asc", "limit": min(limit, 1000)}).json().get("resources", [])
        alerts: list[dict] = []
        for i in range(0, len(ids), 1000):
            alerts += call("POST", "/alerts/entities/alerts/v2", json={"composite_ids": ids[i:i + 1000]}).json().get("resources", [])
        if not alerts:
            return Page([], cursor)
        newest = max(parse_ts(a.get("updated_timestamp") or a["created_timestamp"]) for a in alerts)
        return Page(alerts, iso(max(newest, parse_ts(cursor))), len(ids) >= min(limit, 1000))


# =============================================================== SentinelOne
class SentinelOne(Connector):
    """GET /web/api/v2.1/threats, header `Authorization: ApiToken`, cursor pagination. Permission: Threats.view."""
    type = "sentinelone"

    def make_client(self):
        _need(self.p, "base_url", "token_env")
        return self.new_client(self.p["base_url"], {"Authorization": f"ApiToken {self.secret(self.p['token_env'])}"})

    def fetch(self, cursor, limit):
        field = self.p.get("time_field", "createdAt")  # 'updatedAt' bila tenant Anda mendukung filter updatedAt__gte
        params = {f"{field}__gte": iso(self._since(cursor)), "limit": min(limit, 1000), "sortBy": field, "sortOrder": "asc"}
        items: list[dict] = []
        pages = 0
        while True:
            j = self.client.request("GET", "/web/api/v2.1/threats", params=params).json()
            items += j.get("data", [])
            nxt = (j.get("pagination") or {}).get("nextCursor")
            pages += 1
            if not nxt or len(items) >= limit or pages >= int(self.p.get("max_pages", 20)):
                break
            params["cursor"] = nxt
        items = items[:limit]
        if not items:
            return Page([], cursor)
        key = lambda t: parse_ts((t.get("threatInfo") or {}).get(field) or t["threatInfo"]["createdAt"])  # noqa: E731
        return Page(items, iso(max(max(key(t) for t in items), parse_ts(cursor))), len(items) >= limit)


# =============================================================== Microsoft Defender (Graph security alerts_v2)
class Defender(Connector):
    """GET https://graph.microsoft.com/v1.0/security/alerts_v2 ($filter lastUpdateDateTime, @odata.nextLink). Permission: SecurityAlert.Read.All."""
    type = "defender"

    def make_client(self):
        _need(self.p, "tenant_id", "client_id", "client_secret_env")
        c = self.new_client("https://graph.microsoft.com")
        self.auth = OAuthClientCredentials(c, f"https://login.microsoftonline.com/{self.p['tenant_id']}/oauth2/v2.0/token", {
            "grant_type": "client_credentials", "client_id": self.p["client_id"], "client_secret": self.secret(self.p["client_secret_env"]),
            "scope": "https://graph.microsoft.com/.default"})
        return c

    def fetch(self, cursor, limit):
        # alerts_v2 tidak mendukung $orderby yang andal -> baca SEMUA halaman sebelum memajukan cursor (tanpa celah)
        url, params = "/v1.0/security/alerts_v2", {"$filter": f"lastUpdateDateTime ge {iso(self._since(cursor))}", "$top": 100}
        items: list[dict] = []
        for _ in range(int(self.p.get("max_pages", 50))):
            j = self.client.request("GET", url, params=params, headers_fn=self.auth.headers, on_unauthorized=self.auth.refresh).json()
            items += j.get("value", [])
            url, params = j.get("@odata.nextLink"), None
            if not url:
                break
        else:
            raise AdapterError("batas max_pages tercapai sebelum halaman habis; naikkan max_pages atau persempit rentang")
        if not items:
            return Page([], cursor)
        return Page(items, iso(max(max(parse_ts(a["lastUpdateDateTime"]) for a in items), parse_ts(cursor))), False)


# =============================================================== Palo Alto Cortex XDR
class CortexXDR(Connector):
    """POST /public_api/v1/alerts/get_alerts_multi_events (LEGACY menurut dokumentasi; path dapat diganti lewat `alerts_path`, mis. ke v2).
    Auth standard (Authorization=key) atau advanced (SHA-256(key+nonce+timestamp) per request). Maks 100 hasil/halaman."""
    type = "cortex_xdr"

    def make_client(self):
        _need(self.p, "base_url", "key_id", "key_env")
        return self.new_client(self.p["base_url"])

    def _headers(self) -> dict:
        key = self.secret(self.p["key_env"])
        if self.p.get("auth_type", "standard") == "advanced":
            import secrets, string
            nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
            ts = str(int(time.time() * 1000))
            return {"x-xdr-auth-id": str(self.p["key_id"]), "x-xdr-nonce": nonce, "x-xdr-timestamp": ts,
                    "Authorization": hashlib.sha256(f"{key}{nonce}{ts}".encode()).hexdigest()}
        return {"x-xdr-auth-id": str(self.p["key_id"]), "Authorization": key}

    def initial_cursor(self, lookback_hours):
        return str(int(self.now().replace(tzinfo=timezone.utc).timestamp() * 1000) - lookback_hours * 3600_000)

    def fetch(self, cursor, limit):
        path, since, items, start = self.p.get("alerts_path", "/public_api/v1/alerts/get_alerts_multi_events"), int(cursor) - self.overlap * 1000, [], 0
        while len(items) < limit:
            body = {"request_data": {"filters": [{"field": "creation_time", "operator": "gte", "value": since}], "search_from": start, "search_to": start + 100,
                                     "sort": {"field": "creation_time", "keyword": "asc"}}}
            res = (self.client.request("POST", path, json=body, headers_fn=self._headers).json().get("reply") or {}).get("alerts", [])
            items += res
            if len(res) < 100:
                break
            start += 100
        items = items[:limit]
        if not items:
            return Page([], cursor)
        ts = lambda a: int(a.get("detection_timestamp") or a.get("creation_time") or 0)  # noqa: E731
        return Page(items, str(max(int(cursor), max(ts(a) for a in items))), len(items) >= limit)


# =============================================================== Elasticsearch / OpenSearch (Wazuh indexer, Elastic Security)
class ElasticSearch(Connector):
    """POST /{index}/_search + search_after. Wazuh indexer: index=wazuh-alerts-*, time_field=timestamp, mapper=wazuh. Elastic ECS: time_field=@timestamp."""
    type = "elasticsearch"

    def make_client(self):
        _need(self.p, "base_url", "index")
        h = {}
        if self.p.get("api_key_env"):
            h["Authorization"] = f"ApiKey {self.secret(self.p['api_key_env'])}"
        c = self.new_client(self.p["base_url"], h)
        if self.p.get("username") and self.p.get("password_env"):
            c.http.auth = (self.p["username"], self.secret(self.p["password_env"]))
        return c

    def source(self):  # mapper dipilih dari param (wazuh|ecs) tetapi dedupe tetap per instans
        return f"{self.p.get('mapper', 'ecs')}:{self.name}"

    def fetch(self, cursor, limit):
        tf = self.p.get("time_field", "@timestamp")
        body = {"size": min(limit, 1000), "sort": [{tf: "asc"}, {"_id": "asc"}] if self.p.get("sort_by_id", False) else [{tf: "asc"}],
                "query": {"range": {tf: {"gte": iso(self._since(cursor))}}}}
        hits = self.client.request("POST", f"/{self.p['index']}/_search", json=body).json().get("hits", {}).get("hits", [])
        events = [{**h["_source"], "_id": h["_id"]} for h in hits]
        if not events:
            return Page([], cursor)
        newest = max(parse_ts(str(e.get(tf) or (e.get("@timestamp")))) for e in events)
        return Page(events, iso(max(newest, parse_ts(cursor))), len(events) >= min(limit, 1000))


REGISTRY = {c.type: c for c in (SplunkES, Sentinel, QRadar, CrowdStrike, SentinelOne, Defender, CortexXDR, ElasticSearch)}
