"""Uji konektor dengan httpx.MockTransport. Payload mengikuti bentuk dokumentasi vendor (disusun manual, BUKAN tangkapan dari produk asli)."""
import hashlib
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from services.common.db import session_scope
from services.common.models import ConnectorState, Event
from services.engine.adapters import runner
from services.engine.adapters.base import parse_ts
from services.engine.adapters.http import AdapterError, ApiClient
from services.engine.adapters.mappings import parse_cef, parse_leef
from services.engine.adapters.vendors import REGISTRY
from services.engine.normalizer.core import normalize
from services.engine.pipeline import Pipeline

NOW = datetime(2026, 10, 31, 12, 0, 0)
SECRET = lambda name: f"secret-of-{name}"  # noqa: E731


def mk(type_, params, handler, name=None, **kw):
    sleeps = []
    c = REGISTRY[type_](name or f"t-{type_}", params, SECRET, now=lambda: NOW, transport=httpx.MockTransport(handler), sleep=sleeps.append, **kw)
    c.sleeps = sleeps
    return c


def norm(conn, raw):
    from services.common.config import get_settings
    from services.engine.normalizer.tactics import TacticResolver
    return normalize(raw, conn.source(), "default", TacticResolver(get_settings()))


# ------------------------------------------------------------------ HTTP layer
def test_http_retries_503_then_ok_and_honors_retry_after():
    calls, slept = [], []
    def h(req):
        calls.append(1)
        return httpx.Response(429, headers={"Retry-After": "3"}) if len(calls) == 1 else httpx.Response(503) if len(calls) == 2 else httpx.Response(200, json={"ok": 1})
    c = ApiClient("http://x", transport=httpx.MockTransport(h), sleep=slept.append)
    assert c.request("GET", "/a").json() == {"ok": 1} and slept[0] == 3.0 and len(calls) == 3


def test_http_error_does_not_leak_credentials():
    c = ApiClient("http://x", {"Authorization": "Bearer SUPERSECRET"}, transport=httpx.MockTransport(lambda r: httpx.Response(400, text="bad request")))
    with pytest.raises(AdapterError) as e:
        c.request("GET", "/a")
    assert "SUPERSECRET" not in str(e.value) and e.value.status == 400


def test_http_refreshes_token_once_on_401():
    seen = []
    def h(req):
        seen.append(req.headers.get("Authorization"))
        return httpx.Response(401) if req.headers.get("Authorization") == "Bearer old" else httpx.Response(200, json={})
    c = ApiClient("http://x", transport=httpx.MockTransport(h))
    c.request("GET", "/a", headers={"Authorization": "Bearer old"}, on_unauthorized=lambda: {"Authorization": "Bearer new"})
    assert seen == ["Bearer old", "Bearer new"]


# ------------------------------------------------------------------ Splunk ES
def test_splunk_es():
    rows = [{"ixt": "1793440800", "_time": "2026-10-31T09:59:00.000+00:00", "event_id": "AAA@@notable@@111", "rule_name": "Brute Force Access Behavior Detected",
             "urgency": "high", "src": "203.0.113.45", "dest": "10.0.1.10", "dest_port": "22", "user": "root",
             "annotations.mitre_attack.mitre_technique_id": ["T1110"]},
            {"ixt": "1793440860", "_time": "2026-10-31T10:00:00.000+00:00", "event_id": "BBB@@notable@@222", "rule_name": "Scan", "urgency": "low", "src": "198.51.100.77", "dest": "10.0.1.10"}]
    def h(req):
        assert req.method == "POST" and req.url.path == "/services/search/jobs/export" and req.headers["Authorization"] == "Bearer secret-of-SPLUNK_TOKEN"
        body = req.content.decode()
        assert "_index_earliest%3D" in body.replace("=", "%3D") and "index%3Dnotable" in body.replace("=", "%3D")
        return httpx.Response(200, text="\n".join(json.dumps({"preview": False, "result": r}) for r in rows) + "\n")
    c = mk("splunk_es", {"base_url": "https://splunk:8089", "token_env": "SPLUNK_TOKEN"}, h)
    pg = c.fetch(c.initial_cursor(24), 100)
    assert len(pg.events) == 2 and pg.cursor == "1793440860" and not pg.more
    ne = norm(c, pg.events[0])
    assert ne.technique_id == "T1110" and ne.attack_type == "brute_force" and ne.severity == "high" and ne.src_ip == "203.0.113.45" and ne.dst_port == 22


def test_splunk_saturated_page_without_progress_errors():
    c = mk("splunk_es", {"base_url": "https://s", "token_env": "T", "overlap_seconds": 0}, lambda r: httpx.Response(200, text=json.dumps({"result": {"ixt": "100", "event_id": "x"}}) + "\n"))
    with pytest.raises(AdapterError):
        c.fetch("100", 1)


# ------------------------------------------------------------------ Microsoft Sentinel
def test_sentinel_pagination_entities_and_token():
    inc = lambda n, ts, sev="High": {"name": n, "properties": {"title": "Suspicious sign-in", "description": "d", "severity": sev, "createdTimeUtc": ts, "lastModifiedTimeUtc": ts,
                                                              "additionalData": {"tactics": ["CredentialAccess"], "techniques": ["T1110"]}}}  # noqa: E731
    state = {"tok": 0}
    def h(req):
        if req.url.host == "login.microsoftonline.com":
            assert b"management.azure.com" in req.content and b"secret-of-SENT" in req.content
            state["tok"] += 1
            return httpx.Response(200, json={"access_token": "AZ", "expires_in": 3600})
        assert req.headers["Authorization"] == "Bearer AZ"
        if req.url.path.endswith("/entities"):
            assert req.method == "POST" and req.url.params["api-version"] == "2023-02-01"
            return httpx.Response(200, json={"entities": [{"kind": "Ip", "properties": {"address": "203.0.113.45"}}, {"kind": "Ip", "properties": {"address": "10.0.1.10"}},
                                                          {"kind": "Host", "properties": {"hostName": "web-prod-01"}}, {"kind": "Account", "properties": {"accountName": "admin"}}]})
        if "page2" in str(req.url):
            return httpx.Response(200, json={"value": [inc("i3", "2026-10-31T11:30:00Z")]})
        assert "lastModifiedTimeUtc ge" in req.url.params["$filter"] and "/incidents" in req.url.path
        return httpx.Response(200, json={"value": [inc("i1", "2026-10-31T10:00:00Z"), inc("i2", "2026-10-31T11:00:00Z")], "nextLink": "https://management.azure.com/next?page2=1"})
    c = mk("sentinel", {"tenant_id": "tid", "client_id": "cid", "client_secret_env": "SENT", "subscription_id": "s", "resource_group": "rg", "workspace": "ws"}, h)
    pg = c.fetch(c.initial_cursor(24), 50)
    assert [e["name"] for e in pg.events] == ["i1", "i2", "i3"] and pg.cursor == "2026-10-31T11:30:00Z" and state["tok"] == 1
    ne = norm(c, pg.events[0])
    assert (ne.src_ip, ne.dst_ip, ne.host, ne.username, ne.technique_id, ne.tactic) == ("203.0.113.45", "10.0.1.10", "web-prod-01", "admin", "T1110", "Credential Access")


# ------------------------------------------------------------------ QRadar
def test_qradar():
    def h(req):
        assert req.headers["SEC"] == "secret-of-QR" and req.headers["Range"] == "items=0-49" and req.headers["Version"] == "19.0"
        assert req.url.params["filter"].startswith("last_updated_time >")
        return httpx.Response(200, json=[{"id": 7, "description": "Multiple Login Failures", "severity": 8, "magnitude": 6, "offense_source": "203.0.113.45", "offense_type": 0,
                                          "start_time": 1793440800000, "last_updated_time": 1793441300000, "event_count": 321}])
    c = mk("qradar", {"base_url": "https://qr", "token_env": "QR"}, h)
    pg = c.fetch(c.initial_cursor(48), 50)
    assert pg.cursor == "1793441300000"
    ne = norm(c, pg.events[0])
    assert ne.src_ip == "203.0.113.45" and ne.count == 321 and ne.severity == "high" and ne.attack_type == "brute_force"


# ------------------------------------------------------------------ CrowdStrike
def test_crowdstrike_with_rate_limit_and_nanosecond_timestamps():
    n = {"q": 0}
    def h(req):
        if req.url.path == "/oauth2/token":
            assert b"client_secret=secret-of-CS" in req.content
            return httpx.Response(200, json={"access_token": "CST", "expires_in": 1799})
        assert req.headers["Authorization"] == "Bearer CST"
        if req.url.path == "/alerts/queries/alerts/v2":
            n["q"] += 1
            if n["q"] == 1:
                return httpx.Response(429, headers={"X-RateLimit-RetryAfter": "2"})
            assert req.url.params["sort"] == "updated_timestamp.asc" and req.url.params["filter"].startswith("updated_timestamp:>'")
            return httpx.Response(200, json={"resources": ["cid:ind:abc:1"]})
        assert req.url.path == "/alerts/entities/alerts/v2" and json.loads(req.content) == {"composite_ids": ["cid:ind:abc:1"]}
        return httpx.Response(200, json={"resources": [{"composite_id": "cid:ind:abc:1", "created_timestamp": "2026-10-31T10:00:00.123456789Z", "updated_timestamp": "2026-10-31T10:05:00.987654321Z",
                                                        "severity": 80, "severity_name": "High", "name": "Malicious PowerShell", "description": "encoded command", "cmdline": "powershell -enc AAA",
                                                        "tactic": "Execution", "technique_id": "T1059", "device": {"hostname": "WS-FIN-07", "local_ip": "10.0.3.15"}, "user_name": "jdoe", "sha256": "ab" * 32}]})
    c = mk("crowdstrike", {"client_id": "cid", "client_secret_env": "CS"}, h)
    pg = c.fetch(c.initial_cursor(48), 100)
    assert pg.cursor == "2026-10-31T10:05:00Z" and c.client.sleeps if hasattr(c.client, "sleeps") else True
    ne = norm(c, pg.events[0])
    assert (ne.dst_ip, ne.host, ne.technique_id, ne.tactic, ne.severity, ne.username) == ("10.0.3.15", "ws-fin-07", "T1059", "Execution", "high", "jdoe")


# ------------------------------------------------------------------ SentinelOne
def test_sentinelone_cursor_pagination():
    th = lambda i, ts: {"threatInfo": {"threatId": i, "threatName": "evil.exe", "classification": "Malware", "confidenceLevel": "malicious", "createdAt": ts, "filePath": "C:\\x\\evil.exe",
                                      "sha256": "cd" * 32, "mitigationStatus": "not_mitigated"}, "agentRealtimeInfo": {"agentComputerName": "WSAMZN-1"},
                       "agentDetectionInfo": {"agentIpV4": "10.0.3.15", "externalIp": "18.140.1.2"}, "indicators": [{"category": "Evasion", "description": "x https://attack.mitre.org/techniques/T1055/"}]}  # noqa: E731
    def h(req):
        assert req.headers["Authorization"] == "ApiToken secret-of-S1" and req.url.path == "/web/api/v2.1/threats" and "createdAt__gte" in req.url.params
        if req.url.params.get("cursor") == "CUR2":
            return httpx.Response(200, json={"data": [th("2", "2026-10-31T10:30:00.000000Z")], "pagination": {"nextCursor": None}})
        return httpx.Response(200, json={"data": [th("1", "2026-10-31T10:00:00.000000Z")], "pagination": {"nextCursor": "CUR2"}})
    c = mk("sentinelone", {"base_url": "https://s1.example", "token_env": "S1"}, h)
    pg = c.fetch(c.initial_cursor(48), 10)
    assert [e["threatInfo"]["threatId"] for e in pg.events] == ["1", "2"] and pg.cursor == "2026-10-31T10:30:00Z"
    ne = norm(c, pg.events[0])
    assert (ne.host, ne.dst_ip, ne.severity, ne.technique_id, ne.tactic) == ("wsamzn-1", "10.0.3.15", "high", "T1055", "Defense Evasion")


# ------------------------------------------------------------------ Defender
DEF_ALERT = {"id": "da637_1", "title": "Multiple failed logins then success", "description": "d", "severity": "high", "category": "CredentialAccess", "mitreTechniques": ["T1110"],
             "createdDateTime": "2026-10-31T10:00:00Z", "lastUpdateDateTime": "2026-10-31T10:20:00.123Z",
             "evidence": [{"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "103.108.207.58", "verdict": "malicious"},
                          {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "10.0.1.10", "verdict": "unknown"},
                          {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "danny"}},
                          {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "web-prod-01.corp"}]}


def test_defender_paginates_all_pages_and_maps_evidence():
    def h(req):
        if req.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "G", "expires_in": 3600})
        assert req.headers["Authorization"] == "Bearer G"
        if req.url.params.get("p") == "2":
            return httpx.Response(200, json={"value": [{**DEF_ALERT, "id": "da2"}]})
        return httpx.Response(200, json={"value": [DEF_ALERT], "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/alerts_v2?p=2"})
    c = mk("defender", {"tenant_id": "t", "client_id": "c", "client_secret_env": "D"}, h)
    pg = c.fetch(c.initial_cursor(48), 10)
    assert len(pg.events) == 2 and pg.cursor == "2026-10-31T10:20:00Z"
    ne = norm(c, pg.events[0])
    assert (ne.src_ip, ne.dst_ip, ne.username, ne.technique_id, ne.tactic) == ("103.108.207.58", "10.0.1.10", "danny", "T1110", "Credential Access")


def test_defender_page_cap_raises_instead_of_skipping_data():
    def h(req):
        if req.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "G"})
        return httpx.Response(200, json={"value": [DEF_ALERT], "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/alerts_v2?p=n"})
    c = mk("defender", {"tenant_id": "t", "client_id": "c", "client_secret_env": "D", "max_pages": 3}, h)
    with pytest.raises(AdapterError):
        c.fetch(c.initial_cursor(48), 10)


# ------------------------------------------------------------------ Cortex XDR
def test_cortex_standard_and_advanced_auth_and_pagination():
    seen = []
    def h(req):
        seen.append(dict(req.headers))
        body = json.loads(req.content)["request_data"]
        assert body["filters"][0] == {"field": "creation_time", "operator": "gte", "value": body["filters"][0]["value"]} and body["sort"]["keyword"] == "asc"
        if body["search_from"] == 0:
            alerts = [{"alert_id": str(i), "detection_timestamp": 1793440800000 + i, "severity": "high", "name": "Malware", "host_name": "ws1"} for i in range(100)]
        else:
            alerts = [{"alert_id": "x", "detection_timestamp": 1793441799999, "severity": "medium", "name": "Cred dump", "host_name": "ws2", "action_local_ip": "10.0.3.15",
                       "action_remote_ip": "203.0.113.45", "mitre_technique_id_and_name": ["T1003 - OS Credential Dumping"], "mitre_tactic_id_and_name": ["TA0006 - Credential Access"]}]
        return httpx.Response(200, json={"reply": {"total_count": 101, "result_count": len(alerts), "alerts": alerts}})
    c = mk("cortex_xdr", {"base_url": "https://api-x", "key_id": "88", "key_env": "CX"}, h)
    pg = c.fetch(c.initial_cursor(48), 500)
    assert len(pg.events) == 101 and pg.cursor == "1793441799999"
    assert seen[0]["authorization"] == "secret-of-CX" and seen[0]["x-xdr-auth-id"] == "88"
    ne = norm(c, pg.events[-1])
    assert (ne.technique_id, ne.tactic, ne.src_ip, ne.dst_ip) == ("T1003", "Credential Access", "203.0.113.45", "10.0.3.15")
    c2 = mk("cortex_xdr", {"base_url": "https://api-x", "key_id": "88", "key_env": "CX", "auth_type": "advanced"}, h)
    c2.fetch(c2.initial_cursor(48), 1)
    hh = seen[-1]
    assert hh["authorization"] == hashlib.sha256(f"secret-of-CX{hh['x-xdr-nonce']}{hh['x-xdr-timestamp']}".encode()).hexdigest() and len(hh["x-xdr-nonce"]) == 64


# ------------------------------------------------------------------ Elasticsearch / Wazuh indexer
def test_wazuh_indexer_via_elasticsearch_connector():
    hit = {"_id": "h1", "_source": {"id": "1793440800.1", "timestamp": "2026-10-31T10:00:00.000+0000", "rule": {"id": "5712", "level": 10, "description": "sshd: brute force trying to get access",
                                                                                                           "mitre": {"id": ["T1110"]}}, "agent": {"name": "web-prod-01", "ip": "10.0.1.10"}, "data": {"srcip": "203.0.113.45"}}}
    def h(req):
        assert req.url.path == "/wazuh-alerts-*/_search" and req.headers["authorization"].startswith("Basic ")
        return httpx.Response(200, json={"hits": {"hits": [hit]}})
    c = mk("elasticsearch", {"base_url": "https://idx:9200", "index": "wazuh-alerts-*", "time_field": "timestamp", "mapper": "wazuh", "username": "u", "password_env": "P"}, h)
    pg = c.fetch(c.initial_cursor(48), 100)
    assert pg.cursor == "2026-10-31T10:00:00Z" and c.source().startswith("wazuh:")
    ne = norm(c, pg.events[0])
    assert (ne.src_ip, ne.dst_ip, ne.technique_id, ne.severity) == ("203.0.113.45", "10.0.1.10", "T1110", "high")


# ------------------------------------------------------------------ CEF / LEEF
def test_cef_leef_and_syslog_listener():
    line = "<134>Oct 31 10:00:00 fw CEF:0|Palo Alto Networks|PAN-OS|10.1|THREAT|SSH brute force attempt|8|rt=1761904800000 src=203.0.113.45 dst=10.0.1.10 dpt=22 msg=Multiple failed login suser=root"
    d = parse_cef(line)
    assert d["vendor"] == "Palo Alto Networks" and d["ext"]["dpt"] == "22"
    ne = normalize({"line": line}, "syslog:cef", "default")
    assert ne.src_ip == "203.0.113.45" and ne.dst_port == 22 and ne.severity == "high" and ne.attack_type == "brute_force"
    assert parse_leef("LEEF:1.0|IBM|QRadar|1.0|NetworkScan|src=1.2.3.4\tdst=10.0.0.5\tsev=7")["ext"]["dst"] == "10.0.0.5"
    from services.engine.adapters.syslog_listener import Listener
    got = []
    ls = Listener(got.append)
    ls.feed(line.encode()); ls.feed(b"random non-cef line")
    assert len(got) == 1 and "CEF:0" in got[0]["line"]
    with pytest.raises(ValueError):
        parse_cef("CEF:0|only|three")


# ------------------------------------------------------------------ Runner: checkpoint semantics
def _crowdstrike_ok():
    def h(req):
        if req.url.path == "/oauth2/token":
            return httpx.Response(200, json={"access_token": "t", "expires_in": 1800})
        if req.url.path.startswith("/alerts/queries"):
            return httpx.Response(200, json={"resources": ["a", "b"]})
        return httpx.Response(200, json={"resources": [
            {"composite_id": "a", "created_timestamp": "2026-10-31T10:00:00Z", "updated_timestamp": "2026-10-31T10:00:00Z", "severity_name": "High", "name": "Malware execution", "device": {"local_ip": "10.0.3.15", "hostname": "ws1"}},
            {"composite_id": "b", "created_timestamp": "bukan-tanggal", "updated_timestamp": "2026-10-31T10:01:00Z", "name": "rusak"}]})
    return mk("crowdstrike", {"client_id": "c", "client_secret_env": "S"}, h, name="rt-cs")


def test_runner_checkpoint_advances_only_after_sink_and_counts_rejects():
    conn, cfg = _crowdstrike_ok(), {"tenant_id": "rt", "batch_size": 10}
    boom = lambda ev, src, ten: (_ for _ in ()).throw(RuntimeError("pipeline down"))  # noqa: E731
    r1 = runner.run_once(conn, cfg, boom)
    assert r1["error"] and "pipeline down" in r1["error"]
    with session_scope() as s:
        st = s.get(ConnectorState, "rt-cs")
        assert st.consecutive_failures == 1 and st.cursor == conn.initial_cursor(24) and st.last_success is None   # cursor TIDAK maju
    r2 = runner.run_once(conn, cfg, runner.inline_sink(Pipeline()))
    assert r2["error"] is None and r2["accepted"] == 1 and r2["rejected"] == 1
    with session_scope() as s:
        st = s.get(ConnectorState, "rt-cs")
        assert st.cursor == "2026-10-31T10:01:00Z" and st.consecutive_failures == 0 and st.events_total == 1 and "ditolak" in st.last_warning
        assert s.query(Event).filter_by(tenant_id="rt", source="crowdstrike:rt-cs").count() == 1
    r3 = runner.run_once(conn, cfg, runner.inline_sink(Pipeline()))   # siklus ulang: idempoten (event sama -> duplikat)
    assert r3["accepted"] == 0 and r3["duplicates"] == 1


def test_runner_disables_overlap_when_page_is_stuck():
    calls = []
    class Fake(REGISTRY["qradar"]):
        def fetch(self, cursor, limit):
            calls.append(self.overlap)
            from services.engine.adapters.base import Page
            return Page([], cursor, more=True) if self.overlap else Page([], "999", more=False)
    c = Fake("rt-stuck", {"base_url": "https://x", "token_env": "T"}, SECRET)
    res = runner.run_once(c, {"tenant_id": "rt"}, lambda e, s, t: (0, 0, []))
    assert res["error"] is None and calls[0] > 0 and calls[1] == 0 and c.overlap > 0   # overlap dipulihkan setelah siklus


def test_load_connectors_from_example_file_validates_types(tmp_path, monkeypatch):
    from services.common.config import Settings
    s = Settings()
    s.connectors_config = "infra/config/connectors.example.json"
    assert runner.load_connectors(s) == []              # semua enabled=false
    names = [c.name for c, _ in runner.load_connectors(s, only_enabled=False, secret=SECRET)]
    assert "splunk-prod" in names and len(names) == 9
    bad = tmp_path / "c.json"; bad.write_text(json.dumps({"connectors": [{"name": "x", "type": "nope", "enabled": True}]}))
    s.connectors_config = str(bad)
    with pytest.raises(ValueError):
        runner.load_connectors(s)


def test_one_broken_connector_does_not_take_down_others(tmp_path):
    from services.common.config import Settings
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"connectors": [
        {"name": "broken-cs", "type": "crowdstrike", "enabled": True, "params": {}},
        {"name": "ok-qr", "type": "qradar", "enabled": True, "params": {"base_url": "https://q", "token_env": "T"}}]}))
    s = Settings(); s.connectors_config = str(cfg)
    names = [c.name for c, _ in runner.load_connectors(s, secret=SECRET)]
    assert names == ["ok-qr"]
    with session_scope() as db:
        assert "konfigurasi tidak valid" in db.get(ConnectorState, "broken-cs").last_error
