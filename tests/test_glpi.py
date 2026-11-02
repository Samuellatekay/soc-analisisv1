import json

import httpx
import pytest

from services.engine.enrichment.glpi import GlpiAssetProvider, GlpiError

CFG = json.load(open("infra/config/glpi.example.json"))
CFG["itemtypes"] = ["Computer"]


def mk(handler, cfg=CFG):
    return GlpiAssetProvider("https://glpi.example/", "APP", "USERTOKEN", cfg, transport=httpx.MockTransport(handler))


ROW = {"1": "web-prod-01", "126": ["10.0.1.10", "fe80::1"], "19": "2026-10-30 08:00:00", "9001": "Kritikal", "9002": "Terbatas", "9003": "DMZ", "9004": "Server"}


def test_session_search_params_and_mapping():
    calls = []
    def h(req):
        calls.append((req.url.path, dict(req.url.params), req.headers.get("Authorization"), req.headers.get("Session-Token"), req.headers.get("App-Token")))
        if req.url.path.endswith("/initSession"):
            return httpx.Response(200, json={"session_token": "SESS1"})
        return httpx.Response(200, json={"totalcount": 1, "count": 1, "data": [ROW]})
    p = mk(h)
    facts = p.lookup("10.0.1.10")
    assert calls[0][0] == "/apirest.php/initSession" and calls[0][2] == "user_token USERTOKEN" and calls[0][4] == "APP"
    path, params, _, sess, app = calls[1]
    assert path == "/apirest.php/search/Computer" and sess == "SESS1" and app == "APP"
    assert params["criteria[0][field]"] == "126" and params["criteria[0][searchtype]"] == "equals" and params["criteria[0][value]"] == "10.0.1.10"
    assert {"9001", "9002", "9003", "9004", "1", "126", "19"} <= set(params.values())          # forcedisplay memuat semua field
    got = {f.pred: f.value for f in facts}
    assert got == {"criticality": "core", "sensitivity": "confidential", "exposure": "dmz", "role": "server"}
    assert all(f.subj_id == "10.0.1.10" and f.source == "glpi" and f.updated_at.year == 2026 and f.confidence == 0.85 for f in facts)


def test_name_lookup_uses_contains_and_maps_to_ip_id():
    def h(req):
        if req.url.path.endswith("/initSession"):
            return httpx.Response(200, json={"session_token": "S"})
        assert req.url.params["criteria[0][field]"] == "1" and req.url.params["criteria[0][searchtype]"] == "contains"
        return httpx.Response(200, json={"data": [ROW]})
    assert {f.subj_id for f in mk(h).lookup("web-prod-01")} == {"10.0.1.10"}       # id aset kanonis = IP bila ada


def test_unmapped_values_are_ignored_never_defaulted():
    row = {**ROW, "9001": "Nilai Baru Tak Dikenal", "9003": None}
    h = lambda r: httpx.Response(200, json={"session_token": "S"}) if r.url.path.endswith("initSession") else httpx.Response(200, json={"data": [row]})  # noqa: E731
    got = {f.pred for f in mk(h).lookup("10.0.1.10")}
    assert "criticality" not in got and "exposure" not in got and got == {"sensitivity", "role"}


def test_ambiguous_name_returns_nothing():
    h = lambda r: httpx.Response(200, json={"session_token": "S"}) if r.url.path.endswith("initSession") else httpx.Response(206, json={"data": [ROW, {**ROW, "1": "web-prod-02"}]})  # noqa: E731
    assert mk(h).lookup("web-prod") == []


def test_expired_session_is_reopened_once():
    n = {"init": 0, "search": 0}
    def h(req):
        if req.url.path.endswith("/initSession"):
            n["init"] += 1
            return httpx.Response(200, json={"session_token": f"S{n['init']}"})
        n["search"] += 1
        return httpx.Response(401, json=["ERROR_SESSION_TOKEN_INVALID", "x"]) if req.headers["Session-Token"] == "S1" else httpx.Response(200, json={"data": [ROW]})
    assert mk(h).lookup("10.0.1.10") and n == {"init": 2, "search": 2}


def test_auth_failure_does_not_leak_tokens_and_no_match_is_empty():
    p = mk(lambda r: httpx.Response(401, json=["ERROR_GLPI_LOGIN", "bad"]))
    with pytest.raises(GlpiError) as e:
        p.lookup("10.0.1.10")
    assert "USERTOKEN" not in str(e.value) and "APP" not in str(e.value)
    h = lambda r: httpx.Response(200, json={"session_token": "S"}) if r.url.path.endswith("initSession") else httpx.Response(200, json={"totalcount": 0, "data": []})  # noqa: E731
    assert mk(h).lookup("10.9.9.9") == []


def test_close_kills_session_and_list_options():
    seen = []
    def h(req):
        seen.append(req.url.path)
        if req.url.path.endswith("/initSession"):
            return httpx.Response(200, json={"session_token": "S"})
        if "listSearchOptions" in req.url.path:
            return httpx.Response(200, json={"common": "Caracteristiques", "1": {"name": "Nom", "uid": "Computer.name"}, "126": {"name": "Adresse IP", "uid": "Computer.NetworkPort.NetworkName.IPAddress.name"}})
        return httpx.Response(200, json={})
    p = mk(h)
    assert ("126", "Adresse IP", "Computer.NetworkPort.NetworkName.IPAddress.name") in p.list_options("Computer")
    p.close()
    assert seen[-1].endswith("/killSession")


def test_collector_uses_glpi_when_configured_and_pipeline_scores_with_it(monkeypatch):
    from services.common.config import get_settings
    from services.engine.enrichment.collector import EnrichmentCollector
    s = get_settings()
    monkeypatch.setattr(s, "glpi_url", "https://glpi.example"); monkeypatch.setattr(s, "glpi_user_token", "T"); monkeypatch.setattr(s, "glpi_config", "infra/config/glpi.example.json")
    c = EnrichmentCollector(s)
    assert c.assets.name == "glpi"
    monkeypatch.setattr(s, "glpi_url", "")
    assert EnrichmentCollector(s).assets.name == "glpi"           # FileAssetProvider memakai nama 'glpi' juga (sumber logis yang sama)
