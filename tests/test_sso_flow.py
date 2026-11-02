"""Alur SSO ujung-ke-ujung: IdP tiruan (PKCE) -> token -> API. Sisi browser (pkce.ts) diuji terpisah dengan vitest."""
import base64
import hashlib
import secrets
import sys
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mock_idp import IdP, make_server  # noqa: E402

from app.core import auth  # noqa: E402
from app.core.oidc import OidcVerifier  # noqa: E402

REDIR = "http://localhost:8000/"


@pytest.fixture(scope="module")
def idp():
    holder = IdP("http://placeholder")
    srv = make_server(holder, 0)
    holder.issuer = f"http://127.0.0.1:{srv.server_port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield holder
    srv.shutdown()


@pytest.fixture
def client(idp, monkeypatch):
    v = OidcVerifier(idp.issuer, idp.audience, role_claim="roles", role_map={"soc-admin": "admin", "soc-analyst": "analyst", "soc-viewer": "viewer"})
    monkeypatch.setattr(auth, "_verifier", v)
    monkeypatch.setenv("OIDC_CLIENT_ID", "soc-ui")
    from app.main import app
    with TestClient(app) as c:
        yield c


def pkce():
    ver = secrets.token_urlsafe(48)
    return ver, base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()


def login(idp, user, challenge, state="st1", redirect=REDIR):
    """Meniru browser: buka /approve di IdP (tanpa mengikuti redirect), ambil code dari Location."""
    q = urlencode({"response_type": "code", "client_id": "soc-ui", "redirect_uri": redirect, "state": state, "code_challenge": challenge, "code_challenge_method": "S256", "user": user})
    r = httpx.get(f"{idp.issuer}/approve?{q}", follow_redirects=False)
    assert r.status_code == 302
    loc = urlparse(r.headers["location"]); qs = parse_qs(loc.query)
    assert qs["state"] == [state]
    return qs["code"][0]


def token(idp, code, verifier, redirect=REDIR):
    return httpx.post(f"{idp.issuer}/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "client_id": "soc-ui", "code_verifier": verifier})


def test_auth_config_publishes_public_values_only(client, idp):
    j = client.get("/api/v1/auth/config").json()
    assert j["mode"] == "oidc" and j["client_id"] == "soc-ui" and j["token_endpoint"] == f"{idp.issuer}/token" and j["authorization_endpoint"].endswith("/authorize")
    assert "secret" not in str(j).lower()


def test_auth_config_token_mode_when_oidc_off(monkeypatch):
    monkeypatch.setattr(auth, "_verifier", None)
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    from app.main import app
    with TestClient(app) as c:
        assert c.get("/api/v1/auth/config").json() == {"mode": "token"}


def test_full_pkce_flow_then_rbac(client, idp):
    ver, ch = pkce()
    r = token(idp, login(idp, "analyst", ch), ver)
    assert r.status_code == 200
    tok = r.json()["access_token"]
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {tok}"}).json() == {"name": "Andi Analis", "role": "analyst", "tenant_id": "default"}
    assert client.post("/api/v1/cases", json={"title": "via sso"}, headers={"Authorization": f"Bearer {tok}"}).status_code == 201
    v2, c2 = pkce()
    viewer = token(idp, login(idp, "viewer", c2), v2).json()["access_token"]
    assert client.post("/api/v1/cases", json={"title": "tidak boleh"}, headers={"Authorization": f"Bearer {viewer}"}).status_code == 403
    assert client.get("/api/v1/audit", headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_pkce_protections_at_idp(idp):
    ver, ch = pkce()
    code = login(idp, "admin", ch)
    assert token(idp, code, "verifier-penyerang-salah").status_code == 400           # code dicuri tanpa verifier
    assert token(idp, code, ver).status_code == 400                                   # kode hangus setelah percobaan (sekali pakai)
    ver, ch = pkce(); code = login(idp, "admin", ch)
    assert token(idp, code, ver, redirect="http://evil.example/").status_code == 400  # redirect_uri tidak cocok
    ver, ch = pkce(); code = login(idp, "admin", ch)
    assert token(idp, code, ver).status_code == 200
    assert token(idp, code, ver).status_code == 400                                   # replay
    q = urlencode({"response_type": "code", "client_id": "soc-ui", "redirect_uri": REDIR, "state": "s", "code_challenge": ch, "code_challenge_method": "plain"})
    assert httpx.get(f"{idp.issuer}/authorize?{q}", follow_redirects=False).status_code == 400   # PKCE S256 wajib
    q = urlencode({"response_type": "code", "client_id": "soc-ui", "redirect_uri": "http://evil.example/", "state": "s", "code_challenge": ch, "code_challenge_method": "S256"})
    assert httpx.get(f"{idp.issuer}/authorize?{q}", follow_redirects=False).status_code == 400   # redirect tidak terdaftar


def test_expired_or_foreign_token_rejected_by_api(client, idp):
    import time, jwt
    expired = jwt.encode({"iss": idp.issuer, "aud": idp.audience, "sub": "x", "exp": int(time.time()) - 999, "roles": ["soc-admin"], "tenant_id": "default"}, idp.key, algorithm="RS256", headers={"kid": "mock-1"})
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401
    other = IdP(idp.issuer)                               # IdP lain dengan kunci berbeda tetapi kid sama
    foreign = other.issue("admin")
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {foreign}"}).status_code == 401
