"""Validasi JWT OIDC (Keycloak, Entra ID, Okta, dll.). MFA/SSO dilakukan di IdP; API hanya memverifikasi token.

Keamanan: algoritma di-allowlist (RS256/ES256 saja; 'none' dan HS* ditolak -> tidak ada key-confusion), iss/aud/exp wajib,
tanpa default role (klaim peran tidak dikenal => 403), tenant wajib dari klaim. JWKS di-cache; kid tak dikenal memicu refetch (dibatasi laju)."""
from __future__ import annotations

import json
import threading
import time

import httpx
import jwt

ALLOWED_ALGS = ["RS256", "ES256"]


class OidcError(Exception):
    def __init__(self, msg: str, status: int = 401):
        super().__init__(msg)
        self.status = status


class OidcVerifier:
    def __init__(self, issuer: str, audience: str, jwks_url: str = "", role_claim: str = "roles", role_map: dict | None = None,
                 tenant_claim: str = "tenant_id", transport: httpx.BaseTransport | None = None, now=time.time, leeway: int = 30):
        self.issuer, self.audience, self.jwks_url = issuer.rstrip("/"), audience, jwks_url
        self.role_claim, self.role_map, self.tenant_claim = role_claim, role_map or {}, tenant_claim
        self.http, self.now, self.leeway = httpx.Client(timeout=5.0, transport=transport), now, leeway
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched = 0.0
        self._lock = threading.Lock()

    def discovery(self) -> dict:
        if not getattr(self, "_disc", None):
            r = self.http.get(f"{self.issuer}/.well-known/openid-configuration")
            r.raise_for_status()
            self._disc = r.json()
        return self._disc

    def _jwks_url(self) -> str:
        if not self.jwks_url:
            self.jwks_url = self.discovery()["jwks_uri"]
        return self.jwks_url

    def _refresh(self, force: bool = False):
        with self._lock:
            if not force and self._keys and self.now() - self._fetched < 3600:
                return
            if force and self.now() - self._fetched < 30:   # batasi laju refetch (cegah amplifikasi oleh kid acak)
                return
            try:
                data = self.http.get(self._jwks_url()).json()
            except Exception as e:  # noqa: BLE001
                if self._keys:   # IdP sementara tak terjangkau: pakai cache lama
                    return
                raise OidcError("JWKS tidak dapat diambil", 503) from e
            self._keys = {k["kid"]: jwt.PyJWK(k) for k in data.get("keys", []) if k.get("kid") and k.get("use", "sig") == "sig"}
            self._fetched = self.now()

    def _key_for(self, kid: str | None):
        self._refresh()
        if kid not in self._keys:
            self._refresh(force=True)
        k = self._keys.get(kid or "")
        if not k:
            raise OidcError("kid tidak dikenal")
        return k.key

    def verify(self, token: str) -> dict:
        try:
            hdr = jwt.get_unverified_header(token)
            if hdr.get("alg") not in ALLOWED_ALGS:
                raise OidcError("algoritma token tidak diizinkan")
            claims = jwt.decode(token, self._key_for(hdr.get("kid")), algorithms=ALLOWED_ALGS, audience=self.audience, issuer=self.issuer,
                                leeway=self.leeway, options={"require": ["exp", "iss", "aud", "sub"]})
        except OidcError:
            raise
        except jwt.PyJWTError as e:
            raise OidcError(f"token ditolak: {type(e).__name__}") from e
        return claims

    def principal(self, token: str) -> tuple[str, str, str]:
        """(name, role, tenant). Role = tertinggi dari klaim yang terpeta; tidak ada -> 403."""
        c = self.verify(token)
        raw = c.get(self.role_claim)
        if raw is None and "." in self.role_claim:  # klaim bersarang, mis. realm_access.roles
            cur = c
            for part in self.role_claim.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            raw = cur
        vals = raw if isinstance(raw, list) else [raw] if raw else []
        rank = {"viewer": 1, "analyst": 2, "admin": 3}
        roles = [self.role_map.get(v, v) for v in vals]
        roles = [r for r in roles if r in rank]
        if not roles:
            raise OidcError("tidak ada peran SOC yang terpeta pada token", 403)
        tenant = c.get(self.tenant_claim)
        if not tenant or not isinstance(tenant, str):
            raise OidcError("klaim tenant tidak ada", 403)
        return str(c.get("preferred_username") or c.get("email") or c["sub"]), max(roles, key=rank.__getitem__), tenant
