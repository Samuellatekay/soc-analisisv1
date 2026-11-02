"""Autentikasi token statis + RBAC (Admin/Analyst/Viewer) + tenant dari token.
Untuk enterprise: ganti `get_principal` dengan validasi JWT OIDC dari IdP (SSO + MFA); kontrak Principal tetap sama."""
from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from services.common.config import get_settings
from services.common.db import get_session
from services.common.models import AuditLog

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass
class Principal:
    name: str
    role: str
    tenant_id: str


def _tokens() -> dict[str, Principal]:
    out = {}
    for part in filter(None, (get_settings().api_tokens or "").split(",")):
        tok, role, tenant = (part.split(":") + ["default"])[:3] if part.count(":") >= 2 else (*part.split(":"), "default")[:3]
        if role in ROLES:
            out[tok] = Principal(name=f"{role}@{tenant}", role=role, tenant_id=tenant)
    return out


_verifier = None


def get_verifier():
    """Dibuat dari env: OIDC_ISSUER, OIDC_AUDIENCE, [OIDC_JWKS_URL], [OIDC_ROLE_CLAIM], [OIDC_ROLE_MAP json], [OIDC_TENANT_CLAIM]."""
    global _verifier
    import json
    import os
    if _verifier is None and os.getenv("OIDC_ISSUER"):
        from .oidc import OidcVerifier
        _verifier = OidcVerifier(os.environ["OIDC_ISSUER"], os.getenv("OIDC_AUDIENCE", ""), os.getenv("OIDC_JWKS_URL", ""),
                                 os.getenv("OIDC_ROLE_CLAIM", "roles"), json.loads(os.getenv("OIDC_ROLE_MAP", "{}")), os.getenv("OIDC_TENANT_CLAIM", "tenant_id"))
    return _verifier


def get_principal(authorization: str = Header(default="")) -> Principal:
    tok = authorization.removeprefix("Bearer ").strip()
    v = get_verifier()
    if v is not None:   # OIDC aktif: token statis dinonaktifkan kecuali ALLOW_STATIC_TOKENS=true (mis. akun layanan)
        from .oidc import OidcError
        try:
            name, role, tenant = v.principal(tok)
            return Principal(name=name, role=role, tenant_id=tenant)
        except OidcError as e:
            import os
            if os.getenv("ALLOW_STATIC_TOKENS", "false").lower() != "true" or e.status != 401:
                raise HTTPException(e.status, str(e))
    for known, p in _tokens().items():
        if tok and hmac.compare_digest(tok, known):
            return p
    raise HTTPException(401, "token tidak valid")


def require(role: str):
    def dep(p: Principal = Depends(get_principal)) -> Principal:
        if ROLES[p.role] < ROLES[role]:
            raise HTTPException(403, f"butuh role {role}")
        return p
    return dep


def ingest_tenant(x_ingest_key: str = Header(default="")) -> str:
    """INGEST_API_KEY='key1:tenantA,key2:tenantB' atau 'key' (tenant default)."""
    for part in filter(None, (get_settings().ingest_key or "").split(",")):
        key, _, tenant = part.partition(":")
        if x_ingest_key and hmac.compare_digest(x_ingest_key, key):
            return tenant or "default"
    raise HTTPException(401, "ingest key tidak valid")


def audit(db: Session, p: Principal, action: str, target: str = "", detail: dict | None = None):
    db.add(AuditLog(tenant_id=p.tenant_id, actor=p.name, role=p.role, action=action, target=target, detail=detail or {}))
