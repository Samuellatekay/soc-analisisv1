import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.core import auth
from app.core.oidc import OidcError, OidcVerifier

ISS, AUD = "https://idp.example/realms/soc", "soc-api"


def keypair(kid):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key())); jwk.update(kid=kid, use="sig", alg="RS256")
    return priv, jwk


PRIV, JWK = keypair("k1")
OTHER_PRIV, _ = keypair("evil")


def tok(priv=PRIV, kid="k1", alg="RS256", **over):
    c = {"iss": ISS, "aud": AUD, "sub": "u1", "preferred_username": "andi", "exp": int(time.time()) + 300, "roles": ["soc-analyst"], "tenant_id": "default", **over}
    return jwt.encode({k: v for k, v in c.items() if v is not None}, priv, algorithm=alg, headers={"kid": kid})


def verifier(keys=None, hits=None):
    keys = keys if keys is not None else [JWK]
    def h(req):
        if hits is not None:
            hits.append(str(req.url))
        return httpx.Response(200, json={"keys": keys})
    return OidcVerifier(ISS, AUD, f"{ISS}/jwks", "roles", {"soc-admin": "admin", "soc-analyst": "analyst", "soc-viewer": "viewer"}, transport=httpx.MockTransport(h))


def test_valid_token_maps_role_and_tenant():
    assert verifier().principal(tok()) == ("andi", "analyst", "default")
    assert verifier().principal(tok(roles=["soc-viewer", "soc-admin"]))[1] == "admin"   # peran tertinggi


@pytest.mark.parametrize("over,why", [
    ({"exp": int(time.time()) - 600}, "kedaluwarsa"), ({"aud": "other"}, "audience salah"), ({"iss": "https://evil"}, "issuer salah"), ({"sub": None}, "tanpa sub")])
def test_invalid_claims_rejected(over, why):
    with pytest.raises(OidcError) as e:
        verifier().principal(tok(**over))
    assert e.value.status == 401, why


def test_wrong_signing_key_alg_none_and_hs256_confusion_rejected():
    v = verifier()
    with pytest.raises(OidcError):
        v.principal(tok(priv=OTHER_PRIV))                                   # ditandatangani kunci lain dengan kid sah
    with pytest.raises(OidcError):
        v.principal(jwt.encode({"iss": ISS, "aud": AUD, "sub": "x", "exp": int(time.time()) + 99}, key=None, algorithm="none", headers={"kid": "k1"}))
    import base64, hashlib, hmac
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pem = PRIV.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    signing = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode()) + "." + b64(json.dumps(
        {"iss": ISS, "aud": AUD, "sub": "x", "exp": int(time.time()) + 99, "roles": ["soc-admin"], "tenant_id": "default"}).encode())
    forged = signing + "." + b64(hmac.new(pem, signing.encode(), hashlib.sha256).digest())   # dirakit manual: HMAC dengan kunci publik sebagai secret
    with pytest.raises(OidcError):
        v.principal(forged)                                                 # serangan key-confusion


def test_no_default_role_and_tenant_required():
    with pytest.raises(OidcError) as e:
        verifier().principal(tok(roles=["random-group"]))
    assert e.value.status == 403
    with pytest.raises(OidcError) as e:
        verifier().principal(tok(tenant_id=None))
    assert e.value.status == 403


def test_nested_role_claim_keycloak_style():
    v = verifier(); v.role_claim = "realm_access.roles"
    assert v.principal(tok(realm_access={"roles": ["soc-viewer"]}))[1] == "viewer"


def test_key_rotation_refetch_is_rate_limited():
    hits = []
    _, jwk2 = keypair("k2"); priv2, jwk2 = keypair("k2")
    v = verifier([JWK], hits)
    v.principal(tok())
    assert len(hits) == 1
    v._keys = {}; v._fetched = 0                                            # simulasikan cache kosong lalu rotasi kunci
    v.http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"keys": [JWK, jwk2]})))
    assert v.principal(tok(priv=priv2, kid="k2"))[0] == "andi"              # kid baru -> refetch -> lolos
    spam = [tok(kid=f"random{i}") for i in range(5)]
    calls = []
    v.http = httpx.Client(transport=httpx.MockTransport(lambda r: (calls.append(1), httpx.Response(200, json={"keys": [JWK]}))[1]))
    for t in spam:
        with pytest.raises(OidcError):
            v.principal(t)
    assert len(calls) <= 1                                                  # kid acak tidak menjadi amplifikasi ke IdP


def test_api_with_oidc_enabled_blocks_static_tokens(monkeypatch):
    from app.main import app
    v = verifier()
    monkeypatch.setattr(auth, "_verifier", v)
    with TestClient(app) as c:
        assert c.get("/api/v1/me", headers={"Authorization": f"Bearer {tok()}"}).json() == {"name": "andi", "role": "analyst", "tenant_id": "default"}
        assert c.get("/api/v1/me", headers={"Authorization": "Bearer t-admin"}).status_code == 401      # token statis mati saat OIDC aktif
        assert c.get("/api/v1/me", headers={"Authorization": f"Bearer {tok(roles=['x'])}"}).status_code == 403
        assert c.post("/api/v1/cases", json={"title": "abc"}, headers={"Authorization": f"Bearer {tok(roles=['soc-viewer'])}"}).status_code == 403
        monkeypatch.setenv("ALLOW_STATIC_TOKENS", "true")
        assert c.get("/api/v1/me", headers={"Authorization": "Bearer t-admin"}).status_code == 200
