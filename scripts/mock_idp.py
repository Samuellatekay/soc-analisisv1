"""IdP OIDC TIRUAN untuk development (Authorization Code + PKCE, JWT RS256, JWKS, discovery). BUKAN untuk produksi: tanpa password/MFA.
  python scripts/mock_idp.py            # http://127.0.0.1:9200
  # lalu jalankan API dengan:
  OIDC_ISSUER=http://127.0.0.1:9200 OIDC_AUDIENCE=soc-api OIDC_CLIENT_ID=soc-ui OIDC_ROLE_MAP='{"soc-admin":"admin","soc-analyst":"analyst","soc-viewer":"viewer"}' python run_dev.py
Daftarkan redirect URI http://localhost:8000/ (atau http://127.0.0.1:8000/)."""
import base64
import hashlib
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

USERS = {"admin": ("Admin SOC", "soc-admin"), "analyst": ("Andi Analis", "soc-analyst"), "viewer": ("Vina Viewer", "soc-viewer")}


class IdP:
    def __init__(self, issuer: str, audience="soc-api", client_id="soc-ui", redirect_uris=("http://localhost:8000/", "http://127.0.0.1:8000/", "http://localhost:5173/"), tenant="default"):
        self.issuer, self.audience, self.client_id, self.redirect_uris, self.tenant = issuer, audience, client_id, set(redirect_uris), tenant
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key())); jwk.update(kid="mock-1", use="sig", alg="RS256")
        self.jwks = {"keys": [jwk]}
        self.codes: dict[str, dict] = {}

    def issue(self, user: str, ttl=900) -> str:
        name, role = USERS[user]
        now = int(time.time())
        return jwt.encode({"iss": self.issuer, "aud": self.audience, "sub": f"mock-{user}", "preferred_username": name, "roles": [role],
                           "tenant_id": self.tenant, "iat": now, "exp": now + ttl}, self.key, algorithm="RS256", headers={"kid": "mock-1"})


def make_server(idp: IdP, port: int = 0) -> ThreadingHTTPServer:
    class H(BaseHTTPRequestHandler):
        def _cors(self):
            self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def _json(self, obj, code=200):
            b = json.dumps(obj).encode(); self.send_response(code); self._cors(); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def _html(self, html):
            b = html.encode(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_OPTIONS(self):
            self.send_response(204); self._cors(); self.send_header("Access-Control-Allow-Methods", "POST, GET"); self.end_headers()

        def do_GET(self):
            u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/.well-known/openid-configuration":
                return self._json({"issuer": idp.issuer, "authorization_endpoint": f"{idp.issuer}/authorize", "token_endpoint": f"{idp.issuer}/token", "jwks_uri": f"{idp.issuer}/jwks",
                                   "end_session_endpoint": f"{idp.issuer}/logout", "code_challenge_methods_supported": ["S256"]})
            if u.path == "/jwks":
                return self._json(idp.jwks)
            if u.path == "/logout":
                self.send_response(302); self.send_header("Location", q.get("post_logout_redirect_uri", "/")); self.end_headers(); return
            if u.path == "/authorize":
                if q.get("client_id") != idp.client_id or q.get("redirect_uri") not in idp.redirect_uris or q.get("response_type") != "code":
                    return self._json({"error": "invalid_request"}, 400)
                if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
                    return self._json({"error": "invalid_request", "error_description": "PKCE S256 wajib"}, 400)
                links = "".join(f'<li><a href="/approve?{urlencode({**q, "user": k})}">{n} ({r})</a></li>' for k, (n, r) in USERS.items())
                return self._html(f"<h2>Mock IdP (dev)</h2><p>Masuk sebagai:</p><ul>{links}</ul><p><a href=\"{q['redirect_uri']}?{urlencode({'error': 'access_denied', 'state': q.get('state', '')})}\">Batal</a></p>")
            if u.path == "/approve":
                if q.get("redirect_uri") not in idp.redirect_uris or q.get("user") not in USERS or q.get("client_id") != idp.client_id:
                    return self._json({"error": "invalid_request"}, 400)
                code = secrets.token_urlsafe(24)
                idp.codes[code] = {"challenge": q["code_challenge"], "redirect_uri": q["redirect_uri"], "user": q["user"], "exp": time.time() + 60}
                self.send_response(302); self.send_header("Location", f"{q['redirect_uri']}?{urlencode({'code': code, 'state': q.get('state', '')})}"); self.end_headers(); return
            self._json({}, 404)

        def do_POST(self):
            if urlparse(self.path).path != "/token":
                return self._json({}, 404)
            f = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()).items()}
            c = idp.codes.pop(f.get("code", ""), None)    # pop => kode sekali pakai
            if f.get("grant_type") != "authorization_code" or not c or c["exp"] < time.time():
                return self._json({"error": "invalid_grant"}, 400)
            if f.get("client_id") != idp.client_id or f.get("redirect_uri") != c["redirect_uri"]:
                return self._json({"error": "invalid_grant", "error_description": "client/redirect tidak cocok"}, 400)
            ver = base64.urlsafe_b64encode(hashlib.sha256(f.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
            if not secrets.compare_digest(ver, c["challenge"]):
                return self._json({"error": "invalid_grant", "error_description": "PKCE gagal"}, 400)
            self._json({"access_token": idp.issue(c["user"]), "token_type": "Bearer", "expires_in": 900})

        def log_message(self, *a):
            pass
    return ThreadingHTTPServer(("127.0.0.1", port), H)


if __name__ == "__main__":
    idp = IdP("http://127.0.0.1:9200")
    srv = make_server(idp, 9200)
    print("mock IdP di http://127.0.0.1:9200 (dev saja)"); srv.serve_forever()
