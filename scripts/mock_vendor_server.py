"""Server vendor TIRUAN (bentuk API CrowdStrike Falcon) untuk mencoba konektor tanpa akun vendor.
   python scripts/mock_vendor_server.py   # http://127.0.0.1:9100
Menghasilkan alert sintetis; BUKAN pengganti uji terhadap tenant vendor sungguhan."""
import json
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

NOW = datetime.now(timezone.utc).replace(microsecond=0)
ALERTS = []
for i in range(30):
    t = NOW - timedelta(minutes=30 - i)
    bad = i % 6 == 0
    ALERTS.append({"composite_id": f"demo:ind:{i}", "created_timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f000Z"), "updated_timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f000Z"),
                   "severity": 85 if bad else 30, "severity_name": "High" if bad else "Low", "name": "Credential dumping via LSASS" if bad else "Suspicious script",
                   "description": "demo", "tactic": "Credential Access" if bad else "Execution", "technique_id": "T1003" if bad else "T1059",
                   "device": {"hostname": "WEB-PROD-01" if bad else "WS-FIN-07", "local_ip": "10.0.1.10" if bad else "10.0.3.15"}, "user_name": "svc-web" if bad else "jdoe"})


class H(BaseHTTPRequestHandler):
    def _send(self, obj, code=200):
        b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n)
        u = urlparse(self.path)
        if u.path == "/oauth2/token":
            return self._send({"access_token": "mock-token", "expires_in": 1799})
        if self.headers.get("Authorization") != "Bearer mock-token":
            return self._send({"errors": ["unauthorized"]}, 401)
        if u.path == "/alerts/entities/alerts/v2":
            ids = set(json.loads(body)["composite_ids"]); return self._send({"resources": [a for a in ALERTS if a["composite_id"] in ids]})
        self._send({}, 404)

    def do_GET(self):
        u = urlparse(self.path)
        if self.headers.get("Authorization") != "Bearer mock-token":
            return self._send({"errors": ["unauthorized"]}, 401)
        if u.path == "/alerts/queries/alerts/v2":
            q = parse_qs(u.query); flt = q.get("filter", [""])[0]
            since = flt.split("'")[1] if "'" in flt else "1970-01-01T00:00:00Z"
            out = [a["composite_id"] for a in ALERTS if a["updated_timestamp"] > since][: int(q.get("limit", ["500"])[0])]
            return self._send({"resources": out})
        self._send({}, 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("mock vendor di http://127.0.0.1:9100"); HTTPServer(("127.0.0.1", 9100), H).serve_forever()
