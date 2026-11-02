"""Klien HTTP untuk konektor: timeout, retry+backoff (429/5xx/jaringan), Retry-After, refresh token sekali pada 401.
Body error dipotong dan TIDAK menyertakan header (agar token tidak bocor ke log)."""
from __future__ import annotations

import time
from typing import Callable

import httpx


class AdapterError(RuntimeError):
    def __init__(self, msg: str, status: int | None = None):
        super().__init__(msg)
        self.status = status


class ApiClient:
    def __init__(self, base_url: str = "", headers: dict | None = None, verify: bool = True, timeout: float = 30.0,
                 max_retries: int = 4, transport: httpx.BaseTransport | None = None, sleep: Callable[[float], None] = time.sleep):
        self.base_url = base_url.rstrip("/")
        self.http = httpx.Client(headers=headers or {}, verify=verify, timeout=timeout, transport=transport)
        self.max_retries, self.sleep = max_retries, sleep

    @staticmethod
    def _retry_after(r: httpx.Response, attempt: int) -> float:
        for h in ("Retry-After", "X-RateLimit-RetryAfter"):  # CrowdStrike: epoch detik; lainnya: detik relatif
            v = r.headers.get(h)
            if v:
                try:
                    x = float(v)
                    return max(0.0, x - time.time()) if x > 1e9 else x
                except ValueError:
                    pass
        return min(60.0, 2.0 ** attempt)

    def request(self, method: str, url: str, *, params=None, json=None, data=None, headers=None,
                headers_fn: Callable[[], dict] | None = None, on_unauthorized: Callable[[], dict | None] | None = None) -> httpx.Response:
        full = url if url.startswith("http") else f"{self.base_url}{url}"
        refreshed = False
        extra = dict(headers or {})
        for attempt in range(self.max_retries + 1):
            hdrs = {**extra, **(headers_fn() if headers_fn else {})}
            try:
                r = self.http.request(method, full, params=params, json=json, data=data, headers=hdrs)
            except httpx.TransportError as e:
                if attempt >= self.max_retries:
                    raise AdapterError(f"jaringan: {type(e).__name__}") from e
                self.sleep(min(60.0, 2.0 ** attempt))
                continue
            if r.status_code == 401 and on_unauthorized and not refreshed:
                refreshed = True
                new = on_unauthorized()
                if new:
                    extra.update(new)
                continue
            if r.status_code in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                self.sleep(self._retry_after(r, attempt))
                continue
            if r.status_code >= 400:
                raise AdapterError(f"HTTP {r.status_code} {method} {full.split('?')[0]}: {r.text[:200]}", r.status_code)
            return r
        raise AdapterError("retry habis")

    def close(self):
        self.http.close()


class OAuthClientCredentials:
    """OAuth2 client-credentials dengan cache token (Azure AD, CrowdStrike)."""
    def __init__(self, client: ApiClient, token_url: str, data: dict, now: Callable[[], float] = time.time):
        self.client, self.token_url, self.data, self.now = client, token_url, data, now
        self._tok: str | None = None
        self._exp = 0.0

    def token(self, force: bool = False) -> str:
        if force or not self._tok or self.now() >= self._exp - 60:
            r = self.client.request("POST", self.token_url, data=self.data)
            j = r.json()
            if "access_token" not in j:
                raise AdapterError("respons token tanpa access_token")
            self._tok, self._exp = j["access_token"], self.now() + float(j.get("expires_in", 1800))
        return self._tok

    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token()}"}

    def refresh(self) -> dict:
        return {"Authorization": f"Bearer {self.token(force=True)}"}
