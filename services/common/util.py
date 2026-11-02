from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from datetime import datetime, timezone

_NS = uuid.UUID("6f1c3b3e-5b7a-4a41-9c1e-0d4f6f7a9b10")
_SECRET_RE = re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)(\"?\s*[:=]\s*\"?)([^\s\",;}{]+)")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # disimpan naive-UTC


def to_utc_naive(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def parse_time(v) -> datetime:
    """Parse ISO8601 / epoch ke naive UTC. Raise ValueError bila tidak valid."""
    if isinstance(v, datetime):
        return to_utc_naive(v)
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(float(v) / (1000 if v > 1e11 else 1), tz=timezone.utc).replace(tzinfo=None)
    if isinstance(v, str):
        s = v.strip().replace("Z", "+00:00")
        s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)  # +0700 -> +07:00 (Wazuh)
        return to_utc_naive(datetime.fromisoformat(s))
    raise ValueError(f"waktu tidak valid: {v!r}")


def stable_event_id(tenant_id: str, source: str, source_event_id: str) -> str:
    """event_id stabil/idempoten dari kunci dedupe tenant+source+source_event_id."""
    return str(uuid.uuid5(_NS, f"{tenant_id}|{source}|{source_event_id}"))


def canon_ip(v: str | None) -> str | None:
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError:
        return None


_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]


def is_private_ip(v: str | None) -> bool:
    """Internal = RFC1918/loopback/link-local/ULA. Sengaja TIDAK memakai ip.is_private karena itu juga
    menandai rentang dokumentasi/reserved (mis. 203.0.113.0/24) sebagai private."""
    try:
        ip = ipaddress.ip_address(v)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return False
    return any(ip in n for n in _INTERNAL if n.version == ip.version)


def sanitize(obj, depth: int = 0):
    """Masking credential di payload sebelum disimpan/ditampilkan."""
    if depth > 8:
        return "[truncated]"
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if re.search(r"(?i)pass|secret|token|api[_-]?key|authorization|cookie", str(k)):
                out[k] = "[REDACTED]"
            else:
                out[k] = sanitize(v, depth + 1)
        return out
    if isinstance(obj, list):
        return [sanitize(x, depth + 1) for x in obj[:200]]
    if isinstance(obj, str):
        return _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", obj)[:4000]
    return obj


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
