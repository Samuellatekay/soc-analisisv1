"""Ingress & normalisasi: validasi schema -> field internal -> UTC -> event_id stabil."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from services.common.util import canon_ip, parse_time, sanitize, stable_event_id, utcnow
from services.engine.adapters.mappings import MAPPERS

ATTACK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("malware_comm", re.compile(r"\bc2\b|c&c|malware|beacon|\bdga\b|botnet|trojan|ransom", re.I)),
    ("web_attack", re.compile(r"sql ?inj|\bxss\b|traversal|web attack|\brce\b|remote code|webshell|cve-\d|exploit", re.I)),
    ("brute_force", re.compile(r"brute|failed (log[io]n|password)s?|(login|logon|authentication) fail|multiple fail|invalid user", re.I)),
    ("scanning", re.compile(r"scan|probe|nmap|portsweep|host discovery|recon", re.I)),
    ("policy_violation", re.compile(r"policy|unauthori[sz]ed|weak password|anomalous login", re.I)),
]
DEFAULT_TECHNIQUE = {"brute_force": "T1110", "scanning": "T1595", "web_attack": "T1190", "malware_comm": "T1071"}
SEV = {"info": "low", "informational": "low", "low": "low", "medium": "medium", "moderate": "medium", "high": "high", "critical": "critical"}


class ValidationError(ValueError):
    pass


@dataclass
class NormalizedEvent:
    event_id: str
    tenant_id: str
    source: str
    source_event_id: str
    event_time: datetime
    received_at: datetime
    severity: str
    attack_type: str
    signature: str
    message: str
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    host: str | None
    username: str | None
    entities: dict
    technique_id: str | None
    tactic: str | None
    triplet_key: str
    count: int
    evasion: bool
    payload: dict = field(default_factory=dict)


def _severity(v) -> str:
    if v is None:
        return "low"
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
        n = float(v)  # skala 0-15 (Wazuh) atau 0-10
        return "critical" if n >= 13 else "high" if n >= 10 else "medium" if n >= 6 else "low"
    return SEV.get(str(v).strip().lower(), "low")


def classify(attack_type: str | None, signature: str, message: str) -> str:
    if attack_type and attack_type in {k for k, _ in ATTACK_PATTERNS}:
        return attack_type
    text = f"{signature} {message}"
    for name, pat in ATTACK_PATTERNS:
        if pat.search(text):
            return name
    return "other"


def normalize(raw: dict, source: str, tenant_id: str, tactic_lookup: Callable[[str], str | None] | None = None,
              max_bytes: int = 262144) -> NormalizedEvent:
    if len(json.dumps(raw, default=str)) > max_bytes:
        raise ValidationError("payload melebihi batas ukuran")
    mapper = MAPPERS.get(source.split(":")[0].lower(), MAPPERS["generic"])
    m = mapper(raw)
    if not m.get("source_event_id"):
        raise ValidationError("source_event_id wajib ada (dibutuhkan untuk deduplikasi)")
    try:
        et = parse_time(m["event_time"])
    except Exception as e:  # noqa: BLE001
        raise ValidationError(f"event_time tidak valid: {e}") from e
    src, dst = canon_ip(m.get("src_ip")), canon_ip(m.get("dst_ip"))
    if m.get("src_ip") and not src:
        raise ValidationError("src_ip tidak valid")
    atype = classify(m.get("attack_type"), m.get("signature") or "", m.get("message") or "")
    tech = (m.get("technique_id") or DEFAULT_TECHNIQUE.get(atype) or None)
    tech = tech.upper() if tech else None
    tactic = tactic_lookup(tech) if (tech and tactic_lookup) else None
    tactic = tactic or m.get("tactic")
    port = None
    try:
        port = int(m["dst_port"]) if m.get("dst_port") not in (None, "") else None
    except (TypeError, ValueError):
        pass
    host = (m.get("host") or None)
    entities = {k: v for k, v in {
        "src_ip": src, "dst_ip": dst, "host": host.lower() if host else None, "user": m.get("username"),
        "domain": (m.get("domain") or "").lower() or None, "hash": (m.get("hash") or "").lower() or None,
    }.items() if v}
    try:
        cnt = max(1, int(m.get("count") or 1))
    except (TypeError, ValueError):
        cnt = 1
    return NormalizedEvent(
        event_id=stable_event_id(tenant_id, source, str(m["source_event_id"])), tenant_id=tenant_id, source=source,
        source_event_id=str(m["source_event_id"]), event_time=et, received_at=utcnow(), severity=_severity(m.get("severity")),
        attack_type=atype, signature=str(m.get("signature") or "")[:256], message=str(m.get("message") or "")[:2000],
        src_ip=src, dst_ip=dst, dst_port=port, protocol=(m.get("protocol") or None), host=entities.get("host"),
        username=m.get("username"), entities=entities, technique_id=tech, tactic=tactic,
        triplet_key=f"{src or '-'}|{dst or '-'}|{atype}", count=cnt, evasion=bool(m.get("evasion", False)),
        payload=sanitize(raw),
    )
