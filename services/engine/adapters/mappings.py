"""Pemetaan field per produk -> dict antara. Satu fungsi per produk/format (bukan konektor universal).

Status: `generic`, `wazuh`, dan `ecs` tersedia. Splunk ES, Sentinel, QRadar, CrowdStrike, SentinelOne,
Defender, Cortex XDR adalah target integrasi: tambahkan fungsi map_* + uji dengan payload representatif.
"""
from __future__ import annotations

import re
from typing import Callable

from services.common.util import canon_ip, is_private_ip

MAPPING_VERSION = "map-v2"


def _g(d: dict, path: str, default=None):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def map_generic(raw: dict) -> dict:
    return {
        "source_event_id": str(raw.get("source_event_id") or raw.get("id") or ""),
        "event_time": raw.get("event_time") or raw.get("timestamp"),
        "severity": raw.get("severity"), "signature": raw.get("signature") or raw.get("rule") or "",
        "message": raw.get("message") or "", "src_ip": raw.get("src_ip"), "dst_ip": raw.get("dst_ip"),
        "dst_port": raw.get("dst_port"), "protocol": raw.get("protocol"), "host": raw.get("host"),
        "username": raw.get("user") or raw.get("username"), "attack_type": raw.get("attack_type"),
        "technique_id": raw.get("technique_id"), "domain": raw.get("domain"), "hash": raw.get("hash"),
        "count": raw.get("count"), "evasion": bool(raw.get("evasion", False)),
    }


def map_wazuh(raw: dict) -> dict:
    tech = _g(raw, "rule.mitre.id")
    return {
        "source_event_id": str(raw.get("id") or ""),
        "event_time": raw.get("timestamp"), "severity": _g(raw, "rule.level"),
        "signature": f"wazuh:{_g(raw, 'rule.id', '')}", "message": _g(raw, "rule.description", "") or raw.get("full_log", ""),
        "src_ip": _g(raw, "data.srcip"), "dst_ip": _g(raw, "data.dstip") or _g(raw, "agent.ip"),
        "dst_port": _g(raw, "data.dstport"), "protocol": _g(raw, "data.protocol"),
        "host": _g(raw, "agent.name"), "username": _g(raw, "data.dstuser") or _g(raw, "data.srcuser"),
        "technique_id": (tech[0] if isinstance(tech, list) and tech else tech),
        "count": _g(raw, "data.count"),
    }


def map_ecs(raw: dict) -> dict:
    return {
        "source_event_id": str(_g(raw, "event.id") or raw.get("_id") or ""),
        "event_time": raw.get("@timestamp"), "severity": _g(raw, "event.severity"),
        "signature": _g(raw, "rule.name", "") or "", "message": raw.get("message", ""),
        "src_ip": _g(raw, "source.ip"), "dst_ip": _g(raw, "destination.ip"), "dst_port": _g(raw, "destination.port"),
        "protocol": _g(raw, "network.transport"), "host": _g(raw, "host.name"), "username": _g(raw, "user.name"),
        "technique_id": _g(raw, "threat.technique.id"), "domain": _g(raw, "dns.question.name"),
        "hash": _g(raw, "file.hash.sha256"),
    }



TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
           "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
_TACTIC_KEY = {t.lower().replace(" ", ""): t for t in TACTICS}
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SEV_WORD = {"informational": "low", "info": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical",
             "malicious": "high", "suspicious": "medium"}


def tactic_name(v) -> str | None:
    """'CredentialAccess' / 'credential-access' / 'TA0006 - Credential Access' / 'Credential Access' -> nama kanonis."""
    if not v:
        return None
    v = re.sub(r"^TA\d{4}\s*-\s*", "", str(v))
    return _TACTIC_KEY.get(re.sub(r"[^a-z]", "", v.lower()))


def first_technique(*vals) -> str | None:
    for v in vals:
        for x in (v if isinstance(v, list) else [v]):
            m = _TECH.search(str(x or ""))
            if m:
                return m.group(0)
    return None


def _first_tactic(v) -> str | None:
    for x in (v if isinstance(v, list) else [v]):
        t = tactic_name(x)
        if t:
            return t
    return None


def _sev(v) -> str | None:
    return _SEV_WORD.get(str(v).strip().lower()) if v is not None else None


def _pick_ips(ips: list[str]) -> tuple[str | None, str | None]:
    """(eksternal pertama, internal pertama) dari daftar IP valid."""
    ips = [i for i in (canon_ip(x) for x in ips) if i]
    return next((i for i in ips if not is_private_ip(i)), None), next((i for i in ips if is_private_ip(i)), None)


def map_splunk_es(raw: dict) -> dict:
    mitre = raw.get("annotations.mitre_attack.mitre_technique_id") or _g(raw, "annotations.mitre_attack.mitre_technique_id")
    return {
        "source_event_id": str(raw.get("event_id") or raw.get("_cd") or ""), "event_time": raw.get("_time"),
        "severity": raw.get("severity") or raw.get("urgency"), "signature": raw.get("rule_name") or raw.get("search_name") or "",
        "message": raw.get("rule_title") or raw.get("orig_raw") or raw.get("signature") or "",
        "src_ip": raw.get("src"), "dst_ip": raw.get("dest"), "dst_port": raw.get("dest_port"), "protocol": raw.get("transport"),
        "username": raw.get("user"), "technique_id": first_technique(mitre), "tactic": _first_tactic(raw.get("security_domain")),
    }


def map_qradar(raw: dict) -> dict:
    src = canon_ip(raw.get("offense_source"))
    return {
        "source_event_id": str(raw.get("id") or ""), "event_time": raw.get("start_time"),
        "severity": "critical" if (raw.get("magnitude") or 0) >= 9 else "high" if (raw.get("severity") or 0) >= 7 else "medium" if (raw.get("severity") or 0) >= 4 else "low",
        "signature": f"qradar-offense-{raw.get('id')}", "message": raw.get("description") or "",
        "src_ip": src, "username": None if src else raw.get("offense_source"), "count": raw.get("event_count"),
    }


def map_crowdstrike(raw: dict) -> dict:
    d = raw.get("device") or {}
    return {
        "source_event_id": str(raw.get("composite_id") or ""), "event_time": raw.get("created_timestamp") or raw.get("timestamp"),
        "severity": _sev(raw.get("severity_name")) or ("critical" if (raw.get("severity") or 0) >= 90 else "high" if (raw.get("severity") or 0) >= 70 else "medium" if (raw.get("severity") or 0) >= 40 else "low"),
        "signature": raw.get("name") or raw.get("display_name") or "", "message": " | ".join(x for x in (raw.get("description"), raw.get("cmdline"), raw.get("filename")) if x),
        "dst_ip": d.get("local_ip"), "host": d.get("hostname"), "username": raw.get("user_name"),
        "technique_id": first_technique(raw.get("technique_id"), raw.get("technique")), "tactic": tactic_name(raw.get("tactic")),
        "hash": raw.get("sha256") or raw.get("md5"),
    }


def map_sentinelone(raw: dict) -> dict:
    ti, ar, ad = raw.get("threatInfo") or {}, raw.get("agentRealtimeInfo") or {}, raw.get("agentDetectionInfo") or {}
    ip4 = ad.get("agentIpV4") or ar.get("agentIpV4")
    return {
        "source_event_id": str(ti.get("threatId") or raw.get("id") or ""), "event_time": ti.get("createdAt"),
        "severity": _sev(ti.get("confidenceLevel")) or "medium", "signature": f"{ti.get('classification', '')}: {ti.get('threatName', '')}".strip(": "),
        "message": f"{ti.get('filePath', '')} (mitigation: {ti.get('mitigationStatus', '')})", "dst_ip": ip4,
        "host": ar.get("agentComputerName"), "username": ti.get("processUser"), "hash": ti.get("sha256") or ti.get("sha1"),
        "technique_id": first_technique(str(raw.get("indicators") or "")),
    }


def map_defender(raw: dict) -> dict:
    ips, dev, user, h, dom = [], None, None, None, None
    for e in raw.get("evidence") or []:
        t = str(e.get("@odata.type", "")).rsplit(".", 1)[-1]
        if t == "ipEvidence" and e.get("ipAddress"):
            ips.append((0 if e.get("verdict") in ("malicious", "suspicious") else 1, e["ipAddress"]))
        elif t == "deviceEvidence" and not dev:
            dev = e.get("deviceDnsName") or e.get("mdeDeviceId")
        elif t == "userEvidence" and not user:
            user = (e.get("userAccount") or {}).get("accountName") or (e.get("userAccount") or {}).get("userPrincipalName")
        elif t == "fileEvidence" and not h:
            h = (e.get("fileDetails") or {}).get("sha256")
        elif t in ("urlEvidence", "dnsEvidence") and not dom:
            dom = e.get("domainName") or re.sub(r"^https?://", "", str(e.get("url") or "")).split("/")[0] or None
    ext, internal = _pick_ips([ip for _, ip in sorted(ips)])
    return {
        "source_event_id": str(raw.get("id") or ""), "event_time": raw.get("createdDateTime"), "severity": _sev(raw.get("severity")),
        "signature": raw.get("title") or "", "message": raw.get("description") or "", "src_ip": ext, "dst_ip": internal,
        "host": dev, "username": user, "hash": h, "domain": dom, "technique_id": first_technique(raw.get("mitreTechniques")),
        "tactic": tactic_name(raw.get("category")),
    }


def map_sentinel(raw: dict) -> dict:
    p = raw.get("properties") or {}
    ad = p.get("additionalData") or {}
    ents = raw.get("_entities") or []
    ips = [(e.get("properties") or {}).get("address") for e in ents if e.get("kind") == "Ip"]
    ext, internal = _pick_ips([i for i in ips if i])
    pick = lambda kind, key: next(((e.get("properties") or {}).get(key) for e in ents if e.get("kind") == kind and (e.get("properties") or {}).get(key)), None)  # noqa: E731
    return {
        "source_event_id": str(raw.get("name") or ""), "event_time": p.get("createdTimeUtc"), "severity": _sev(p.get("severity")),
        "signature": p.get("title") or "", "message": p.get("description") or "", "src_ip": ext, "dst_ip": internal,
        "host": pick("Host", "hostName"), "username": pick("Account", "accountName"), "hash": pick("FileHash", "hashValue"),
        "domain": pick("DnsResolution", "domainName"), "technique_id": first_technique(ad.get("techniques")),
        "tactic": _first_tactic(ad.get("tactics")),
    }


def map_cortex(raw: dict) -> dict:
    ev = (raw.get("events") or [{}])[0] if isinstance(raw.get("events"), list) else {}
    g = lambda k: raw.get(k) if raw.get(k) not in (None, "", []) else ev.get(k)  # noqa: E731
    hip = g("host_ip")
    hip = hip[0] if isinstance(hip, list) and hip else hip
    ts = g("detection_timestamp") or g("creation_time")
    return {
        "source_event_id": str(raw.get("alert_id") or ""), "event_time": ts, "severity": _sev(g("severity")),
        "signature": g("name") or g("alert_name") or "", "message": g("description") or "",
        "src_ip": g("action_remote_ip"), "dst_ip": g("action_local_ip") or hip, "host": g("host_name") or g("agent_hostname"),
        "username": g("user_name"), "hash": g("action_file_sha256") or g("causality_actor_process_image_sha256"),
        "technique_id": first_technique(g("mitre_technique_id_and_name"), g("mitre_technique_id")),
        "tactic": _first_tactic(g("mitre_tactic_id_and_name")), "dst_port": g("action_remote_port"),
    }


# ---------------- CEF / LEEF (syslog) — hanya untuk produk yang memang mengirim format ini
_CEF_HDR = re.compile(r"((?:[^|\\]|\\.)*)\|")
_KV = re.compile(r"(\w+(?:\.\w+)*)=")


def _unesc(s: str) -> str:
    return s.replace("\\|", "|").replace("\\=", "=").replace("\\\\", "\\").replace("\\n", "\n")


def parse_cef(line: str) -> dict:
    i = line.find("CEF:")
    if i < 0:
        raise ValueError("bukan CEF")
    rest, parts = line[i + 4:], []
    for _ in range(7):  # version|vendor|product|devver|sigid|name|severity|
        m = _CEF_HDR.match(rest)
        if not m:
            raise ValueError("header CEF tidak lengkap")
        parts.append(_unesc(m.group(1)))
        rest = rest[m.end():]
    ext: dict[str, str] = {}
    ms = list(_KV.finditer(rest))
    for n, m in enumerate(ms):
        end = ms[n + 1].start() if n + 1 < len(ms) else len(rest)
        ext[m.group(1)] = _unesc(rest[m.end():end].strip())
    return {"format": "CEF", "vendor": parts[1], "product": parts[2], "sig_id": parts[4], "name": parts[5], "severity": parts[6], "ext": ext}


def parse_leef(line: str) -> dict:
    i = line.find("LEEF:")
    if i < 0:
        raise ValueError("bukan LEEF")
    segs = line[i + 5:].split("|", 5)
    if len(segs) < 6:
        raise ValueError("header LEEF tidak lengkap")
    ver, vendor, product, _, event_id, body = segs
    delim = "\t"
    if ver.startswith("2.0"):  # 2.0: delimiter opsional sebagai field ke-6
        d, _, body = body.partition("|")
        delim = {"^": "^", "x09": "\t"}.get(d, d or "\t") if d else "\t"
    ext = dict(kv.split("=", 1) for kv in body.split(delim) if "=" in kv)
    return {"format": "LEEF", "vendor": vendor, "product": product, "sig_id": event_id, "name": event_id, "severity": ext.get("sev", ""), "ext": ext}


def map_cef(raw: dict) -> dict:
    """raw = {'line': '<syslog line>', 'received': iso}. ID = hash baris + waktu event (syslog tak punya ID asal)."""
    import hashlib
    line = raw.get("line", "")
    d = parse_cef(line) if "CEF:" in line else parse_leef(line)
    e = d["ext"]
    sev = str(d["severity"])
    sevn = int(sev) if sev.isdigit() else None
    ts = e.get("rt") or e.get("devTime") or raw.get("received")
    if isinstance(ts, str) and ts.isdigit():
        ts = int(ts)
    return {
        "source_event_id": hashlib.sha256(f"{line}|{ts}".encode()).hexdigest()[:32], "event_time": ts,
        "severity": ("critical" if sevn is not None and sevn >= 9 else "high" if sevn is not None and sevn >= 7 else "medium" if sevn is not None and sevn >= 4 else _sev(sev) or "low"),
        "signature": f"{d['vendor']}/{d['product']}: {d['name']}", "message": e.get("msg") or e.get("cs1") or d["name"],
        "src_ip": e.get("src") or e.get("srcIp"), "dst_ip": e.get("dst") or e.get("dstIp"), "dst_port": e.get("dpt") or e.get("dstPort"),
        "protocol": e.get("proto"), "host": e.get("dhost") or e.get("shost"), "username": e.get("duser") or e.get("suser") or e.get("usrName"),
        "technique_id": first_technique(e.get("cs1"), e.get("cs2"), e.get("msg")),
    }


MAPPERS: dict[str, Callable[[dict], dict]] = {
    "generic": map_generic, "wazuh": map_wazuh, "ecs": map_ecs, "elastic": map_ecs, "elasticsearch": map_ecs,
    "splunk_es": map_splunk_es, "qradar": map_qradar, "crowdstrike": map_crowdstrike, "sentinelone": map_sentinelone,
    "defender": map_defender, "sentinel": map_sentinel, "cortex_xdr": map_cortex, "syslog": map_cef, "cef": map_cef,
}
