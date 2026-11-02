"""Ekstraksi bukti terstruktur dari snapshot graph yang sudah tervalidasi."""
from __future__ import annotations

from dataclasses import dataclass, field

from services.common.util import utcnow

from .integrity import ValidatedSnapshot


@dataclass
class Evidence:
    asset: dict = field(default_factory=lambda: {"known": False})
    ioc: dict = field(default_factory=lambda: {"confirmed": False})
    vuln: dict = field(default_factory=lambda: {"existing": False, "exploit": "none", "cves": []})
    fact_ids: list[str] = field(default_factory=list)

    def to_dict(self):
        return {"asset": self.asset, "ioc": self.ioc, "vuln": self.vuln, "fact_ids": self.fact_ids}


def build_evidence(entities: dict, snap: ValidatedSnapshot, now=None) -> Evidence:
    now = now or utcnow()
    ev = Evidence()
    by_subj: dict[tuple, list] = {}
    for f in snap.facts:
        by_subj.setdefault((f.subj_type, f.subj_id), []).append(f)

    # --- aset tujuan
    for key in filter(None, [entities.get("dst_ip"), entities.get("host"), entities.get("src_ip")]):
        fs = by_subj.get(("Asset", str(key).lower())) or by_subj.get(("Asset", key))
        if not fs:
            continue
        a = {"known": True, "id": fs[0].subj_id}
        for f in fs:
            if f.pred in ("criticality", "sensitivity", "exposure", "role"):
                a[f.pred] = f.value
                ev.fact_ids.append(f.fact_id)
        vulns = [f for f in fs if f.pred == "has_vulnerability"]
        if vulns:
            order = {"public_exploit": 2, "vuln_only": 1}
            best = max(vulns, key=lambda f: order.get(f.attrs.get("exploit", "vuln_only"), 1))
            ev.vuln = {
                "existing": True, "exploit": best.attrs.get("exploit", "vuln_only"),
                "cves": sorted({f.obj_id for f in vulns if f.obj_id}),
            }
            ev.fact_ids += [f.fact_id for f in vulns]
        ev.asset = a
        break

    # --- IOC (sumber, domain, hash)
    best = None
    for key in filter(None, [entities.get("src_ip"), entities.get("domain"), entities.get("hash"), entities.get("dst_ip")]):
        fs = by_subj.get(("IOC", str(key).lower())) or by_subj.get(("IOC", key)) or []
        for f in fs:
            if f.pred == "verdict" and f.value in ("malicious", "suspicious"):
                if best is None or (f.confidence or 0) > (best.confidence or 0):
                    best = f
        if best:
            apt = [x for x in fs if x.pred == "attributed_to"]
            ts = best.updated_at or best.acquired_at
            ev.ioc = {
                "confirmed": best.value == "malicious" and (best.confidence or 0) >= 0.6,
                "verdict": best.value, "confidence": best.confidence, "indicator": best.subj_id,
                "age_days": max(0.0, (now - ts).total_seconds() / 86400) if ts else None,
                "apt": apt[0].obj_id if apt else None,
                "apt_threat_level": float(apt[0].attrs.get("threat_level", 0.0)) if apt else 0.0,
            }
            ev.fact_ids += [best.fact_id] + [x.fact_id for x in apt]
            break
    return ev
