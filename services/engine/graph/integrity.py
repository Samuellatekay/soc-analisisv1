"""Semantic integrity & consistency verification (Algoritma 2 pada paper).

G* = G \\ Q : hanya fakta yang lolos canonical identity, schema/type, relation domain/range,
metadata (source/time/confidence), temporal freshness, dan conflict detection yang boleh dipakai
untuk risk gate dan AHP. Fakta stale/kontradiktif/tanpa provenance dikarantina — BUKAN dianggap fakta.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import timedelta

from services.common.util import canon_ip, utcnow

from .facts import Fact

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# predicate -> (domain, range_type | "literal", allowed literals | None, functional?)
SCHEMA: dict[str, tuple[str, str, set[str] | None, bool]] = {
    "has_vulnerability": ("Asset", "CVE", None, False),
    "attributed_to": ("IOC", "APT", None, False),
    "uses_technique": ("APT", "Technique", None, False),
    "verdict": ("IOC", "literal", {"malicious", "suspicious", "benign"}, True),
    "criticality": ("Asset", "literal", {"core", "support", "test"}, True),
    "sensitivity": ("Asset", "literal", {"top_secret", "confidential", "internal", "public"}, True),
    "exposure": ("Asset", "literal", {"internet", "dmz", "internal", "isolated"}, True),
    "role": ("Asset", "literal", {"jump_server", "key_segment", "server", "endpoint"}, True),
}
DISJOINT = [{"Asset", "IOC"}]  # IOC tidak boleh sekaligus aset internal
FRESHNESS = {  # batas umur per kelas sumber (Δ)
    "intel": timedelta(days=30), "inventory": timedelta(days=7), "scanner": timedelta(days=30), "default": timedelta(days=30),
}
CONFLICT_MIN_CONF = 0.7


@dataclass
class Violation:
    rule: str
    fact_id: str
    detail: str
    quarantined: bool = True

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class ValidatedSnapshot:
    facts: list[Fact]
    violations: list[Violation]
    quarantined: list[Fact]
    snapshot_id: str

    def summary(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id, "accepted": len(self.facts), "quarantined": len(self.quarantined),
            "violations": [v.to_dict() for v in self.violations][:50],
        }


def _canon_id(t: str, v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    if t == "CVE":
        return v.upper()
    if t == "Technique":
        return v.upper()
    if t in ("Asset", "IOC"):
        return canon_ip(v) or v.lower()
    if t == "APT":
        return v.strip().upper()
    return v


def _freshness_class(source: str | None) -> str:
    s = (source or "").lower()
    if s in {"glpi", "inventory", "cmdb"} or "asset" in s:
        return "inventory"
    if s in {"opencti", "intel", "misp"} or "intel" in s:
        return "intel"
    if "scan" in s or "vuln" in s:
        return "scanner"
    return "default"


def verify(candidates: list[Fact], now=None, freshness: dict | None = None) -> ValidatedSnapshot:
    now = now or utcnow()
    limits = {**FRESHNESS, **(freshness or {})}
    violations: list[Violation] = []
    quarantine: dict[str, Fact] = {}

    def q(f: Fact, rule: str, detail: str, hard: bool = True):
        violations.append(Violation(rule, f.fact_id, detail, hard))
        if hard:
            quarantine[f.fact_id] = f

    # 1. canonicalisasi + deduplikasi eksak
    seen: dict[str, Fact] = {}
    for f in candidates:
        f.subj_id = _canon_id(f.subj_type, f.subj_id) or ""
        f.obj_id = _canon_id(f.obj_type, f.obj_id) if f.obj_type else None
        if f.value is not None:  # perbaikan deterministik hanya bila pemetaan unik (huruf besar/kecil, spasi)
            f.value = f.value.strip().lower().replace(" ", "_")
        seen.setdefault(f.fact_id, f)
    facts = list(seen.values())

    # 2. disjoint-class: id yang sama bertipe saling lepas
    types_by_id: dict[str, set[str]] = {}
    for f in facts:
        types_by_id.setdefault(f.subj_id, set()).add(f.subj_type)
        if f.obj_type and f.obj_id:
            types_by_id.setdefault(f.obj_id, set()).add(f.obj_type)
    bad_ids = {i for i, ts in types_by_id.items() if any(d <= ts for d in DISJOINT)}

    inventory_assets = {f.subj_id for f in facts if f.subj_type == "Asset" and f.pred == "criticality"}

    for f in facts:
        if f.subj_id in bad_ids or (f.obj_id in bad_ids if f.obj_id else False):
            q(f, "disjoint_class", f"{f.subj_id} bertipe ganda saling lepas {sorted(types_by_id.get(f.subj_id, []))}")
            continue
        sch = SCHEMA.get(f.pred)
        if not sch:
            q(f, "schema", f"predikat tidak dikenal: {f.pred}")
            continue
        dom, rng, allowed, _ = sch
        # 3. domain/range
        if f.subj_type != dom:
            q(f, "relation_domain", f"{f.pred} butuh subjek {dom}, dapat {f.subj_type}")
            continue
        if rng == "literal":
            if f.obj_type is not None or f.value is None:
                q(f, "relation_range", f"{f.pred} butuh nilai literal")
                continue
            if allowed and f.value not in allowed:
                q(f, "relation_range", f"nilai '{f.value}' di luar {sorted(allowed)}")
                continue
        else:
            if f.obj_type != rng or not f.obj_id:
                q(f, "relation_range", f"{f.pred} butuh objek {rng}, dapat {f.obj_type}")
                continue
        # identitas kanonis
        if f.subj_type == "Technique" and not TECH_RE.match(f.subj_id):
            q(f, "canonical_identity", f"ID teknik tidak valid {f.subj_id}")
            continue
        for t, i in ((f.subj_type, f.subj_id), (f.obj_type, f.obj_id)):
            if t == "CVE" and not CVE_RE.match(i or ""):
                q(f, "canonical_identity", f"ID CVE tidak valid {i}")
                break
            if t == "Technique" and not TECH_RE.match(i or ""):
                q(f, "canonical_identity", f"ID teknik tidak valid {i}")
                break
        if f.fact_id in quarantine:
            continue
        # 4. endpoint harus ada atau ditandai unknown
        if f.pred == "has_vulnerability" and f.subj_id not in inventory_assets:
            f.attrs["endpoint_unknown"] = True
            violations.append(Violation("endpoint_unknown", f.fact_id, f"aset {f.subj_id} tidak ada di inventaris (ditandai unknown)", False))
        # 5. provenance & confidence
        if not f.source or f.acquired_at is None or f.confidence is None:
            q(f, "provenance", "source/acquired_at/confidence wajib ada")
            continue
        if not (0.0 <= f.confidence <= 1.0):
            q(f, "provenance", f"confidence di luar [0,1]: {f.confidence}")
            continue
        # 6. freshness
        ts = f.updated_at or f.acquired_at
        lim = limits.get(_freshness_class(f.source), limits["default"])
        if now - ts > lim:
            q(f, "temporal_freshness", f"data {now - ts} lebih tua dari batas {lim}")
            continue

    live = [f for f in facts if f.fact_id not in quarantine]

    # 7. conflict detection pada predikat fungsional
    groups: dict[tuple, list[Fact]] = {}
    for f in live:
        sch = SCHEMA[f.pred]
        if sch[3]:
            groups.setdefault((f.subj_type, f.subj_id, f.pred), []).append(f)
    for key, fs in groups.items():
        vals = {f.value for f in fs}
        if len(vals) < 2:
            continue
        high = [f for f in fs if (f.confidence or 0) >= CONFLICT_MIN_CONF]
        if len({f.value for f in high}) >= 2:
            for f in fs:
                q(f, "conflict", f"asersi tidak kompatibel untuk {key[1]}.{key[2]}: {sorted(vals)}")
        else:  # satu sumber berkeyakinan tinggi menang; sisanya superseded
            best = max(fs, key=lambda x: x.confidence or 0)
            for f in fs:
                if f is not best and f.value != best.value:
                    violations.append(Violation("superseded", f.fact_id, f"digantikan nilai '{best.value}' (confidence lebih tinggi)", True))
                    quarantine[f.fact_id] = f

    accepted = [f for f in facts if f.fact_id not in quarantine]
    sid = hashlib.sha1("|".join(sorted(f.fact_id for f in accepted)).encode()).hexdigest()[:16]
    return ValidatedSnapshot(accepted, violations, list(quarantine.values()), sid)
