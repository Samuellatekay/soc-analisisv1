"""Deterministic Master Agent + Knowledge Retrieval / Association Query / BERT Reasoning agents + fusion konservatif.

Tidak ada LLM generatif di jalur keputusan online. "Agent" = komponen perangkat lunak berfungsi spesifik.
"""
from __future__ import annotations

from dataclasses import dataclass

from services.engine.graph.evidence import Evidence
from services.engine.noise.risk_gate import GateResult

from .plugins import PLUGIN_ROUTES, Ctx, PluginResult

# bobot cabang & η belum dipublikasikan di paper -> nilai awal yang perlu dikalibrasi (jumlah maksimum = 1.0)
OMEGA = {"knowledge": 0.30, "query": 0.30, "bert": 0.30}
ETA = 0.10


def knowledge_agent(ev, rules: dict, ctx: Ctx) -> dict:
    rule = rules["rules"].get(ev.attack_type, rules["rules"]["other"])
    count = max(ev.count, ctx.count_hour)
    thr = rule["min_count_true"]
    y = 1 if count >= thr else 0
    if y:
        c = min(1.0, 0.6 + 0.4 * min(1.0, (count - thr) / max(thr, 1)))
    else:
        c = 0.6 if thr < 1_000_000 else 0.35
    return {"agent": "knowledge_retrieval", "y": y, "c": round(c, 3), "rule": ev.attack_type, "rule_version": rules["version"],
            "steps": rule["verify_steps"], "observed_count": count, "threshold": thr}


def query_agent(ev, evidence: Evidence, ctx: Ctx) -> dict:
    results: list[PluginResult] = []
    for fn in PLUGIN_ROUTES.get(ev.attack_type, PLUGIN_ROUTES["other"]):
        try:
            results.append(PluginResult.model_validate(fn(evidence, ctx, ev).model_dump()))
        except Exception as e:  # noqa: BLE001  plugin gagal -> tidak menghentikan pipeline
            results.append(PluginResult(plugin=fn.__name__, ok=False, data={"error": str(e)[:120]}))
    pos = [r for r in results if r.ok and r.positive is True]
    neg = [r for r in results if r.ok and r.positive is False]
    if pos:
        y, c = 1, max(r.confidence for r in pos)
    elif neg:
        y, c = 0, max(r.confidence for r in neg)
    else:
        y, c = 0, 0.15 if not any(r.ok for r in results) else 0.3
    return {"agent": "association_query", "y": y, "c": round(float(c), 3), "plugins": [r.model_dump() for r in results]}


def bert_agent(ev, reasoner) -> dict:
    out = reasoner.predict(ev)
    return {"agent": "bert_reasoning", "y": out.y, "c": round(out.confidence, 3), "p_true": round(out.p_true, 4),
            "p_false_positive": round(1 - out.p_true, 4), "model": out.model}


def fuse(k: dict, q: dict, b: dict, gate: GateResult, retain: float = 0.60, flt: float = 0.30, context_ok: bool = True) -> dict:
    """Eq. 7: S_TA = Σ ω_j c_j y_j + η G, dengan aturan konservatif."""
    s = OMEGA["knowledge"] * k["c"] * k["y"] + OMEGA["query"] * q["c"] * q["y"] + OMEGA["bert"] * b["c"] * b["y"] + ETA * gate.G
    fp_confident = sum(1 for x in (k, q, b) if x["y"] == 0 and x["c"] >= 0.5)
    tp_conf = sum(1 for x in (k, q, b) if x["y"] == 1 and x["c"] >= 0.5)
    if gate.G:
        disp, why = "retained", "risk gate aktif (" + "; ".join(gate.reasons) + ") -> dipertahankan apa pun hasil BERT"
    elif s >= retain:
        disp, why = "retained", f"S_TA={s:.2f} ≥ {retain}"
    elif s <= flt:
        if fp_confident >= 2 and context_ok:
            disp, why = "filtered", f"S_TA={s:.2f} ≤ {flt} dan {fp_confident}/3 cabang yakin false-positive"
        else:
            disp, why = "manual_review", f"S_TA={s:.2f} rendah tetapi bukti false-positive kurang yakin ({fp_confident}/3) atau konteks aset/enrichment tidak lengkap -> review analis"
    else:
        disp, why = "manual_review", f"{flt} < S_TA={s:.2f} < {retain} -> review analis"
    return {"S_TA": round(s, 4), "disposition": disp, "reason": why, "conflict": bool(tp_conf and fp_confident),
            "weights": OMEGA, "eta": ETA}


def orchestrate(ev, evidence: Evidence, gate: GateResult, ctx: Ctx, rules: dict, reasoner, retain=0.60, flt=0.30, enr_status: str = 'missing') -> dict:
    """Master Agent: dekomposisi tugas deterministik -> 3 agen -> fusion konservatif."""
    k = knowledge_agent(ev, rules, ctx)
    q = query_agent(ev, evidence, ctx)
    b = bert_agent(ev, reasoner)
    f = fuse(k, q, b, gate, retain, flt, context_ok=bool(evidence.asset.get('known')) and enr_status == 'ok')
    return {"master": "deterministic", "attack_type": ev.attack_type, "knowledge": k, "query": q, "bert": b,
            "risk_gate": gate.to_dict(), "fusion": f}
