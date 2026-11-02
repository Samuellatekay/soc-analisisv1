"""Risk engine AHP deterministik (Eq. 8-10). LLM/RAG tidak menghitung atau menimpa skor ini.

C_i    = Σ_j w_ij · v_ij
R_base = 100 · Σ_i W_i · C_i
R      = min(100, R_base · E_ext · E_int)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from services.common.util import is_private_ip
from services.engine.graph.evidence import Evidence
from services.engine.scoring.ahp import weights_from_matrix


@dataclass
class ScoreInput:
    tactic: str | None
    evidence: Evidence
    src_ip: str | None = None
    same_triplet_24h: int = 0
    killchain_progression: bool = False
    evasion: bool = False
    industry_campaign: bool = False
    network_anomaly: bool = False
    enrichment_status: str = "missing"
    snapshot_id: str | None = None


class RiskEngine:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.version = cfg["scoring_version"]
        order = cfg["criteria_order"]
        if cfg.get("weights_source") == "matrix":
            w, self.cr = weights_from_matrix(cfg["ahp_judgment_matrix"])
            self.W = {k: float(v) for k, v in zip(order, w)}
        else:
            self.W = dict(cfg["criteria_weights_published"])
            self.cr = None
        s = sum(self.W.values())
        if abs(s - 1.0) > 1e-6:
            raise ValueError(f"bobot kriteria harus berjumlah 1, dapat {s}")

    # ---------- helpers
    def level(self, r: float) -> str:
        lv = self.cfg["levels"]
        return "high" if r >= lv["high_min"] else "medium" if r >= lv["medium_min"] else "low"

    def _norm(self, name: str, key: str) -> float:
        m = self.cfg["normalization"][name]
        return float(m.get(key, m.get("unknown", 0.0)))

    def _path(self, ev: Evidence, src_ip: str | None) -> str:
        exp = ev.asset.get("exposure", "unknown")
        external_src = bool(src_ip) and not is_private_ip(src_ip)
        if exp == "isolated":
            return "isolated"
        if external_src and exp in ("internet", "dmz"):
            return "direct"
        return "hop"

    def score(self, inp: ScoreInput) -> dict:
        n = self.cfg["normalization"]
        sw = self.cfg["sub_weights"]
        ev = inp.evidence
        tactic = inp.tactic if inp.tactic in self.cfg["tactic_hazard"] else "Unknown"
        pol = self.cfg["tactic_policy_weight"]
        ioc = ev.ioc
        fresh = 0.0
        if ioc.get("verdict") and ioc.get("age_days") is not None:
            fresh = math.exp(-math.log(2) * ioc["age_days"] / n["intel_freshness_halflife_days"])
        hc = n["homogeneous_correlation"]
        raw: dict[str, dict[str, tuple]] = {
            "target_criticality": {
                "asset_business_value": (ev.asset.get("criticality", "unknown"), self._norm("asset_business_value", ev.asset.get("criticality", "unknown"))),
                "data_sensitivity": (ev.asset.get("sensitivity", "unknown"), self._norm("data_sensitivity", ev.asset.get("sensitivity", "unknown"))),
                "attack_surface_exposure": (ev.asset.get("exposure", "unknown"), self._norm("attack_surface_exposure", ev.asset.get("exposure", "unknown"))),
            },
            "attack_stage_hazard": {
                "phase_hazard": (tactic, float(self.cfg["tactic_hazard"][tactic])),
                "stage_policy_weight": (tactic, min(1.0, max(0.0, float(pol.get(tactic, pol["default"]))))),
            },
            "threat_intel_match": {
                "ioc_confidence": (ioc.get("verdict", "none"), float(ioc.get("confidence") or 0.0) if ioc.get("verdict") else 0.0),
                "vulnerability_existence": ("existing" if ev.vuln.get("existing") else "none", self._norm("vulnerability_existence", "existing" if ev.vuln.get("existing") else "none")),
                "apt_association": (ioc.get("apt") or "none", float(ioc.get("apt_threat_level") or 0.0)),
                "intel_freshness": (None if ioc.get("age_days") is None else round(ioc["age_days"], 2), fresh),
            },
            "attack_feasibility": {
                "vuln_exploitability": (ev.vuln.get("exploit", "none"), self._norm("vuln_exploitability", ev.vuln.get("exploit", "none"))),
                "path_reachability": (self._path(ev, inp.src_ip),) * 1 + (self._norm("path_reachability", self._path(ev, inp.src_ip)),),
                "protection_bypass": ("evasion" if inp.evasion else "none", self._norm("protection_bypass", "evasion" if inp.evasion else "none")),
            },
            "attack_persistence": {
                "homogeneous_correlation": (inp.same_triplet_24h, min(hc["cap"], hc["base"] + hc["per_alert"] * inp.same_triplet_24h)),
                "killchain_progression": ("progression" if inp.killchain_progression else "none", self._norm("killchain_progression", "progression" if inp.killchain_progression else "none")),
                "lateral_movement": (ev.asset.get("role", "endpoint"), self._norm("lateral_movement", "key_segment" if ev.asset.get("role") in ("jump_server", "key_segment") else "endpoint")),
            },
        }
        criteria: dict[str, dict] = {}
        for crit, subs in raw.items():
            c = 0.0
            detail = {}
            for sub, (rv, v) in subs.items():
                v = min(1.0, max(0.0, float(v)))
                w = sw[crit][sub]
                c += w * v
                detail[sub] = {"w": w, "raw": rv, "v": round(v, 4)}
            criteria[crit] = {"W": self.W[crit], "C": round(c, 4), "sub": detail}

        env = self.cfg["environment"]
        env_vals = {"external_threat_posture": 1.0 if inp.industry_campaign else 0.0,
                    "internal_security_status": 1.0 if inp.network_anomaly else 0.0}
        c_env = sum(env_vals.values()) / 2
        e_ext = e_int = 1.0
        if env.get("use_multipliers"):
            e_ext = env["E_ext_industry_campaign"] if inp.industry_campaign else 1.0
            e_int = env["E_int_network_wide_anomaly"] if inp.network_anomaly else 1.0
            c_env = 0.0  # hindari double-counting (lihat catatan validasi v1)
        criteria["environmental"] = {"W": self.W["environmental"], "C": round(c_env, 4),
                                     "sub": {k: {"w": 0.5, "raw": bool(v), "v": v} for k, v in env_vals.items()}}

        r_base = 100.0 * sum(c["W"] * c["C"] for c in criteria.values())
        r = min(100.0, r_base * e_ext * e_int)
        return {
            "scoring_version": self.version, "weights_source": self.cfg.get("weights_source", "published"),
            "formula": "R=min(100, 100*Σ W_i*C_i * E_ext * E_int); C_i=Σ w_ij*v_ij",
            "criteria": criteria, "R_base": round(r_base, 2), "E_ext": e_ext, "E_int": e_int,
            "R": round(r, 2), "level": self.level(r),
            "provenance": {"graph_snapshot_id": inp.snapshot_id, "enrichment_status": inp.enrichment_status, "fact_ids": ev.fact_ids},
        }
