"""Conservative risk gate: alert periodik yang membawa bukti berisiko tinggi tidak boleh dibuang."""
from __future__ import annotations

from dataclasses import dataclass, field

from services.engine.graph.evidence import Evidence


@dataclass
class GateResult:
    G: int
    indicators: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return sum(1 for v in self.indicators.values() if v)

    def to_dict(self):
        return {"G": self.G, "indicators": self.indicators, "high_risk_indicator": f"{self.count}/{len(self.indicators)}", "reasons": self.reasons}


def evaluate(ev: Evidence, killchain_progression: bool) -> GateResult:
    """Bukti HANYA dari graph tervalidasi (sudah lolos semantic integrity) yang dapat mengaktifkan gate."""
    ind = {
        "confirmed_ioc": bool(ev.ioc.get("confirmed")),
        "exploitable_vulnerability": bool(ev.vuln.get("existing")) and ev.vuln.get("exploit") == "public_exploit",
        "high_criticality_asset": ev.asset.get("criticality") == "core",
        "killchain_progression": bool(killchain_progression),
    }
    reasons = {
        "confirmed_ioc": "IOC terkonfirmasi cocok dengan entitas alert",
        "exploitable_vulnerability": "aset punya vulnerability dengan exploit publik",
        "high_criticality_asset": "aset tujuan berkriteria core",
        "killchain_progression": "ada progres kill-chain pada entitas yang sama",
    }
    r = [reasons[k] for k, v in ind.items() if v]
    return GateResult(G=1 if r else 0, indicators=ind, reasons=r)
