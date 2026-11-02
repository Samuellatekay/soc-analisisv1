"""Plugin evidence untuk Association Query Agent (Tabel 1 paper). Output divalidasi schema (pydantic)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from services.engine.graph.evidence import Evidence


class PluginResult(BaseModel):
    plugin: str
    ok: bool
    positive: bool | None = None        # True = bukti true-alert, False = bukti false-positive, None = tidak ada informasi
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    data: dict[str, Any] = {}


class Ctx(BaseModel):
    count_hour: int = 0
    count_24h: int = 0
    distinct_dst_24h: int = 0


def ioc_plugin(ev: Evidence, ctx: Ctx, e) -> PluginResult:
    if ev.ioc.get("verdict"):
        return PluginResult(plugin="IOC Matching", ok=True, positive=bool(ev.ioc.get("confirmed")), confidence=float(ev.ioc.get("confidence") or 0),
                            data={k: ev.ioc.get(k) for k in ("indicator", "verdict", "confidence", "apt")})
    return PluginResult(plugin="IOC Matching", ok=True, positive=False, confidence=0.4, data={"match": False})


def ip_reputation_plugin(ev: Evidence, ctx: Ctx, e) -> PluginResult:
    if ev.ioc.get("verdict") in ("malicious", "suspicious"):
        c = float(ev.ioc.get("confidence") or 0)
        return PluginResult(plugin="IP Reputation", ok=True, positive=True, confidence=c, data={"verdict": ev.ioc["verdict"]})
    return PluginResult(plugin="IP Reputation", ok=True, positive=None, confidence=0.0, data={"listed": False})


def netflow_plugin(ev: Evidence, ctx: Ctx, e) -> PluginResult:
    burst = ctx.count_hour >= 100 or e.count >= 100
    return PluginResult(plugin="NetFlow Behavior", ok=True, positive=True if burst else None, confidence=0.7 if burst else 0.0,
                        data={"count_hour": ctx.count_hour, "count_24h": ctx.count_24h, "distinct_dst_24h": ctx.distinct_dst_24h})


def whois_plugin(ev: Evidence, ctx: Ctx, e) -> PluginResult:
    # tidak ada provider WHOIS offline; ditandai tidak tersedia (tidak mengarang data)
    return PluginResult(plugin="Whois", ok=False, data={"reason": "provider_not_configured"})


def asset_plugin(ev: Evidence, ctx: Ctx, e) -> PluginResult:
    if not ev.asset.get("known"):
        return PluginResult(plugin="Asset Query", ok=True, positive=None, confidence=0.0, data={"known": False})
    crit = ev.asset.get("criticality")
    return PluginResult(plugin="Asset Query", ok=True, positive=True if crit == "core" else None,
                        confidence=0.8 if crit == "core" else 0.0, data=ev.asset)


def vuln_plugin(ev: Evidence, ctx: Ctx, e) -> PluginResult:
    if ev.vuln.get("existing"):
        pub = ev.vuln.get("exploit") == "public_exploit"
        return PluginResult(plugin="Vulnerability Correlation", ok=True, positive=pub, confidence=0.85 if pub else 0.4, data=ev.vuln)
    return PluginResult(plugin="Vulnerability Correlation", ok=True, positive=None, confidence=0.0, data={"existing": False})


# attack type -> plugin yang relevan (ringkasan Tabel 1)
PLUGIN_ROUTES = {
    "brute_force": [ip_reputation_plugin, netflow_plugin, asset_plugin, ioc_plugin],
    "scanning": [ip_reputation_plugin, netflow_plugin, asset_plugin, vuln_plugin],
    "web_attack": [vuln_plugin, ioc_plugin, asset_plugin, netflow_plugin],
    "malware_comm": [ioc_plugin, netflow_plugin, whois_plugin, asset_plugin],
    "policy_violation": [asset_plugin],
    "other": [ioc_plugin, asset_plugin],
}
