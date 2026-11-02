import numpy as np
import pytest
from datetime import timedelta

from services.common.util import utcnow
from services.engine.graph import integrity
from services.engine.graph.evidence import Evidence, build_evidence
from services.engine.graph.facts import Fact
from services.engine.noise import fft_pcc, risk_gate
from services.engine.scoring.ahp import weights_from_matrix
from services.engine.scoring.risk import RiskEngine, ScoreInput
from services.common.config import get_settings

RNG = np.random.default_rng(7)


def periodic_series(days=7, base=20, amp=0.8, noise=1.0):
    h = np.arange(24 * days)
    lam = base * (1 + amp * np.sin(2 * np.pi * (h - 8) / 24))
    return RNG.poisson(lam * noise)


# ---------------- FFT-PCC
def test_periodic_series_detected():
    r = fft_pcc.analyze(periodic_series())
    assert r.periodic and r.period_hours == 24 and r.pcc > 0.85 and r.peak_ratio >= 3


def test_random_series_not_periodic():
    r = fft_pcc.analyze(RNG.poisson(15, 168))
    assert not r.periodic


def test_insufficient_history_is_conservative():
    r = fft_pcc.analyze(periodic_series(days=1))
    assert not r.periodic and r.reason == "insufficient_history"


def test_constant_series_not_periodic():
    assert not fft_pcc.analyze([5] * 100).periodic


def test_periodic_but_pcc_low_is_rejected():
    # dominan 24 jam tetapi fase bergeser tiap hari -> PCC rendah
    h = np.arange(168)
    shift = (h // 24) * 6
    x = 20 + 15 * np.sin(2 * np.pi * (h - shift) / 24)
    assert not fft_pcc.analyze(x).periodic


# ---------------- risk gate
def _ev(**kw):
    e = Evidence()
    for k, v in kw.items():
        setattr(e, k, v)
    return e


def test_gate_off_without_evidence():
    assert risk_gate.evaluate(Evidence(), False).G == 0


@pytest.mark.parametrize("ev,kc", [
    (_ev(ioc={"confirmed": True}), False),
    (_ev(vuln={"existing": True, "exploit": "public_exploit", "cves": []}), False),
    (_ev(asset={"known": True, "criticality": "core"}), False),
    (Evidence(), True),
])
def test_gate_each_indicator(ev, kc):
    assert risk_gate.evaluate(ev, kc).G == 1


def test_vuln_only_does_not_trigger_gate():
    assert risk_gate.evaluate(_ev(vuln={"existing": True, "exploit": "vuln_only", "cves": []}), False).G == 0


# ---------------- integrity
def F(st, sid, pred, ot=None, oid=None, val=None, src="opencti", conf=0.9, age_days=0):
    now = utcnow()
    return Fact(st, sid, pred, ot, oid, val, src, now, now - timedelta(days=age_days), conf)


def test_stale_ioc_quarantined_not_fact():
    snap = integrity.verify([F("IOC", "1.2.3.4", "verdict", val="malicious", age_days=90)])
    assert not snap.facts and snap.quarantined and snap.violations[0].rule == "temporal_freshness"


def test_conflict_two_high_confidence_sources_quarantined():
    snap = integrity.verify([F("IOC", "1.2.3.4", "verdict", val="malicious", src="a"), F("IOC", "1.2.3.4", "verdict", val="benign", src="b")])
    assert not snap.facts and {v.rule for v in snap.violations} == {"conflict"}


def test_low_confidence_conflict_superseded():
    snap = integrity.verify([F("IOC", "1.2.3.4", "verdict", val="malicious", conf=0.95, src="a"), F("IOC", "1.2.3.4", "verdict", val="benign", conf=0.3, src="b")])
    assert [f.value for f in snap.facts] == ["malicious"]


def test_ioc_cannot_be_internal_asset():
    snap = integrity.verify([F("IOC", "10.0.0.5", "verdict", val="malicious"), F("Asset", "10.0.0.5", "criticality", val="core", src="glpi")])
    assert not snap.facts and all(v.rule == "disjoint_class" for v in snap.violations)


def test_bad_cve_and_domain_range_and_missing_provenance():
    snap = integrity.verify([
        F("Asset", "10.0.0.5", "criticality", val="core", src="glpi"),
        F("Asset", "10.0.0.5", "has_vulnerability", "CVE", "CVE-bad", src="scanner"),
        F("IOC", "1.2.3.4", "criticality", val="core"),                       # domain salah
        Fact("IOC", "5.6.7.8", "verdict", None, None, "malicious", None, None, None, None),  # tanpa provenance
    ])
    rules = {v.rule for v in snap.violations}
    assert {"canonical_identity", "relation_domain", "provenance"} <= rules
    assert [f.pred for f in snap.facts] == ["criticality"]


def test_quarantined_evidence_cannot_activate_gate():
    snap = integrity.verify([F("IOC", "1.2.3.4", "verdict", val="malicious", age_days=400)])
    ev = build_evidence({"src_ip": "1.2.3.4"}, snap)
    assert not ev.ioc["confirmed"] and risk_gate.evaluate(ev, False).G == 0


def test_canonicalization_merges_case():
    snap = integrity.verify([F("Asset", "WEB-01", "criticality", val="Core", src="glpi")])
    assert snap.facts[0].subj_id == "web-01" and snap.facts[0].value == "core"


# ---------------- AHP
def test_published_weights_sum_to_one_and_levels():
    e = RiskEngine(get_settings().scoring())
    assert abs(sum(e.W.values()) - 1) < 1e-9
    assert e.level(80) == "high" and e.level(79.99) == "medium" and e.level(60) == "medium" and e.level(59.9) == "low"


def test_score_bounds_and_monotonic():
    e = RiskEngine(get_settings().scoring())
    lo = e.score(ScoreInput(tactic="Reconnaissance", evidence=Evidence()))["R"]
    ev = _ev(asset={"known": True, "criticality": "core", "sensitivity": "top_secret", "exposure": "internet", "role": "jump_server"},
             ioc={"confirmed": True, "verdict": "malicious", "confidence": 1, "age_days": 0, "apt": "X", "apt_threat_level": 1},
             vuln={"existing": True, "exploit": "public_exploit", "cves": ["CVE-2024-0001"]})
    hi = e.score(ScoreInput(tactic="Impact", evidence=ev, src_ip="8.8.8.8", same_triplet_24h=10, killchain_progression=True, evasion=True,
                            industry_campaign=True, network_anomaly=True))
    assert 0 <= lo < hi["R"] <= 100 and hi["level"] == "high"
    assert abs(hi["R"] - 100 * sum(c["W"] * c["C"] for c in hi["criteria"].values())) < 0.02  # E_ext=E_int=1 pada baseline


def test_multipliers_capped_at_100():
    cfg = get_settings().scoring()
    cfg["environment"]["use_multipliers"] = True
    e = RiskEngine(cfg)
    ev = _ev(asset={"known": True, "criticality": "core", "sensitivity": "top_secret", "exposure": "internet", "role": "jump_server"},
             ioc={"confirmed": True, "verdict": "malicious", "confidence": 1, "age_days": 0, "apt": "X", "apt_threat_level": 1},
             vuln={"existing": True, "exploit": "public_exploit", "cves": []})
    r = e.score(ScoreInput(tactic="Impact", evidence=ev, src_ip="8.8.8.8", same_triplet_24h=10, killchain_progression=True, evasion=True, industry_campaign=True, network_anomaly=True))
    assert r["R"] == 100 and r["E_ext"] == 1.2 and r["E_int"] == 1.1


def test_matrix_consistency_matches_paper_cr_roughly():
    w, cr = weights_from_matrix(get_settings().scoring()["ahp_judgment_matrix"])
    assert cr < 0.10 and abs(w.sum() - 1) < 1e-9
    # Catatan: bobot hasil matriks != bobot terpublikasi (0.16/0.31/...). Lihat README -> "Temuan verifikasi paper".


def test_internal_ip_definition_excludes_documentation_ranges():
    from services.common.util import is_private_ip
    assert is_private_ip("10.1.2.3") and is_private_ip("192.168.0.9") and is_private_ip("172.20.0.1")
    assert not is_private_ip("203.0.113.45") and not is_private_ip("8.8.8.8") and not is_private_ip(None)
