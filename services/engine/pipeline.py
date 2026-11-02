"""Pipeline analisis fast path (tanpa menunggu RAG/LLM):

normalize -> dedupe -> hitung triplet/jam -> enrichment -> integrity verification -> risk gate
-> FFT-PCC (kandidat noise) -> [evidence orchestration] -> AHP risk score -> commit event + outbox (+ job AI pending)
"""
from __future__ import annotations

from datetime import datetime, timedelta

import copy
import hashlib
import time

from sqlalchemy import func, select, text
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

from services.common.config import Settings, get_settings
from services.common.models import Analysis, Event, KBCandidate, Outbox, PolicyState, TripletCount, TripletState
from services.common.util import utcnow
from services.engine.agents import master
from services.engine.agents.bert import load_reasoner
from services.engine.agents.plugins import Ctx
from services.engine.enrichment.collector import EnrichmentCollector
from services.engine.graph import integrity
from services.engine.graph.evidence import build_evidence
from services.engine.noise import fft_pcc, risk_gate
from services.engine.normalizer.core import NormalizedEvent, normalize
from services.engine.normalizer.tactics import TacticResolver
from services.engine.scoring.killchain import progression
from services.engine.scoring.risk import RiskEngine, ScoreInput

WINDOW_HOURS = 168  # satu minggu (paper)


def _hour(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


class Pipeline:
    def __init__(self, settings: Settings | None = None, collector: EnrichmentCollector | None = None, reasoner=None):
        self.s = settings or get_settings()
        self.base_cfg = self.s.scoring()
        self.cfg = self.base_cfg
        self.rules = self.s.rules()
        self.policy_version, self._policy_checked = 0, 0.0
        self.pcc, self.peak, self.min_hist = self.s.pcc_threshold, self.s.fft_peak_ratio, self.s.fft_min_history_hours
        self.retain, self.flt = self.s.fusion_retain, self.s.fusion_filter
        self.risk = RiskEngine(self.cfg)
        self.collector = collector or EnrichmentCollector(self.s)
        self.reasoner = reasoner or load_reasoner(self.s.bert_model_path)
        self.tactics = TacticResolver(self.s)

    # ---------------- kebijakan dari Master (dibaca dari DB LOKAL; engine tidak pernah memanggil Master)
    def _refresh_policy(self, session: Session, ttl: float = 30.0):
        if time.time() - self._policy_checked < ttl:
            return
        self._policy_checked = time.time()
        row = session.execute(select(PolicyState.version, PolicyState.policy).where(PolicyState.id == 1)).first()
        ver, pol = (row[0], row[1]) if row else (0, {})
        if ver == self.policy_version:
            return
        n, f, sc = pol.get("noise") or {}, pol.get("fusion") or {}, pol.get("scoring") or {}
        self.pcc = n.get("pcc_threshold") or self.s.pcc_threshold
        self.peak = n.get("fft_peak_ratio") or self.s.fft_peak_ratio
        self.min_hist = n.get("fft_min_history_hours") or self.s.fft_min_history_hours
        self.retain = f.get("retain") or self.s.fusion_retain
        self.flt = f.get("filter") or self.s.fusion_filter
        cfg = copy.deepcopy(self.base_cfg)
        if sc.get("criteria_weights"):
            cfg["criteria_weights_published"], cfg["weights_source"] = sc["criteria_weights"], "published"
        if sc.get("tactic_policy_weight"):
            cfg["tactic_policy_weight"] = {**cfg["tactic_policy_weight"], **sc["tactic_policy_weight"]}
        if sc.get("level_high_min") is not None:
            cfg["levels"]["high_min"] = sc["level_high_min"]
        if sc.get("level_medium_min") is not None:
            cfg["levels"]["medium_min"] = sc["level_medium_min"]
        self.cfg, self.risk, self.policy_version = cfg, RiskEngine(cfg), ver

    # ---------------- triplet history
    @staticmethod
    def _insert(session: Session, model):
        return (postgresql.insert if session.get_bind().dialect.name == "postgresql" else sqlite.insert)(model)

    @classmethod
    def _bump(cls, session: Session, tenant: str, key: str, hour: datetime, n: int):
        """Upsert ATOMIK (INSERT .. ON CONFLICT DO UPDATE count = count + n): aman untuk banyak worker; tanpa lost-update/PK collision."""
        ins = cls._insert(session, TripletCount).values(tenant_id=tenant, triplet_key=key, hour=hour, count=n)
        session.execute(ins.on_conflict_do_update(index_elements=["tenant_id", "triplet_key", "hour"],
                                                  set_={"count": TripletCount.count + ins.excluded.count}))

    @staticmethod
    def _lock_event(session: Session, event_id: str):
        """Serialisasi pemrosesan event_id yang sama antar worker (redelivery at-least-once). PostgreSQL: advisory lock transaksi."""
        if session.get_bind().dialect.name == "postgresql":
            k = int.from_bytes(hashlib.sha256(event_id.encode()).digest()[:8], "big", signed=True)
            session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": k})

    @staticmethod
    def _series(session: Session, tenant: str, key: str, end_hour: datetime) -> list[int]:
        start = end_hour - timedelta(hours=WINDOW_HOURS - 1)
        rows = session.execute(select(TripletCount.hour, TripletCount.count).where(
            TripletCount.tenant_id == tenant, TripletCount.triplet_key == key,
            TripletCount.hour >= start, TripletCount.hour <= end_hour)).all()
        if not rows:
            return []
        m = {h: c for h, c in rows}
        first = min(m)
        n = int((end_hour - first).total_seconds() // 3600) + 1
        return [m.get(first + timedelta(hours=i), 0) for i in range(n)]

    def _periodicity(self, session: Session, tenant: str, key: str, hour: datetime) -> dict:
        prev = session.scalar(select(TripletState.result).where(TripletState.tenant_id == tenant, TripletState.triplet_key == key))
        if prev and prev.get("as_of"):
            as_of = datetime.fromisoformat(prev["as_of"])
            if hour - as_of < timedelta(hours=6) and hour >= as_of:  # evaluasi ulang tiap 6 jam waktu-event
                return prev
        res = fft_pcc.analyze(self._series(session, tenant, key, hour), self.peak, self.pcc,
                              min_history=self.min_hist).to_dict()
        res["as_of"] = hour.isoformat()
        ins = self._insert(session, TripletState).values(tenant_id=tenant, triplet_key=key, result=res, evaluated_at=utcnow())
        session.execute(ins.on_conflict_do_update(index_elements=["tenant_id", "triplet_key"], set_={"result": res, "evaluated_at": utcnow()}))
        return res

    # ---------------- main
    def process(self, session: Session, raw: dict, source: str, tenant_id: str) -> tuple[Event, bool]:
        """Return (event, created). Idempoten: event yang sama diproses sekali."""
        self.tactics.refresh(session)
        self._refresh_policy(session)
        ne: NormalizedEvent = normalize(raw, source, tenant_id, self.tactics, self.s.max_payload_bytes)
        self._lock_event(session, ne.event_id)
        existing = session.get(Event, ne.event_id)
        if existing:
            return existing, False
        hour = _hour(ne.event_time)
        self._bump(session, tenant_id, ne.triplet_key, hour, ne.count)

        facts, enr_status = self.collector.collect(ne.entities)
        snap = integrity.verify(facts)
        evidence = build_evidence(ne.entities, snap)

        order = self.cfg["killchain_order"]
        kc, kc_path = progression(session, tenant_id, ne.src_ip, ne.dst_ip, ne.tactic, ne.event_time, order)
        gate = risk_gate.evaluate(evidence, kc)

        # kandidat noise periodik
        per = self._periodicity(session, tenant_id, ne.triplet_key, hour)
        c24 = session.execute(select(func.coalesce(func.sum(TripletCount.count), 0)).where(
            TripletCount.tenant_id == tenant_id, TripletCount.triplet_key == ne.triplet_key,
            TripletCount.hour >= hour - timedelta(hours=24), TripletCount.hour <= hour)).scalar_one()
        chour_n = session.scalar(select(TripletCount.count).where(TripletCount.tenant_id == tenant_id, TripletCount.triplet_key == ne.triplet_key, TripletCount.hour == hour))
        dst24 = session.execute(select(func.count(func.distinct(Event.dst_ip))).where(
            Event.tenant_id == tenant_id, Event.src_ip == ne.src_ip, Event.event_time >= ne.event_time - timedelta(hours=24))).scalar_one() if ne.src_ip else 0
        ctx = Ctx(count_hour=chour_n or ne.count, count_24h=int(c24), distinct_dst_24h=int(dst24))

        orchestration: dict = {}
        if per["periodic"] and gate.G == 0:
            disposition = "filtered"
            reason = (f"Periodic low-risk noise: periode {per['period_hours']} jam, peak ratio {per['peak_ratio']}, "
                      f"PCC {per['pcc']} > {self.pcc}; risk gate tidak aktif (G=0)")
        else:
            orchestration = master.orchestrate(ne, evidence, gate, ctx, self.rules, self.reasoner, self.retain, self.flt, enr_status)
            disposition = orchestration["fusion"]["disposition"]
            reason = orchestration["fusion"]["reason"]
            if per["periodic"] and gate.G:
                reason = "Periodik TETAPI membawa bukti berisiko (risk gate) -> dianalisis, tidak dibuang. " + reason

        score = self.risk.score(ScoreInput(
            tactic=ne.tactic, evidence=evidence, src_ip=ne.src_ip, same_triplet_24h=max(0, int(c24) - ne.count),
            killchain_progression=kc, evasion=ne.evasion or ne.tactic == "Defense Evasion",
            industry_campaign=self.s.env_industry_campaign, network_anomaly=self.s.env_network_anomaly,
            enrichment_status=enr_status, snapshot_id=snap.snapshot_id))
        score["killchain_path"] = kc_path
        score["policy_version"] = self.policy_version

        ev = Event(
            event_id=ne.event_id, tenant_id=tenant_id, source=source, source_event_id=ne.source_event_id,
            event_time=ne.event_time, received_at=ne.received_at, severity=ne.severity, attack_type=ne.attack_type,
            signature=ne.signature, src_ip=ne.src_ip, dst_ip=ne.dst_ip, dst_port=ne.dst_port, protocol=ne.protocol,
            host=ne.host, username=ne.username, entities=ne.entities, technique_id=ne.technique_id, tactic=ne.tactic,
            triplet_key=ne.triplet_key, message=ne.message, payload=ne.payload, processing_status="scored",
            analysis_status="pending" if disposition != "filtered" else "not_requested",
            disposition=disposition, disposition_reason=reason, noise_info=per, orchestration=orchestration,
            risk_score=score["R"], risk_level=score["level"], scoring_version=score["scoring_version"],
            score_components=score, graph_snapshot_id=snap.snapshot_id,
            integrity={**snap.summary(), "evidence": evidence.to_dict()}, enrichment_status=enr_status,
        )
        session.add(ev)
        session.add(Outbox(event_id=ev.event_id, kind="upsert_alert"))   # outbox dalam transaksi yang sama
        if disposition != "filtered":
            session.add(Analysis(event_id=ev.event_id, tenant_id=tenant_id, status="pending"))
        self._maybe_candidate(session, ev, ne, orchestration)
        session.flush()
        return ev, True

    def _maybe_candidate(self, session: Session, ev: Event, ne: NormalizedEvent, orch: dict):
        """Kandidat teknik baru -> antrean review analis (tidak menulis ke graph kanonis)."""
        if not orch or ne.technique_id and self.tactics.known(ne.technique_id):
            return
        b = orch.get("bert", {})
        if b.get("p_true", 0) >= 0.8 and ev.disposition == "retained":
            session.add(KBCandidate(tenant_id=ev.tenant_id, event_id=ev.event_id, confidence=b["p_true"],
                                    hypothesis=f"Alert '{ev.signature or ev.attack_type}' berprobabilitas true-alert tinggi tetapi tidak terpetakan ke teknik ATT&CK yang dikenal",
                                    evidence={"attack_type": ev.attack_type, "technique_id": ne.technique_id, "bert": b, "gate": orch.get("risk_gate")}))
