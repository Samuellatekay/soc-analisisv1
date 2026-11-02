"""Kebijakan cluster: skema tervalidasi (batas keamanan keras) + tanda tangan Ed25519.

Prinsip keamanan:
* Master TIDAK dapat menonaktifkan risk gate atau menurunkan perlindungan alert berisiko tinggi: tidak ada field untuk itu, dan field tak dikenal ditolak (extra=forbid).
* Setiap angka dibatasi rentang aman; kombinasi dicek silang (mis. ambang filter < ambang retain).
* Cluster hanya menerima kebijakan yang tanda tangannya valid (kunci publik Master), ditujukan untuk cluster itu, dan versinya lebih baru (anti-rollback/replay)."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, model_validator

TACTICS = {"Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
           "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact", "Unknown"}
CRITERIA = {"target_criticality", "attack_stage_hazard", "threat_intel_match", "attack_feasibility", "attack_persistence", "environmental"}


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoisePolicy(_M):
    pcc_threshold: float | None = Field(None, ge=0.75, le=0.99)
    fft_peak_ratio: float | None = Field(None, ge=2.0, le=10.0)
    fft_min_history_hours: int | None = Field(None, ge=24, le=168)


class FusionPolicy(_M):
    retain: float | None = Field(None, ge=0.50, le=0.90)
    filter: float | None = Field(None, ge=0.05, le=0.40)


class ScoringPolicy(_M):
    level_high_min: float | None = Field(None, ge=70, le=95)
    level_medium_min: float | None = Field(None, ge=40, le=80)
    criteria_weights: dict[str, float] | None = None
    tactic_policy_weight: dict[str, float] | None = None

    @model_validator(mode="after")
    def _check(self):
        if self.criteria_weights is not None:
            if set(self.criteria_weights) != CRITERIA:
                raise ValueError(f"criteria_weights harus memuat tepat {sorted(CRITERIA)}")
            if any(not (0.02 <= v <= 0.60) for v in self.criteria_weights.values()) or abs(sum(self.criteria_weights.values()) - 1.0) > 1e-6:
                raise ValueError("bobot kriteria harus di [0.02, 0.60] dan berjumlah 1")
        if self.tactic_policy_weight is not None:
            bad = [k for k, v in self.tactic_policy_weight.items() if (k != "default" and k not in TACTICS) or not 0 <= v <= 1]
            if bad:
                raise ValueError(f"tactic_policy_weight tidak valid: {bad}")
        return self


class EnrichmentPolicy(_M):
    timeout_seconds: float | None = Field(None, ge=0.5, le=10)
    cache_ttl_seconds: int | None = Field(None, ge=30, le=3600)


class Policy(_M):
    noise: NoisePolicy = NoisePolicy()
    fusion: FusionPolicy = FusionPolicy()
    scoring: ScoringPolicy = ScoringPolicy()
    enrichment: EnrichmentPolicy = EnrichmentPolicy()
    kb_stale_days: int | None = Field(None, ge=1, le=14)

    @model_validator(mode="after")
    def _cross(self):
        f, s = self.fusion, self.scoring
        if f.retain is not None and f.filter is not None and not f.filter < f.retain:
            raise ValueError("fusion.filter harus < fusion.retain")
        if s.level_high_min is not None and s.level_medium_min is not None and not s.level_medium_min < s.level_high_min:
            raise ValueError("level_medium_min harus < level_high_min")
        return self

    def overrides(self) -> dict:
        return self.model_dump(exclude_none=True, exclude_defaults=False) | {}


def validate_policy(d: dict) -> Policy:
    return Policy.model_validate(d)


def canonical(cluster_id: str, version: int, issued_at: str, policy: dict) -> bytes:
    return json.dumps({"cluster_id": cluster_id, "version": version, "issued_at": issued_at, "policy": policy}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def gen_keypair() -> tuple[str, str]:
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def sign(priv_b64: str, cluster_id: str, version: int, policy: dict, issued_at: str | None = None) -> dict:
    issued_at = issued_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sig = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64)).sign(canonical(cluster_id, version, issued_at, policy))
    return {"cluster_id": cluster_id, "version": version, "issued_at": issued_at, "policy": policy, "signature": base64.b64encode(sig).decode()}


class PolicyRejected(Exception):
    pass


def verify_bundle(bundle: dict, pub_b64: str, expect_cluster: str, applied_version: int) -> Policy:
    """Tanda tangan -> cluster tujuan -> versi lebih baru -> skema/batas keamanan. Gagal salah satu = ditolak (tidak diterapkan)."""
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
            base64.b64decode(bundle["signature"]), canonical(bundle["cluster_id"], bundle["version"], bundle["issued_at"], bundle["policy"]))
    except (InvalidSignature, KeyError, ValueError, TypeError) as e:
        raise PolicyRejected("tanda tangan tidak valid") from e
    if bundle["cluster_id"] != expect_cluster:
        raise PolicyRejected(f"kebijakan ditujukan untuk cluster lain ({bundle['cluster_id']})")
    if not isinstance(bundle["version"], int) or bundle["version"] <= applied_version:
        raise PolicyRejected(f"versi {bundle['version']} bukan lebih baru dari yang terpasang ({applied_version})")
    try:
        return validate_policy(bundle["policy"])
    except Exception as e:  # noqa: BLE001
        raise PolicyRejected(f"kebijakan melanggar batas keamanan: {str(e)[:200]}") from e
