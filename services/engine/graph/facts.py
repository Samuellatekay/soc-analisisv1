"""Model fakta graph (kandidat) sebelum diverifikasi integritas semantiknya."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Fact:
    subj_type: str          # Asset | IOC | CVE | APT | Technique
    subj_id: str
    pred: str               # has_vulnerability | verdict | attributed_to | criticality | sensitivity | exposure | role
    obj_type: str | None    # None => literal
    obj_id: str | None
    value: str | None       # nilai literal (mis. 'malicious', 'core')
    source: str | None
    acquired_at: datetime | None
    updated_at: datetime | None
    confidence: float | None
    attrs: dict = field(default_factory=dict)

    @property
    def fact_id(self) -> str:
        raw = f"{self.subj_type}|{self.subj_id}|{self.pred}|{self.obj_type}|{self.obj_id}|{self.value}|{self.source}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "fact_id": self.fact_id, "subj": f"{self.subj_type}:{self.subj_id}", "pred": self.pred,
            "obj": f"{self.obj_type}:{self.obj_id}" if self.obj_type else self.value,
            "source": self.source, "confidence": self.confidence,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None, "attrs": self.attrs,
        }
