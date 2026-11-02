from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

CaseStatus = Literal["New", "Triage", "Investigating", "Resolved", "Closed"]


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=256)
    description: str = ""
    priority: Literal["low", "medium", "high"] = "medium"
    assignee: str | None = None
    event_ids: list[str] = []


class CasePatch(BaseModel):
    title: str | None = Field(None, min_length=3, max_length=256)
    description: str | None = None
    priority: Literal["low", "medium", "high"] | None = None
    assignee: str | None = None
    status: CaseStatus | None = None


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


class LinkIn(BaseModel):
    event_id: str


class CandidateReview(BaseModel):
    decision: Literal["approved", "rejected"]
    technique_id: str | None = None
    name: str | None = None
    tactic: str | None = None


class IngestBatch(BaseModel):
    events: list[dict[str, Any]] = Field(max_length=500)
