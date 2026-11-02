"""Gabungkan alert di database dengan label dari tiket/analis menjadi data latih.
  labels.csv: event_id,label   (0 = TRUE alert, 1 = FALSE POSITIVE)  — sumber label: tiket insiden, keputusan analis, audit sampling.
JANGAN melatih dari `disposition` buatan sistem sendiri (itu menyalin bias keputusan lama / label leakage)."""
import argparse
import csv
import json
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[1])]
from sqlalchemy import select  # noqa: E402

from services.common.db import session_scope  # noqa: E402
from services.common.models import Event  # noqa: E402
from services.engine.agents.bert import serialize_alert  # noqa: E402

ap = argparse.ArgumentParser(); ap.add_argument("--labels", required=True); ap.add_argument("--out", required=True); ap.add_argument("--tenant", default="default")
a = ap.parse_args()
labels = {r["event_id"]: int(r["label"]) for r in csv.DictReader(open(a.labels))}
n = 0
with session_scope() as db, open(a.out, "w") as f:
    for e in db.scalars(select(Event).where(Event.tenant_id == a.tenant, Event.event_id.in_(list(labels)))):
        f.write(json.dumps({"text": serialize_alert(e), "label": labels[e.event_id], "triplet": e.triplet_key, "time": e.event_time.timestamp()}) + "\n"); n += 1
print(f"{n} baris -> {a.out} ({len(labels) - n} event pada labels.csv tidak ditemukan)")
