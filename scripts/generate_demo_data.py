"""Data sintetis (bukan data nyata) untuk demo: noise periodik, periodik-berisiko, rantai serangan, dan noise acak.

  python scripts/generate_demo_data.py                       # langsung ke database (tanpa server)
  python scripts/generate_demo_data.py --api http://localhost:8000 --key dev-ingest-key
"""
from __future__ import annotations

import argparse
import math
import sys
from datetime import timedelta
from pathlib import Path

import numpy as np

sys.path[:0] = [str(Path(__file__).resolve().parents[1])]
from services.common.util import utcnow  # noqa: E402


def build(days: int = 10, seed: int = 42) -> list[dict]:
    rng = np.random.default_rng(seed)
    end = utcnow().replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days)
    ev: list[dict] = []
    n = 0

    def add(ts, **kw):
        nonlocal n
        n += 1
        ev.append({"id": f"demo-{n}", "timestamp": ts.isoformat() + "Z", **kw})

    hours = days * 24
    for h in range(hours):
        ts = start + timedelta(hours=h, minutes=int(rng.integers(1, 55)))
        phase = 1 + 0.8 * math.sin(2 * math.pi * (h % 24 - 8) / 24)
        # 1) periodik berisiko rendah (probe monitoring internal -> lab terisolasi)
        add(ts, signature="Scheduled vulnerability scan monitoring probe", src_ip="10.0.4.30", dst_ip="10.0.9.9", dst_port=443,
            count=max(1, int(rng.poisson(25 * phase))), severity="low", attack_type="scanning")
        # 2) periodik rendah lain (policy misjudgment)
        add(ts + timedelta(minutes=1), signature="Policy: monitoring heartbeat health check", src_ip="10.0.4.30", dst_ip="10.0.3.15", dst_port=161,
            count=max(1, int(rng.poisson(30 * phase))), severity="low", attack_type="policy_violation")
        # 3) PERIODIK TETAPI BERISIKO: beaconing low-and-slow dari IOC ke aset core
        add(ts + timedelta(minutes=2), signature="Periodic outbound beacon C2 pattern", src_ip="198.51.100.77", dst_ip="10.0.1.10", dst_port=8443,
            count=max(1, int(rng.poisson(8 * phase))), severity="medium", attack_type="malware_comm")
    # 4) noise acak jarang
    for _ in range(25):
        ts = start + timedelta(minutes=int(rng.integers(0, hours * 60)))
        add(ts, signature=str(rng.choice(["Unauthorized USB policy", "Weak password policy", "Anomalous login time", "Port probe"])),
            src_ip=f"10.0.3.{int(rng.integers(10, 60))}", dst_ip="10.0.3.15", count=1, severity=str(rng.choice(["low", "medium"])))
    # 5) rantai serangan 203.0.113.45 (kill-chain) dalam 6 jam terakhir
    t0 = end - timedelta(hours=6)
    add(t0, signature="Network port scan nmap", src_ip="203.0.113.45", dst_ip="10.0.1.10", count=420, severity="medium", technique_id="T1595")
    add(t0 + timedelta(minutes=50), signature="Web attack: exploit CVE-2024-3400 remote code", src_ip="203.0.113.45", dst_ip="10.0.1.10", dst_port=443, count=14, severity="high", technique_id="T1190")
    add(t0 + timedelta(hours=1, minutes=40), signature="SSH brute force multiple failed login", src_ip="203.0.113.45", dst_ip="10.0.1.10", dst_port=22, count=465, severity="high")
    add(t0 + timedelta(hours=3), signature="Malware C2 beacon to DGA domain", src_ip="10.0.1.10", dst_ip="192.0.2.50", domain="evil-dga-x1.example", count=60, severity="high", technique_id="T1568.002")
    add(t0 + timedelta(hours=4), signature="Lateral movement via SSH from web host", src_ip="10.0.1.10", dst_ip="10.0.2.5", dst_port=22, count=9, severity="high", technique_id="T1021.004")
    add(t0 + timedelta(hours=5, minutes=20), signature="Large data exfiltration over C2 channel", src_ip="10.0.1.20", dst_ip="203.0.113.45", count=3, severity="critical", technique_id="T1041")
    ev.sort(key=lambda e: e["timestamp"])
    return ev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api"); ap.add_argument("--key", default="dev-ingest-key"); ap.add_argument("--days", type=int, default=10)
    a = ap.parse_args()
    events = build(a.days)
    if a.api:
        import httpx
        tot = {"accepted": 0, "duplicates": 0, "rejected": 0}
        for i in range(0, len(events), 200):
            r = httpx.post(f"{a.api}/api/v1/ingest/generic", json={"events": events[i:i + 200]}, headers={"X-Ingest-Key": a.key}, timeout=120)
            r.raise_for_status(); j = r.json()
            tot["accepted"] += j["accepted"]; tot["duplicates"] += j["duplicates"]; tot["rejected"] += len(j["rejected"])
        print(tot)
    else:
        from services.common.db import init_db, session_scope
        from services.engine.pipeline import Pipeline
        init_db(); p = Pipeline(); c = 0
        with session_scope() as s:
            for e in events:
                p.process(s, e, "generic", "default"); c += 1
        print(f"{c} event diproses langsung ke database")


if __name__ == "__main__":
    main()
