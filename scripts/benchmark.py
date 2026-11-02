"""Ukur kinerja pipeline fast path (normalize -> enrich -> integrity -> gate -> FFT-PCC -> AHP -> commit).
   python scripts/benchmark.py --events 2000 --triplets 50
Hasil bergantung pada hardware & database (SQLite lokal != PostgreSQL produksi). Gunakan sebagai pembanding relatif."""
import argparse
import os
import statistics
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[1])]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=2000); ap.add_argument("--triplets", type=int, default=50); ap.add_argument("--batch", type=int, default=100)
    a = ap.parse_args()
    os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/bench.db"
    import numpy as np
    from services.common.db import init_db, session_scope
    from services.common.util import utcnow
    from services.engine.pipeline import Pipeline
    init_db()
    p = Pipeline()
    rng = np.random.default_rng(1)
    start = utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(days=7)
    evs = []
    for i in range(a.events):  # urut waktu; sebagian triplet punya riwayat 7 hari -> FFT-PCC ikut terhitung
        t = int(rng.integers(0, a.triplets))
        ts = start + timedelta(hours=i * 168 / a.events, seconds=int(rng.integers(0, 60)))
        evs.append({"id": f"b{i}", "timestamp": ts.isoformat() + "Z", "signature": "Scheduled scan monitoring probe" if t % 3 else "SSH brute force failed login",
                    "src_ip": f"10.0.4.{t % 250 + 1}" if t % 2 else f"203.0.113.{t % 250 + 1}", "dst_ip": ["10.0.1.10", "10.0.9.9", "10.0.3.15"][t % 3], "count": int(rng.integers(1, 50))})
    lat, t0 = [], time.perf_counter()
    for i in range(0, len(evs), a.batch):
        with session_scope() as s:
            for e in evs[i:i + a.batch]:
                t1 = time.perf_counter()
                p.process(s, e, "generic", "bench")
                lat.append((time.perf_counter() - t1) * 1000)
    dt = time.perf_counter() - t0
    lat.sort()
    print(f"{a.events} event / {dt:.1f}s = {a.events / dt:.0f} event/s | per-event ms: p50={lat[len(lat)//2]:.1f} p95={lat[int(len(lat)*.95)]:.1f} p99={lat[int(len(lat)*.99)]:.1f} max={lat[-1]:.1f}")


if __name__ == "__main__":
    main()
