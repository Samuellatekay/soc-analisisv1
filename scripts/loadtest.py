"""Load test mode Orkestrasi: N proses worker engine <- Redis Streams (consumer group) -> PostgreSQL.
  DATABASE_URL=postgresql+psycopg://... REDIS_URL=redis://127.0.0.1:6379/0 python scripts/loadtest.py --events 20000 --workers 1,2,4 [--kill]
Mengukur: throughput drain, latensi antrean->commit (p50/p95/p99), dan memverifikasi: tanpa kehilangan, tanpa duplikasi, DLQ kosong,
penghitung triplet = jumlah count input. HASIL TERGANTUNG hardware/konfigurasi DB; jalankan di lingkungan target untuk angka bermakna."""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT)]


def gen(n: int, triplets: int):
    import numpy as np
    from services.common.util import utcnow
    rng = np.random.default_rng(3)
    start = utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(days=7)
    evs, total = [], 0
    for i in range(n):
        t = int(rng.integers(0, triplets)); c = int(rng.integers(1, 40)); total += c
        ts = start + timedelta(hours=i * 168 / n, seconds=int(rng.integers(0, 60)))
        evs.append({"id": f"lt-{i}", "timestamp": ts.isoformat() + "Z", "signature": "Scheduled scan monitoring probe" if t % 3 else "SSH brute force failed login",
                    "src_ip": f"10.0.4.{t % 250 + 1}" if t % 2 else f"203.0.113.{t % 250 + 1}", "dst_ip": ["10.0.1.10", "10.0.9.9", "10.0.3.15"][t % 3], "count": c})
    return evs, total


def reset():
    import redis
    from services.common.db import get_engine, init_db
    from services.common.models import Base
    Base.metadata.drop_all(get_engine()); init_db()
    r = redis.Redis.from_url(os.environ["REDIS_URL"]); r.flushdb()
    return r


def spawn(k, idle_ms):
    env = {**os.environ, "ENGINE_CLAIM_IDLE_MS": str(idle_ms), "PYTHONPATH": str(ROOT)}
    return subprocess.Popen([sys.executable, "-m", "services.engine.main"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT)


def count(table="events"):
    from sqlalchemy import text
    from services.common.db import get_engine
    with get_engine().connect() as c:
        return c.execute(text(f"select count(*) from {table}")).scalar_one()


def run(events, total_count, workers, kill=False, idle_ms=60000, timeout=600):
    import numpy as np
    from sqlalchemy import text
    from services.common.db import get_engine
    r = reset()
    from services.engine.consumers.queue import RedisStreamQueue
    q = RedisStreamQueue(r, consumer="producer")
    procs = [spawn(i, idle_ms) for i in range(workers)]
    time.sleep(4)                                              # worker siap (import + koneksi)
    t0 = time.time()
    pipe = r.pipeline(); now = time.time()
    for i, e in enumerate(events):
        e = {**e, "_pushed_at": now}
        pipe.xadd(q.stream, {"d": json.dumps({"raw": e, "source": "generic", "tenant_id": "lt"}), "attempts": 0})
        if i % 1000 == 999:
            pipe.execute()
    pipe.execute()
    pushed = time.time() - t0
    killed = False
    deadline = t0 + timeout
    while time.time() < deadline:
        n = count()
        if kill and not killed and n >= len(events) * 0.3 and len(procs) > 1:
            os.kill(procs[0].pid, signal.SIGKILL); killed = True; print(f"   [kill -9] worker 0 dimatikan pada {n} event")
        if n >= len(events):
            break
        time.sleep(0.25)
    t1 = time.time()
    for p in procs:
        p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
    with get_engine().connect() as c:
        n = c.execute(text("select count(*) from events")).scalar_one()
        uniq = c.execute(text("select count(distinct source_event_id) from events")).scalar_one()
        tc = c.execute(text("select coalesce(sum(count),0) from triplet_counts")).scalar_one()
        ob = c.execute(text("select count(*) from outbox")).scalar_one()
        lat = np.array([float(x) * 1000 for (x,) in c.execute(text(
            "select extract(epoch from o.created_at) - (e.payload->>'_pushed_at')::float from outbox o join events e on e.event_id=o.event_id"))])
    # created_at disimpan naive-UTC; waktu epoch PostgreSQL 'extract(epoch from timestamp)' diperlakukan sebagai UTC -> konsisten dengan time.time()
    lag = q.lag()
    ok = n == len(events) and uniq == len(events) and int(tc) == total_count and ob == len(events) and lag["dlq"] == 0 and lag["pending"] == 0
    return {"workers": workers, "events": len(events), "done": int(n), "seconds": round(t1 - t0, 1), "eps": round(n / (t1 - t0)), "push_s": round(pushed, 1),
            "lat_ms": {"p50": round(float(np.percentile(lat, 50))), "p95": round(float(np.percentile(lat, 95))), "p99": round(float(np.percentile(lat, 99)))} if len(lat) else None,
            "unique": int(uniq), "triplet_sum_ok": int(tc) == total_count, "outbox": int(ob), "dlq": lag["dlq"], "pending": lag["pending"], "killed": killed, "PASS": ok}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=20000); ap.add_argument("--triplets", type=int, default=200)
    ap.add_argument("--workers", default="1,2,4"); ap.add_argument("--kill", action="store_true"); ap.add_argument("--idle-ms", type=int, default=3000)
    a = ap.parse_args()
    for k in ("DATABASE_URL", "REDIS_URL"):
        if not os.environ.get(k):
            raise SystemExit(f"{k} wajib")
    evs, total = gen(a.events, a.triplets)
    for w in [int(x) for x in a.workers.split(",")]:
        print(json.dumps(run(evs, total, w, kill=False)))
    if a.kill:
        print("kill-test:", json.dumps(run(evs, total, max(3, int(a.workers.split(",")[-1])), kill=True, idle_ms=a.idle_ms)))
