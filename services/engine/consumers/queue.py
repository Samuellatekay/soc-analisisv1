"""Antrean event durable: Redis Streams + consumer groups (bukan Pub/Sub). Ack hanya SETELAH commit DB."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass


@dataclass
class Message:
    id: str
    data: dict


class RedisStreamQueue:
    def __init__(self, client, stream: str = "soc:events", group: str = "engine", consumer: str = "c1",
                 dlq: str = "soc:events:dlq", max_attempts: int = 3, maxlen: int = 1_000_000):
        self.r, self.stream, self.group, self.consumer, self.dlq = client, stream, group, consumer, dlq
        self.max_attempts, self.maxlen = max_attempts, maxlen
        try:
            self.r.xgroup_create(stream, group, id="0", mkstream=True)
        except Exception as e:  # noqa: BLE001  BUSYGROUP = sudah ada
            if "BUSYGROUP" not in str(e):
                raise

    def push(self, data: dict, attempts: int = 0) -> str:
        return self.r.xadd(self.stream, {"d": json.dumps(data, default=str), "attempts": attempts}, maxlen=self.maxlen, approximate=True)

    def read(self, count: int = 50, block_ms: int = 1000) -> list[Message]:
        res = self.r.xreadgroup(self.group, self.consumer, {self.stream: ">"}, count=count, block=block_ms)
        return self._parse(res)

    def claim_stale(self, min_idle_ms: int = 60_000, count: int = 50) -> list[Message]:
        """Ambil alih pesan pending milik consumer yang mati (recovery)."""
        try:
            _, msgs, *_ = self.r.xautoclaim(self.stream, self.group, self.consumer, min_idle_ms, "0-0", count=count)
        except Exception:  # noqa: BLE001
            return []
        return self._parse([(self.stream, msgs)])

    @staticmethod
    def _parse(res) -> list[Message]:
        out = []
        for _, items in res or []:
            for mid, f in items:
                f = {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v) for k, v in f.items()}
                if "d" in f:
                    out.append(Message(mid.decode() if isinstance(mid, bytes) else mid, {**json.loads(f["d"]), "_attempts": int(f.get("attempts", 0))}))
        return out

    def ack(self, mid: str):
        self.r.xack(self.stream, self.group, mid)
        self.r.xdel(self.stream, mid)

    def fail(self, msg: Message, error: str, permanent: bool = False):
        """Retry terbatas lalu DLQ. Pesan asli di-ack setelah salinan retry/DLQ tertulis."""
        data = {k: v for k, v in msg.data.items() if k != "_attempts"}
        att = msg.data.get("_attempts", 0) + 1
        if permanent or att >= self.max_attempts:
            self.r.xadd(self.dlq, {"d": json.dumps({**data, "_error": error[:500], "_failed_at": time.time()}, default=str)})
        else:
            self.push(data, attempts=att)
        self.ack(msg.id)

    def replay_dlq(self, limit: int = 100) -> int:
        n = 0
        for mid, f in self.r.xrange(self.dlq, count=limit):
            d = json.loads((f.get(b"d") or f.get("d")))
            d.pop("_error", None); d.pop("_failed_at", None)
            self.push(d)
            self.r.xdel(self.dlq, mid)
            n += 1
        return n

    def lag(self) -> dict:
        return {"length": self.r.xlen(self.stream), "dlq": self.r.xlen(self.dlq),
                "pending": (self.r.xpending(self.stream, self.group) or {}).get("pending", 0)}


def get_queue(redis_url: str, consumer: str = "c1", client=None) -> RedisStreamQueue | None:
    if client is None:
        if not redis_url:
            return None
        import redis
        client = redis.Redis.from_url(redis_url)
    return RedisStreamQueue(client, consumer=consumer)
