"""Listener syslog CEF/LEEF (UDP + TCP newline-framed). Hanya untuk produk yang BENAR-BENAR mengirim CEF/LEEF
(mis. QRadar DSM, ArcSight, banyak firewall). Tidak ada TLS/RFC6587 octet-counting di sini: letakkan di belakang relay TLS (rsyslog/syslog-ng).
  python -m services.engine.adapters.syslog_listener --host 0.0.0.0 --port 5514 --tenant default"""
from __future__ import annotations

import argparse
import asyncio
import logging
from typing import Callable

from services.common.util import utcnow

log = logging.getLogger("syslog")


class Listener:
    def __init__(self, handle: Callable[[dict], None], max_line: int = 8192):
        self.handle, self.max_line = handle, max_line

    def feed(self, data: bytes):
        line = data.decode("utf-8", "replace").strip()[: self.max_line]
        if "CEF:" in line or "LEEF:" in line:
            self.handle({"line": line, "received": utcnow().isoformat() + "Z"})

    def datagram(self):
        outer = self

        class P(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                outer.feed(data)
        return P()

    async def tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while not reader.at_eof():
                try:
                    self.feed(await asyncio.wait_for(reader.readline(), 60))
                except (asyncio.TimeoutError, ValueError):
                    break
        finally:
            writer.close()


async def serve(host: str, port: int, handle: Callable[[dict], None]):
    ls = Listener(handle)
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(ls.datagram, local_addr=(host, port))
    srv = await asyncio.start_server(ls.tcp, host, port, limit=ls.max_line * 2)
    log.info("syslog CEF/LEEF mendengarkan %s:%s (udp+tcp)", host, port)
    async with srv:
        await srv.serve_forever()


def main():
    logging.basicConfig(level=logging.INFO)
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=5514); ap.add_argument("--tenant", default="default")
    a = ap.parse_args()
    from services.common.config import get_settings
    from services.common.db import init_db
    from services.engine.adapters.runner import default_sink
    init_db()
    sink = default_sink(get_settings())

    def handle(raw: dict):
        acc, dup, rej = sink([raw], "syslog:cef", a.tenant)
        if rej:
            log.warning("baris ditolak: %s", rej[0])
    asyncio.run(serve(a.host, a.port, handle))


if __name__ == "__main__":
    main()
