"""Bukti progres kill-chain: tactic lebih lanjut muncul pada entitas yang sama dalam 24 jam."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from services.common.models import Event


def progression(session: Session, tenant_id: str, src_ip: str | None, dst_ip: str | None, tactic: str | None,
                event_time, order: list[str], window_hours: int = 24, exclude_event_id: str | None = None) -> tuple[bool, list[str]]:
    if not tactic or tactic not in order or not (src_ip or dst_ip):
        return False, []
    conds = []
    for ip in (src_ip, dst_ip):  # entitas yang sama boleh berganti peran (penyerang -> korban -> sumber exfil)
        if ip:
            conds += [Event.src_ip == ip, Event.dst_ip == ip]
    q = select(Event.tactic).where(
        Event.tenant_id == tenant_id, Event.tactic.is_not(None),
        Event.event_time >= event_time - timedelta(hours=window_hours), Event.event_time <= event_time,
        or_(*conds),
    )
    if exclude_event_id:
        q = q.where(Event.event_id != exclude_event_id)
    seen = {t for (t,) in session.execute(q).all() if t in order}
    cur = order.index(tactic)
    earlier = sorted((t for t in seen if order.index(t) < cur), key=order.index)
    return (len(earlier) > 0), earlier + [tactic] if earlier else []
