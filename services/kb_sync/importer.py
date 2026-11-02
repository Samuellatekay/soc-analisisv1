"""Importer KB: validasi -> diff checksum -> upsert idempoten -> catat run + snapshot rollback -> (opsional) cermin ke Neo4j."""
from __future__ import annotations

import hashlib
import json
import re
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.common.config import Settings
from services.common.models import KBItem, KBRun
from services.common.util import utcnow

TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _checksum(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def validate(item: dict) -> str | None:
    if not item.get("item_id") or item.get("kind") not in ("technique", "playbook"):
        return "item_id/kind tidak valid"
    d = item.get("data") or {}
    tenants = d.get("tenant_ids")
    if tenants is not None and (not isinstance(tenants, list) or not tenants or
                                any(not isinstance(tenant, str) or not tenant.strip() for tenant in tenants)):
        return "tenant_ids harus berupa daftar tenant yang tidak kosong"
    if item["kind"] == "technique":
        if not TECH_RE.match(item["item_id"]):
            return f"ID teknik tidak valid {item['item_id']}"
        if not d.get("name") or not d.get("tactics"):
            return "name/tactics wajib"
    else:
        if not d.get("steps"):
            return "steps wajib"
    return None


def import_items(session: Session, items: list[dict], source: str, version: str, settings: Settings | None = None) -> KBRun:
    run = KBRun(source=source, version=version, status="running")
    session.add(run)
    session.flush()
    try:
        bad = [(i.get("item_id"), validate(i)) for i in items if validate(i)]
        if bad and len(bad) > max(5, len(items) * 0.02):  # terlalu banyak invalid -> tolak seluruh rilis
            raise ValueError(f"{len(bad)} item invalid, contoh: {bad[:3]}")
        valid = [i for i in items if not validate(i)]
        existing = {it.item_id: it for it in session.scalars(select(KBItem).where(KBItem.item_id.in_([i['item_id'] for i in valid])))} if len(valid) < 500 else {it.item_id: it for it in session.scalars(select(KBItem))}
        snapshot, add, upd, same = [], 0, 0, 0
        for i in valid:
            cs = _checksum(i["data"])
            cur = existing.get(i["item_id"])
            if cur is None:
                session.add(KBItem(item_id=i["item_id"], kind=i["kind"], data=i["data"], source=source, version=version, checksum=cs))
                snapshot.append({"item_id": i["item_id"], "prev": None})
                add += 1
            elif cur.checksum != cs:
                snapshot.append({"item_id": cur.item_id, "prev": {"kind": cur.kind, "data": cur.data, "source": cur.source, "version": cur.version, "checksum": cur.checksum}})
                cur.data, cur.source, cur.version, cur.checksum, cur.updated_at = i["data"], source, version, cs, utcnow()
                upd += 1
            else:
                cur.version = version
                cur.updated_at = utcnow()
                same += 1
        run.added, run.updated, run.unchanged, run.previous_snapshot = add, upd, same, snapshot
        run.status, run.finished_at = "success", utcnow()
        if settings and settings.neo4j_uri and settings.neo4j_password:
            mirror_to_neo4j(settings, valid, source, version)
    except Exception as e:  # noqa: BLE001
        run.status, run.error, run.finished_at = "failed", str(e)[:1000], utcnow()
    session.flush()
    return run


def rollback(session: Session, run_id: int) -> int:
    run = session.get(KBRun, run_id)
    n = 0
    for sn in run.previous_snapshot or []:
        it = session.get(KBItem, sn["item_id"])
        if sn["prev"] is None and it:
            session.delete(it)
        elif sn["prev"] and it:
            it.kind, it.data, it.source, it.version, it.checksum = (sn["prev"][k] for k in ("kind", "data", "source", "version", "checksum"))
        n += 1
    run.status = "rolled_back"
    return n


def mirror_to_neo4j(s: Settings, items: list[dict], source: str, version: str) -> None:  # pragma: no cover - butuh server live
    from neo4j import GraphDatabase
    with GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password)) as drv, drv.session() as ses:
        for i in items:
            d = i["data"]
            access_tenants = d.get("tenant_ids", ["*"])
            if i["kind"] == "technique":
                ses.run("MERGE (t:Technique {id:$id}) SET t.name=$name, t.description=$desc, t.source=$src, t.version=$ver, "
                        "t.access_tenants=$tenants, t.updated_at_epoch=$updated",
                        id=d["id"], name=d["name"], desc=d.get("description", ""), src=source, ver=version,
                        tenants=access_tenants, updated=time.time())
                for tac in d["tactics"]:
                    ses.run("MATCH (t:Technique {id:$id}) MERGE (ta:Tactic {name:$tac}) MERGE (t)-[:IN_TACTIC]->(ta)", id=d["id"], tac=tac)
            else:
                ses.run("MERGE (p:Playbook {id:$id}) SET p.title=$title, p.steps=$steps, p.attack_type=$at, p.source=$src, "
                        "p.version=$ver, p.access_tenants=$tenants, p.updated_at_epoch=$updated",
                        id=d["id"], title=d["title"], steps=d["steps"], at=d["attack_type"], src=source, ver=version,
                        tenants=access_tenants, updated=time.time())
