"""Retriever knowledge base: Neo4j (Cypher berparameter, akses BACA) atau tabel kb_items (dev)."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from sqlalchemy import select

from services.common.config import Settings
from services.common.db import session_scope
from services.common.models import KBItem


@dataclass
class Doc:
    source_id: str
    kind: str
    text: str
    provenance: dict

    def to_dict(self):
        return asdict(self)


def _tech_doc(d: dict, it_source: str, version: str) -> Doc:
    return Doc(d["id"], "technique", f"{d['id']} {d['name']} (taktik: {', '.join(d.get('tactics', []))}). {d.get('description', '')}",
               {"source": it_source, "version": version})


class DBRetriever:
    def retrieve(self, technique_id: str | None, attack_type: str, tactic: str | None) -> list[Doc]:
        docs: list[Doc] = []
        with session_scope() as s:
            ids = [i for i in {technique_id, (technique_id or "").split(".")[0]} if i]
            for it in s.scalars(select(KBItem).where(KBItem.item_id.in_(ids), KBItem.kind == "technique")):
                docs.append(_tech_doc(it.data, it.source, it.version))
            pb = s.get(KBItem, f"playbook:{attack_type}")
            if pb:
                docs.append(Doc(pb.item_id, "playbook", f"{pb.data['title']}: " + "; ".join(pb.data["steps"]), {"source": pb.source, "version": pb.version}))
        return docs


class Neo4jRetriever:  # pragma: no cover - butuh server live
    """Skema yang diasumsikan: (:Technique {id,name,description})-[:IN_TACTIC]->(:Tactic {name}); (:Playbook {id,title,steps,attack_type}).
    Pastikan importer Neo4j Anda memakai skema yang sama (lihat services/kb_sync/importer.py::mirror_to_neo4j)."""
    Q_TECH = ("MATCH (t:Technique) WHERE t.id IN $ids OPTIONAL MATCH (t)-[:IN_TACTIC]->(ta:Tactic) "
              "RETURN t.id AS id, t.name AS name, t.description AS description, collect(ta.name) AS tactics, t.source AS source, t.version AS version")
    Q_PB = "MATCH (p:Playbook {attack_type:$at}) RETURN p.id AS id, p.title AS title, p.steps AS steps, p.source AS source, p.version AS version"

    def __init__(self, s: Settings):
        from neo4j import GraphDatabase
        self.driver = GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password))

    def retrieve(self, technique_id, attack_type, tactic) -> list[Doc]:
        ids = [i for i in {technique_id, (technique_id or "").split(".")[0]} if i]
        docs: list[Doc] = []
        with self.driver.session(default_access_mode="READ") as ses:
            for r in ses.run(self.Q_TECH, ids=ids):
                docs.append(_tech_doc({"id": r["id"], "name": r["name"], "tactics": r["tactics"], "description": r["description"] or ""}, r["source"] or "neo4j", r["version"] or ""))
            for r in ses.run(self.Q_PB, at=attack_type):
                docs.append(Doc(r["id"], "playbook", f"{r['title']}: " + "; ".join(r["steps"]), {"source": r["source"], "version": r["version"]}))
        return docs


def get_retriever(s: Settings):
    if s.neo4j_uri and s.neo4j_password:
        try:
            return Neo4jRetriever(s)
        except Exception:  # noqa: BLE001
            pass
    return DBRetriever()
