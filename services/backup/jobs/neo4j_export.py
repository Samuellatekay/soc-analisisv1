"""Export/restore LOGIS graf pengetahuan (Technique/Tactic/Playbook + relasi) sebagai JSON — berjalan online (tanpa mematikan Neo4j).
Dump fisik (`neo4j-admin database dump`) memerlukan database offline pada Community Edition: gunakan itu di level infrastruktur bila perlu.
Catatan: KB kanonis juga ada di tabel PostgreSQL `kb_items` (tercakup backup SQL) dan dapat dibangun ulang via kb_sync; export ini mempercepat pemulihan.
Neo4jStore BELUM diuji terhadap server Neo4j nyata; logika serialisasi/restore diuji dengan MemoryStore."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

KEYS = {"Technique": "id", "Playbook": "id", "Tactic": "name"}


class Store(Protocol):
    def nodes(self) -> list[dict]: ...      # {"label","props"}
    def rels(self) -> list[dict]: ...       # {"type","from":{"label","key"},"to":{"label","key"}}
    def merge_node(self, label: str, props: dict) -> None: ...
    def merge_rel(self, rtype: str, frm: dict, to: dict) -> None: ...


class MemoryStore:
    def __init__(self):
        self._n: dict[tuple, dict] = {}
        self._r: set[tuple] = set()

    def nodes(self):
        return [{"label": k[0], "props": dict(v)} for k, v in self._n.items()]

    def rels(self):
        return [{"type": t, "from": {"label": a[0], "key": a[1]}, "to": {"label": b[0], "key": b[1]}} for t, a, b in sorted(self._r)]

    def merge_node(self, label, props):
        self._n[(label, props[KEYS[label]])] = dict(props)

    def merge_rel(self, rtype, frm, to):
        self._r.add((rtype, (frm["label"], frm["key"]), (to["label"], to["key"])))


class Neo4jStore:  # pragma: no cover - butuh server live
    def __init__(self, uri: str, user: str, password: str):
        from neo4j import GraphDatabase
        self.d = GraphDatabase.driver(uri, auth=(user, password))

    def nodes(self):
        out = []
        with self.d.session(default_access_mode="READ") as s:
            for label in KEYS:   # label dari allowlist (bukan input pengguna) -> aman diinterpolasi
                for r in s.run(f"MATCH (n:{label}) RETURN properties(n) AS p"):
                    out.append({"label": label, "props": dict(r["p"])})
        return out

    def rels(self):
        out = []
        with self.d.session(default_access_mode="READ") as s:
            for r in s.run("MATCH (a)-[r]->(b) WHERE (a:Technique OR a:Playbook OR a:Tactic) AND (b:Technique OR b:Playbook OR b:Tactic) "
                           "RETURN type(r) AS t, labels(a)[0] AS al, a.id AS aid, a.name AS an, labels(b)[0] AS bl, b.id AS bid, b.name AS bn"):
                out.append({"type": r["t"], "from": {"label": r["al"], "key": r["aid"] or r["an"]}, "to": {"label": r["bl"], "key": r["bid"] or r["bn"]}})
        return out

    def merge_node(self, label, props):
        assert label in KEYS
        with self.d.session() as s:
            s.run(f"MERGE (n:{label} {{{KEYS[label]}: $k}}) SET n += $p", k=props[KEYS[label]], p=props)

    def merge_rel(self, rtype, frm, to):
        assert frm["label"] in KEYS and to["label"] in KEYS and rtype.replace("_", "").isalnum() and rtype.upper() == rtype
        with self.d.session() as s:
            s.run(f"MATCH (a:{frm['label']} {{{KEYS[frm['label']]}: $a}}), (b:{to['label']} {{{KEYS[to['label']]}: $b}}) MERGE (a)-[:{rtype}]->(b)", a=frm["key"], b=to["key"])


def export(store: Store, out_dir: Path) -> Path:
    nodes, rels = store.nodes(), store.rels()
    if not nodes:
        raise RuntimeError("graf kosong: tidak ada yang di-export (periksa koneksi/skema)")
    out_dir.mkdir(parents=True, exist_ok=True)
    dst = out_dir / f"neo4j-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.kg.json"
    dst.write_text(json.dumps({"format": "soc-kg-v1", "nodes": sorted(nodes, key=lambda n: (n["label"], str(n["props"].get(KEYS[n["label"]])))), "rels": rels}, ensure_ascii=False))
    return dst


def restore(store: Store, src: Path) -> dict:
    d = json.loads(src.read_text())
    if d.get("format") != "soc-kg-v1":
        raise RuntimeError("format export graf tidak dikenal")
    for n in d["nodes"]:
        if n["label"] not in KEYS or KEYS[n["label"]] not in n["props"]:
            raise RuntimeError(f"node tidak valid: {n['label']}")
        store.merge_node(n["label"], n["props"])          # MERGE: idempoten, aman dijalankan ulang
    for r in d["rels"]:
        store.merge_rel(r["type"], r["from"], r["to"])
    return {"nodes": len(d["nodes"]), "rels": len(d["rels"])}
