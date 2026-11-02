import { useEffect, useState } from "react";
import { api } from "../../api";
import type { Me } from "../../App";
import { fmt, Mono, Empty } from "../../components/ui";

export default function Cases({ me, openId }: { me: Me; openId?: string }) {
  const [list, setList] = useState<any[]>([]); const [cur, setCur] = useState<any>(null); const [note, setNote] = useState(""); const [err, setErr] = useState("");
  const loadList = () => api("/cases").then(setList).catch((e) => setErr(e.message));
  const loadCur = (id: string) => api(`/cases/${id}`).then(setCur).catch((e) => setErr(e.message));
  useEffect(() => { loadList(); }, []);
  useEffect(() => { if (openId) loadCur(openId); else setCur(null); }, [openId]);
  const canEdit = me.role !== "viewer";
  const act = async (fn: () => Promise<any>) => { try { setErr(""); await fn(); await loadList(); if (cur) await loadCur(cur.case_id); } catch (e: any) { setErr(e.message); } };
  const STEPS = ["New", "Triage", "Investigating", "Resolved", "Closed"];
  return (
    <div className="split">
      <div>
        <h2>Case</h2>
        {err && <p className="err">{err}</p>}
        {list.length === 0 ? <Empty>Belum ada case. Buat dari halaman detail alert.</Empty> : list.map((c) => (
          <a key={c.case_id} href={`#/cases/${c.case_id}`} className={`case ${cur?.case_id === c.case_id ? "on" : ""}`}>
            <b>{c.title}</b><span className="muted">{c.status} · {c.priority} · {c.event_ids.length} alert · {fmt(c.updated_at)}</span></a>))}
      </div>
      <div>{cur ? <>
        <h2>{cur.title}</h2>
        <div className="steps">{STEPS.map((s) => <span key={s} className={s === cur.status ? "on" : STEPS.indexOf(s) < STEPS.indexOf(cur.status) ? "done" : ""}>{s}</span>)}</div>
        {canEdit && <div className="actions">{cur.allowed_transitions.map((t: string) => <button key={t} onClick={() => act(() => api(`/cases/${cur.case_id}`, { method: "PATCH", body: { status: t } }))}>→ {t}</button>)}</div>}
        <p className="muted">dibuat oleh {cur.created_by} · assignee: {cur.assignee || "–"}</p>
        {canEdit && !cur.assignee && <button onClick={() => act(() => api(`/cases/${cur.case_id}`, { method: "PATCH", body: { assignee: me.name } }))}>Ambil case</button>}
        <h3>Alert terkait</h3>{cur.event_ids.length === 0 ? <Empty>Belum ada.</Empty> : <ul>{cur.event_ids.map((e: string) => <li key={e}><a href={`#/alerts/${e}`}><Mono>{e}</Mono></a>
          {canEdit && <button className="x" onClick={() => act(() => api(`/cases/${cur.case_id}/alerts/${e}`, { method: "DELETE" }))}>lepas</button>}</li>)}</ul>}
        <h3>Catatan</h3>{cur.notes.map((n: any, i: number) => <p key={i} className="note"><span className="muted">{n.author} · {fmt(n.created_at)}</span><br />{n.text}</p>)}
        {canEdit && <div className="actions"><input value={note} placeholder="tambah catatan…" onChange={(e) => setNote(e.target.value)} />
          <button disabled={!note.trim()} onClick={() => act(async () => { await api(`/cases/${cur.case_id}/notes`, { method: "POST", body: { text: note } }); setNote(""); })}>Simpan</button></div>}
        <h3>Riwayat (audit)</h3><ul className="muted">{cur.history.map((h: any, i: number) => <li key={i}>{fmt(h.ts)} · {h.actor} · {h.action} {Object.keys(h.detail || {}).length ? JSON.stringify(h.detail) : ""}</li>)}</ul>
      </> : <Empty>Pilih case di kiri.</Empty>}</div>
    </div>
  );
}
