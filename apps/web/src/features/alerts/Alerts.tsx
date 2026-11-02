import { useEffect, useState } from "react";
import { api } from "../../api";
import { Level, Disp, fmt, Empty } from "../../components/ui";

export default function Alerts() {
  const [f, setF] = useState({ q: "", risk_level: "", disposition: "", analysis_status: "", sort: "event_time", order: "desc", include_filtered: false });
  const [page, setPage] = useState(1); const [data, setData] = useState<any>(null); const [err, setErr] = useState("");
  const load = () => {
    const p = new URLSearchParams({ page: String(page), page_size: "25", sort: f.sort, order: f.order, include_filtered: String(f.include_filtered) });
    (["q", "risk_level", "disposition", "analysis_status"] as const).forEach((k) => f[k] && p.set(k, f[k]));
    api(`/alerts?${p}`).then(setData).catch((e) => setErr(e.message));
  };
  useEffect(load, [page, f.risk_level, f.disposition, f.analysis_status, f.sort, f.order, f.include_filtered]);
  const set = (k: string, v: any) => { setPage(1); setF({ ...f, [k]: v }); };
  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;
  return (
    <>
      <h2>Alert</h2>
      <div className="filters">
        <input placeholder="event_id, IP, host, teknik (T1110), teks…" value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} onKeyDown={(e) => e.key === "Enter" && (setPage(1), load())} />
        <select value={f.risk_level} onChange={(e) => set("risk_level", e.target.value)}><option value="">semua level</option><option value="high">tinggi</option><option value="medium">sedang</option><option value="low">rendah</option></select>
        <select value={f.disposition} onChange={(e) => set("disposition", e.target.value)}><option value="">disposisi (tanpa noise)</option><option value="retained">dipertahankan</option><option value="manual_review">review manual</option><option value="filtered">difilter</option></select>
        <select value={f.analysis_status} onChange={(e) => set("analysis_status", e.target.value)}><option value="">status analisis</option><option value="pending">pending</option><option value="completed">completed</option><option value="failed">failed</option><option value="insufficient_evidence">bukti kurang</option></select>
        <select value={f.sort + ":" + f.order} onChange={(e) => { const [s, o] = e.target.value.split(":"); setPage(1); setF({ ...f, sort: s, order: o }); }}>
          <option value="event_time:desc">terbaru</option><option value="risk_score:desc">skor tertinggi</option><option value="risk_score:asc">skor terendah</option></select>
        <button onClick={() => { setPage(1); load(); }}>Cari</button>
      </div>
      {err && <p className="err">{err}</p>}
      {!data ? <p className="muted">Memuat…</p> : data.items.length === 0 ? <Empty>Tidak ada alert yang cocok. Kirim data lewat <code>scripts/generate_demo_data.py</code>.</Empty> : (
        <table><thead><tr><th>Skor</th><th>Level</th><th>Waktu (UTC)</th><th>Jenis</th><th>Teknik</th><th>Sumber → Tujuan</th><th>Disposisi</th><th>AI</th></tr></thead>
          <tbody>{data.items.map((a: any) => (
            <tr key={a.event_id} className="click" onClick={() => (location.hash = `#/alerts/${a.event_id}`)}>
              <td className="num">{a.risk_score?.toFixed(1)}</td><td><Level v={a.risk_level} /></td><td>{fmt(a.event_time)}</td><td>{a.attack_type}</td>
              <td className="mono">{a.technique_id || "-"}</td><td className="mono">{a.src_ip || "-"} → {a.dst_ip || a.host || "-"}</td><td><Disp v={a.disposition} /></td><td>{a.analysis_status}</td></tr>))}</tbody></table>)}
      <div className="pager"><button disabled={page <= 1} onClick={() => setPage(page - 1)}>‹ Sebelumnya</button>
        <span>{data ? `${data.total} alert · hal ${page}/${pages}` : ""}</span><button disabled={page >= pages} onClick={() => setPage(page + 1)}>Berikutnya ›</button></div>
    </>
  );
}
