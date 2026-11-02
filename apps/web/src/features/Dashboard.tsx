import { useEffect, useState } from "react";
import { api } from "../api";
import { Level, Disp, fmt } from "../components/ui";

export default function Dashboard() {
  const [d, setD] = useState<any>(null); const [kb, setKb] = useState<any>(null); const [err, setErr] = useState("");
  useEffect(() => { api("/dashboard/summary").then(setD).catch((e) => setErr(e.message)); api("/kb/status").then(setKb).catch(() => {}); }, []);
  if (err) return <p className="err">{err}</p>;
  if (!d) return <p className="muted">Memuat…</p>;
  const disp = d.by_disposition || {}; const lv = d.by_level || {};
  const parts = [["retained", "dipertahankan"], ["manual_review", "review manual"], ["filtered", "noise difilter"]] as const;
  return (
    <>
      <h2>Ringkasan</h2>
      <section className="funnel">
        <div className="funnel-head"><span className="big">{d.total}</span> alert masuk
          <span className="muted"> · {(d.noise_reduction_rate * 100).toFixed(1)}% disisihkan sebagai noise periodik berisiko rendah</span></div>
        <div className="bar">{parts.map(([k]) => <i key={k} className={`seg dp-${k}`} style={{ flex: disp[k] || 0 }} title={`${k}: ${disp[k] || 0}`} />)}</div>
        <div className="legend">{parts.map(([k, l]) => <span key={k}><i className={`dot dp-${k}`} />{l} <b>{disp[k] || 0}</b></span>)}</div>
      </section>
      <div className="grid3">
        <section><h3>Tingkat risiko</h3>{["high", "medium", "low"].map((k) => <div className="row" key={k}><Level v={k} /><b>{lv[k] || 0}</b></div>)}</section>
        <section><h3>Analisis AI</h3>{Object.entries(d.by_analysis_status || {}).map(([k, v]) => <div className="row" key={k}><span>{k}</span><b>{v as number}</b></div>)}</section>
        <section><h3>Sistem</h3>
          <div className="row"><span>Outbox menunggu / gagal</span><b>{d.outbox_pending} / {d.outbox_failed}</b></div>
          <div className="row"><span>Knowledge base</span><b>{kb ? `${kb.items} item${kb.stale ? " · STALE" : ""}` : "–"}</b></div>
          <div className="row"><span>Versi KB</span><b>{kb?.version || "–"}</b></div>
        </section>
      </div>
      <h3>Alert berisiko tertinggi</h3>
      <table><thead><tr><th>Skor</th><th>Level</th><th>Waktu</th><th>Jenis</th><th>Sumber → Tujuan</th><th>Disposisi</th></tr></thead>
        <tbody>{d.top_alerts.map((a: any) => (
          <tr key={a.event_id} onClick={() => (location.hash = `#/alerts/${a.event_id}`)} className="click">
            <td className="num">{a.risk_score?.toFixed(1)}</td><td><Level v={a.risk_level} /></td><td>{fmt(a.event_time)}</td>
            <td>{a.attack_type}</td><td className="mono">{a.src_ip || "-"} → {a.dst_ip || "-"}</td><td><Disp v={a.disposition} /></td></tr>))}</tbody></table>
    </>
  );
}
