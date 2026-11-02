import { useEffect, useState } from "react";
import { api } from "../api";
import type { Me } from "../App";
import { Empty, fmt } from "../components/ui";

const LABEL: Record<string, string> = { splunk_es: "Splunk ES", sentinel: "Microsoft Sentinel", qradar: "IBM QRadar", crowdstrike: "CrowdStrike Falcon",
  sentinelone: "SentinelOne", defender: "Microsoft Defender", cortex_xdr: "Cortex XDR", elasticsearch: "Elasticsearch / Wazuh" };

export default function Connectors({ me }: { me: Me }) {
  const [list, setList] = useState<any[] | null>(null); const [msg, setMsg] = useState<Record<string, string>>({}); const [err, setErr] = useState("");
  const load = () => api("/connectors").then(setList).catch((e) => setErr(e.message));
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, []);
  const test = async (name: string) => {
    setMsg({ ...msg, [name]: "menguji…" });
    const r = await api(`/connectors/${name}/test`, { method: "POST" }).catch((e) => ({ ok: false, error: e.message }));
    setMsg((m) => ({ ...m, [name]: r.ok ? `OK (${r.sample_count} event contoh)` : `GAGAL: ${r.error}` }));
  };
  const health = (c: any) => !c.enabled ? "off" : !c.state ? "wait" : c.state.consecutive_failures > 0 ? "bad" : "ok";
  return (
    <>
      <h2>Konektor</h2>
      <p className="muted">Sumber alert yang di-poll. Cursor hanya maju setelah event diterima pipeline. Konfigurasi di <code>infra/config/connectors.json</code>; credential lewat env/secret, tidak ditampilkan di sini.</p>
      {err && <p className="err">{err}</p>}
      {!list ? <p className="muted">Memuat…</p> : list.length === 0 ? <Empty>Belum ada konektor. Salin <code>connectors.example.json</code> menjadi <code>connectors.json</code>.</Empty> : (
        <table><thead><tr><th>Status</th><th>Nama</th><th>Produk</th><th>Sukses terakhir</th><th>Event / ditolak</th><th>Catatan</th><th></th></tr></thead>
          <tbody>{list.map((c) => (
            <tr key={c.name}><td><span className={`hl hl-${health(c)}`}>{{ off: "nonaktif", wait: "menunggu", bad: "bermasalah", ok: "sehat" }[health(c)]}</span></td>
              <td><b>{c.name}</b><br /><span className="muted">tiap {c.poll_seconds}s</span></td><td>{LABEL[c.type] || c.type}</td>
              <td>{c.state?.last_success ? `${fmt(c.state.last_success)} (${c.state.seconds_since_success}s lalu)` : "–"}</td>
              <td className="num">{c.state ? `${c.state.events_total} / ${c.state.rejected_total}` : "–"}</td>
              <td className="muted">{c.state?.last_error ? <span className="err">{c.state.last_error}</span> : c.state?.last_warning || ""}{msg[c.name] ? <><br />{msg[c.name]}</> : ""}</td>
              <td>{me.role === "admin" && <button onClick={() => test(c.name)}>Uji koneksi</button>}</td></tr>))}</tbody></table>)}
    </>
  );
}
