import { useEffect, useState } from "react";
import { api } from "../../api";
import type { Me } from "../../App";
import { Level, Disp, Mono, fmt } from "../../components/ui";

const CRIT: Record<string, string> = { target_criticality: "Kritikalitas target", attack_stage_hazard: "Bahaya fase serangan", threat_intel_match: "Kecocokan intelijen",
  attack_feasibility: "Kelayakan serangan", attack_persistence: "Persistensi serangan", environmental: "Situasi lingkungan" };
const COLORS = ["#2b6f77", "#b4472d", "#6b5b95", "#c28a1b", "#4f7d3a", "#7a828a"];

function Anatomy({ sc }: { sc: any }) {
  const rows = Object.entries<any>(sc.criteria).map(([k, c], i) => ({ k, c, part: 100 * c.W * c.C, max: 100 * c.W, color: COLORS[i] }));
  return (
    <section>
      <h3>Anatomi skor <span className="muted">R = {sc.R} (R_base {sc.R_base} × E_ext {sc.E_ext} × E_int {sc.E_int}) · {sc.scoring_version}</span></h3>
      <div className="anat">{rows.map((r) => <i key={r.k} style={{ width: `${r.part}%`, background: r.color }} title={`${CRIT[r.k]}: ${r.part.toFixed(1)}`} />)}<em style={{ left: "80%" }} title="batas Tinggi 80" /><em style={{ left: "60%" }} title="batas Sedang 60" /></div>
      <table className="slim"><thead><tr><th></th><th>Kriteria</th><th>W</th><th>C</th><th>Kontribusi</th><th>Sub-indikator (nilai mentah → v)</th></tr></thead><tbody>
        {rows.map((r) => (<tr key={r.k}><td><i className="dot" style={{ background: r.color }} /></td><td>{CRIT[r.k]}</td><td className="num">{r.c.W}</td><td className="num">{r.c.C}</td>
          <td className="num">{r.part.toFixed(1)} / {r.max.toFixed(0)}</td>
          <td className="muted">{Object.entries<any>(r.c.sub).map(([n, s]) => `${n}: ${String(s.raw)}→${s.v}`).join(" · ")}</td></tr>))}</tbody></table>
    </section>
  );
}

export default function AlertDetail({ id, me }: { id: string; me: Me }) {
  const [a, setA] = useState<any>(null); const [an, setAn] = useState<any>(null); const [err, setErr] = useState(""); const [cases, setCases] = useState<any[]>([]);
  const load = () => { api(`/alerts/${id}`).then(setA).catch((e) => setErr(e.message)); api(`/alerts/${id}/analysis`).then(setAn).catch(() => {}); };
  useEffect(() => { load(); api("/cases").then(setCases).catch(() => {}); }, [id]);
  if (err) return <p className="err">{err}</p>;
  if (!a) return <p className="muted">Memuat…</p>;
  const canEdit = me.role !== "viewer"; const o = a.orchestration || {}; const n = a.noise_info || {}; const integ = a.integrity || {};
  const newCase = async () => { const c = await api("/cases", { method: "POST", body: { title: `Investigasi: ${a.signature || a.attack_type} (${a.src_ip || "?"})`, priority: a.risk_level, event_ids: [id] } }); location.hash = `#/cases/${c.case_id}`; };
  return (
    <>
      <p><a href="#/alerts">‹ Semua alert</a></p>
      <h2>{a.signature || a.attack_type} <Level v={a.risk_level} /> <span className="score">{a.risk_score?.toFixed(1)}</span></h2>
      <p className="muted"><Mono>{a.event_id}</Mono> · {fmt(a.event_time)} UTC · {a.source} · {a.src_ip || "-"} → {a.dst_ip || a.host || "-"}{a.dst_port ? `:${a.dst_port}` : ""} · {a.technique_id || "tanpa teknik"} {a.tactic ? `(${a.tactic})` : ""}</p>
      <section><h3>Disposisi <Disp v={a.disposition} /></h3><p>{a.disposition_reason}</p>
        {n.reason && <p className="muted">FFT-PCC: {n.periodic ? `periodik (periode ${n.period_hours} jam, peak ratio ${n.peak_ratio}, PCC ${n.pcc})` : `bukan kandidat periodik (${n.reason})`}</p>}
        {canEdit && <div className="actions"><button className="primary" onClick={newCase}>Buat case dari alert ini</button>
          {cases.filter((c) => c.status !== "Closed").length > 0 && <select defaultValue="" onChange={async (e) => { if (e.target.value) { await api(`/cases/${e.target.value}/alerts`, { method: "POST", body: { event_id: id } }); location.hash = `#/cases/${e.target.value}`; } }}>
            <option value="">tautkan ke case…</option>{cases.filter((c) => c.status !== "Closed").map((c) => <option key={c.case_id} value={c.case_id}>{c.title}</option>)}</select>}</div>}
      </section>
      {a.score_components?.criteria && <Anatomy sc={a.score_components} />}
      {o.risk_gate && <section><h3>Risk gate & evidence orchestration</h3>
        <p>Gate <b>{o.risk_gate.G ? "AKTIF" : "tidak aktif"}</b> ({o.risk_gate.high_risk_indicator}){o.risk_gate.reasons?.length ? ": " + o.risk_gate.reasons.join("; ") : ""}</p>
        <table className="slim"><thead><tr><th>Cabang</th><th>y</th><th>c</th><th>Catatan</th></tr></thead><tbody>
          <tr><td>Knowledge retrieval</td><td>{o.knowledge.y}</td><td>{o.knowledge.c}</td><td className="muted">{o.knowledge.rule}: {o.knowledge.observed_count} vs ambang {o.knowledge.threshold}</td></tr>
          <tr><td>Association query</td><td>{o.query.y}</td><td>{o.query.c}</td><td className="muted">{o.query.plugins.map((p: any) => `${p.plugin}${p.ok ? "" : " (n/a)"}`).join(", ")}</td></tr>
          <tr><td>BERT reasoning</td><td>{o.bert.y}</td><td>{o.bert.c}</td><td className="muted">P(true)={o.bert.p_true} · {o.bert.model}</td></tr></tbody></table>
        <p className="muted">S_TA = {o.fusion.S_TA}{o.fusion.conflict ? " · terdeteksi konflik antar-cabang" : ""}</p></section>}
      <section><h3>Integritas graph <span className="muted">snapshot {a.graph_snapshot_id} · enrichment: {a.enrichment_status}</span></h3>
        <p>{integ.accepted ?? 0} fakta diterima, {integ.quarantined ?? 0} dikarantina.</p>
        {(integ.violations || []).length > 0 && <ul>{integ.violations.map((v: any, i: number) => <li key={i}><b>{v.rule}</b> — {v.detail}</li>)}</ul>}
        {integ.evidence && <pre>{JSON.stringify({ asset: integ.evidence.asset, ioc: integ.evidence.ioc, vuln: integ.evidence.vuln }, null, 1)}</pre>}</section>
      <section><h3>Analisis AI <span className="muted">{an?.status}{an?.model ? ` · ${an.model} · ${an.prompt_version}` : ""} · rekomendasi untuk analis, tidak mengubah skor</span></h3>
        {an?.status === "completed" ? <>
          <p>{an.result.summary}</p>
          {an.result.supporting_evidence?.length > 0 && <><b>Bukti pendukung</b><ul>{an.result.supporting_evidence.map((x: any, i: number) => <li key={i}>{x.claim} <Mono>[{x.source}]</Mono></li>)}</ul></>}
          {an.result.triage_recommendations?.length > 0 && <><b>Rekomendasi triase</b><ul>{an.result.triage_recommendations.map((x: any, i: number) => <li key={i}>{x.action} <Mono>[{x.source}]</Mono></li>)}</ul></>}
          {an.result._dropped_unsupported > 0 && <p className="muted">{an.result._dropped_unsupported} klaim dibuang karena mengutip sumber di luar bukti terambil.</p>}</>
          : <p className="muted">{an?.status === "insufficient_evidence" ? "Bukti knowledge base tidak cukup; tinjau manual." : an?.status === "failed" ? `Gagal: ${an.error}` : "Menunggu worker analisis…"}</p>}
        {canEdit && an && an.status !== "pending" && <button onClick={async () => { await api(`/alerts/${id}/analysis/retry`, { method: "POST" }); setTimeout(load, 1500); }}>Ulangi analisis</button>}</section>
      <section><h3>Payload (tersanitasi)</h3><pre>{JSON.stringify(a.payload, null, 1)}</pre></section>
    </>
  );
}
