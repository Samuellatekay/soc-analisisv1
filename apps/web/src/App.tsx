import { useEffect, useState } from "react";
import { api, getToken, setToken } from "./api";
import { handleCallback, loadAuthConfig, logout, startLogin } from "./auth";
import type { AuthCfg } from "./pkce";
import Dashboard from "./features/Dashboard";
import Alerts from "./features/alerts/Alerts";
import AlertDetail from "./features/alerts/AlertDetail";
import Cases from "./features/cases/Cases";
import Connectors from "./features/Connectors";

export type Me = { name: string; role: string; tenant_id: string };

function Login({ cfg, onDone, notice }: { cfg: AuthCfg | null; onDone: () => void; notice: string }) {
  const [t, setT] = useState(""); const [err, setErr] = useState(notice);
  const go = async () => {
    setToken(t.trim());
    try { await api("/me"); onDone(); } catch (e: any) { setToken(""); setErr(e.message); }
  };
  if (!cfg) return <div className="login"><h1>SOC Analisis</h1><p className="muted">Memuat…</p>{err && <p className="err">{err}</p>}</div>;
  return (
    <div className="login">
      <h1>SOC Analisis</h1>
      {cfg.mode === "oidc" ? <>
        <p className="muted">Masuk melalui penyedia identitas organisasi (SSO).</p>
        <button className="primary" onClick={() => startLogin(cfg)}>Masuk dengan SSO</button>
      </> : <>
        <p className="muted">Masukkan token API (lihat <code>API_TOKENS</code> di .env). Mode pengembangan.</p>
        <input type="password" placeholder="token" value={t} onChange={(e) => setT(e.target.value)} onKeyDown={(e) => e.key === "Enter" && go()} autoFocus />
        <button className="primary" onClick={go}>Masuk</button></>}
      {err && <p className="err">{err}</p>}
    </div>
  );
}

export default function App() {
  const [hash, setHash] = useState(location.hash || "#/");
  const [me, setMe] = useState<Me | null>(null);
  const [cfg, setCfg] = useState<AuthCfg | null>(null); const [notice, setNotice] = useState("");
  useEffect(() => { const f = () => setHash(location.hash || "#/"); addEventListener("hashchange", f); return () => removeEventListener("hashchange", f); }, []);
  const loadMe = () => api<Me>("/me").then(setMe).catch((e) => { setMe(null); setNotice(e.message); });
  useEffect(() => {
    (async () => {
      try {
        const c = await loadAuthConfig(); setCfg(c);
        if (c.mode === "oidc") { const r = await handleCallback(c); if (r && r !== "ok") { setNotice(r); return; } }
        if (getToken()) loadMe();
      } catch (e: any) { setNotice(e.message); }
    })();
    const f = () => setMe(null); addEventListener("soc-unauth", f); return () => removeEventListener("soc-unauth", f);
  }, []);
  if (!me) return <Login cfg={cfg} notice={notice} onDone={() => { loadMe(); location.hash = "#/"; }} />;

  const [, route, id] = hash.split("/");
  const nav = (to: string, label: string, key: string) => <a href={`#/${to}`} className={route === key || (key === "" && !route) ? "on" : ""}>{label}</a>;
  return (
    <div className="shell">
      <aside>
        <div className="brand">SOC<br />Analisis</div>
        <nav>{nav("", "Ringkasan", "")}{nav("alerts", "Alert", "alerts")}{nav("cases", "Case", "cases")}{me.role !== "viewer" && nav("connectors", "Konektor", "connectors")}</nav>
        <div className="me"><b>{me.name}</b><span>tenant: {me.tenant_id}</span>
          <button onClick={() => { setMe(null); logout(cfg); }}>Keluar</button></div>
      </aside>
      <main>
        {route === "alerts" && id ? <AlertDetail id={id} me={me} /> : route === "alerts" ? <Alerts /> :
         route === "cases" ? <Cases me={me} openId={id} /> : route === "connectors" ? <Connectors me={me} /> : <Dashboard />}
      </main>
    </div>
  );
}
