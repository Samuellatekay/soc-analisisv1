import { useEffect, useMemo, useState } from "react";
import { api, setToken } from "../api";
import type { Me } from "../App";

type SettingField = {
  key: string; label: string; kind: string; secret: boolean; default: string | number | boolean | null;
  options: string[]; minimum?: number | null; maximum?: number | null; category: string; help: string;
};
type ScaleField = { key: string; label: string; kind: string; default: number | boolean; minimum?: number; maximum?: number };
type Cluster = {
  id: string; name: string; region: string; api_url: string;
  health: { state: string; reasons: string[] };
  configuration: { target: number; applied: number; in_sync: boolean };
};
type Config = {
  cluster_id: string; version: number; settings: Record<string, string | number | boolean>;
  secrets_set: string[]; autoscaling: Record<string, number | boolean>; connectors: Record<string, unknown>[];
};
type Catalog = { settings: SettingField[]; autoscaling: ScaleField[]; bootstrap_keys: string[] };

const EMPTY_CONFIG = (): Config => ({ cluster_id: "", version: 0, settings: {}, secrets_set: [], autoscaling: {}, connectors: [] });

export default function MasterConsole({ me }: { me: Me }) {
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [selected, setSelected] = useState("");
  const [config, setConfig] = useState<Config>(EMPTY_CONFIG());
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [secretsToClear, setSecretsToClear] = useState<string[]>([]);
  const [connectorsDraft, setConnectorsDraft] = useState("[]");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [clusterForm, setClusterForm] = useState(false);
  const [newCluster, setNewCluster] = useState({ id: "", name: "", api_url: "", region: "", status_token_env: "", verify_tls: true });
  const [pullToken, setPullToken] = useState("");
  const groupedSettings = useMemo(() => (catalog?.settings || []).reduce<Record<string, SettingField[]>>((groups, field) => {
    (groups[field.category] ||= []).push(field);
    return groups;
  }, {}), [catalog]);

  const loadClusters = async () => {
    try {
      setClusters(await api<Cluster[]>("/clusters"));
    } catch (e) {
      setError((e as Error).message);
    }
  };
  useEffect(() => {
    if (me.role === "admin") {
      api<Catalog>("/config/catalog").then(setCatalog).catch((e) => setError(e.message));
    }
    loadClusters();
    const timer = setInterval(loadClusters, 30000);
    return () => clearInterval(timer);
  }, [me.role]);
  useEffect(() => {
    if (!selected || me.role !== "admin") return;
    setLoading(true);
    setError("");
    api<Config>(`/clusters/${encodeURIComponent(selected)}/configuration`)
      .then((response) => {
        setConfig(response);
        setSecrets({});
        setSecretsToClear([]);
        setConnectorsDraft(JSON.stringify(response.connectors, null, 2));
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [me.role, selected]);

  const setSetting = (key: string, value: string | number | boolean | undefined) => {
    setConfig((current) => {
      const settings = { ...current.settings };
      if (value === undefined) delete settings[key];
      else settings[key] = value;
      return { ...current, settings };
    });
  };
  const setScale = (key: string, value: number | boolean) =>
    setConfig((current) => ({ ...current, autoscaling: { ...current.autoscaling, [key]: value } }));
  const saveConfig = async () => {
    if (!selected) return;
    setSaving(true);
    setError("");
    setNotice("");
    try {
      let connectors: unknown;
      try {
        connectors = JSON.parse(connectorsDraft);
      } catch {
        throw new Error("JSON konektor tidak valid.");
      }
      if (!Array.isArray(connectors)) throw new Error("Konfigurasi konektor harus berupa array JSON.");
      const result = await api<Config>(`/clusters/${encodeURIComponent(selected)}/configuration`, {
        method: "PUT",
        body: {
          settings: config.settings, secrets, clear_secrets: secretsToClear,
          autoscaling: config.autoscaling, connectors,
        },
      });
      setConfig(result);
      setSecrets({});
      setSecretsToClear([]);
      setConnectorsDraft(JSON.stringify(result.connectors, null, 2));
      setNotice(`Konfigurasi v${result.version} dipublikasikan. Cluster menerapkan perubahan dan melakukan rolling restart.`);
      await loadClusters();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };
  const registerCluster = async () => {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const result = await api<{ id: string; pull_token: string }>("/clusters", { method: "POST", body: newCluster });
      setPullToken(result.pull_token);
      setClusterForm(false);
      setNewCluster({ id: "", name: "", api_url: "", region: "", status_token_env: "", verify_tls: true });
      setNotice(`Cluster ${result.id} terdaftar. Simpan token tarik yang ditampilkan sekarang; token tidak dapat dibaca lagi.`);
      await loadClusters();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const renderSetting = (field: SettingField) => {
    if (field.secret) {
      return <label key={field.key}>
        {field.label}
        <input type="password" autoComplete="new-password" disabled={secretsToClear.includes(field.key)}
          value={secrets[field.key] || ""}
          placeholder={config.secrets_set.includes(field.key) ? "Sudah diatur; kosongkan untuk mempertahankan" : "Masukkan nilai rahasia"}
          onChange={(event) => {
            setSecrets((current) => ({ ...current, [field.key]: event.target.value }));
            setSecretsToClear((current) => current.filter((key) => key !== field.key));
          }} />
        {config.secrets_set.includes(field.key) && <span className="connector-checkbox">
          <input type="checkbox" checked={secretsToClear.includes(field.key)}
            onChange={(event) => {
              if (event.target.checked) {
                setSecrets((current) => {
                  const next = { ...current };
                  delete next[field.key];
                  return next;
                });
                setSecretsToClear((current) => [...current, field.key]);
              } else {
                setSecretsToClear((current) => current.filter((key) => key !== field.key));
              }
            }} />
          Hapus secret yang tersimpan
        </span>}
        <small className="muted">Dienkripsi sebelum disimpan di database Master. Tidak pernah ditampilkan kembali.</small>
      </label>;
    }
    const value = config.settings[field.key] ?? field.default ?? "";
    return <label key={field.key}>
      {field.label}
      {field.kind === "boolean" ? (
        <span className="connector-checkbox"><input type="checkbox" checked={Boolean(value)}
          onChange={(event) => setSetting(field.key, event.target.checked)} /> Aktif</span>
      ) : field.kind === "select" ? (
        <select value={String(value)} onChange={(event) => setSetting(field.key, event.target.value)}>
          {field.options.map((option) => <option key={option} value={option}>{option}</option>)}
        </select>
      ) : field.kind === "json" ? (
        <textarea value={String(value)} rows={3} onChange={(event) => setSetting(field.key, event.target.value)} />
      ) : (
        <input type={field.kind === "number" ? "number" : "text"}
          min={field.minimum ?? undefined} max={field.maximum ?? undefined}
          value={String(value)} onChange={(event) => setSetting(field.key, field.kind === "number"
            ? (event.target.value === "" ? undefined : Number(event.target.value))
            : event.target.value)} />
      )}
      {field.help && <small className="muted">{field.help}</small>}
    </label>;
  };

  return <div className="master-console">
    <header className="master-header">
      <div><h1>SOC Master</h1><p className="muted">Pengaturan armada dan konfigurasi runtime per cluster</p></div>
      <div><b>{me.name}</b> <button onClick={() => { setToken(""); location.reload(); }}>Keluar</button></div>
    </header>
    {error && <p className="err" role="alert">{error}</p>}
    {notice && <section className="master-notice">
      <p>{notice}</p>
      {pullToken && <><label>Pull token — disalin dan simpan sekarang
        <textarea readOnly rows={2} value={pullToken} /></label>
        <button onClick={() => { navigator.clipboard.writeText(pullToken); setPullToken(""); }}>Salin dan sembunyikan token</button></>}
    </section>}
    <section>
      <div className="master-section-heading"><h2>Cluster terdaftar ({clusters.length})</h2>
        {me.role === "admin" && <button className="primary" onClick={() => setClusterForm((value) => !value)}>Tambah cluster</button>}</div>
      {clusterForm && <div className="connector-fields">
        {([
          ["id", "ID cluster"], ["name", "Nama"], ["api_url", "URL API cluster"],
          ["region", "Region"], ["status_token_env", "Nama env token status"],
        ] as const).map(([key, label]) => <label key={key}>{label}
          <input value={newCluster[key]} onChange={(event) => setNewCluster((current) => ({ ...current, [key]: event.target.value }))} />
        </label>)}
        <label className="connector-checkbox"><input type="checkbox" checked={newCluster.verify_tls}
          onChange={(event) => setNewCluster((current) => ({ ...current, verify_tls: event.target.checked }))} /> Verifikasi TLS</label>
        <div className="actions"><button className="primary" disabled={saving} onClick={registerCluster}>Daftarkan</button>
          <button onClick={() => setClusterForm(false)}>Batal</button></div>
      </div>}
      {!clusters.length ? <p className="muted">Belum ada cluster terdaftar.</p> :
        <div className="master-cluster-grid">{clusters.map((cluster) =>
          <button key={cluster.id} className={`master-cluster ${selected === cluster.id ? "on" : ""}`}
            onClick={() => setSelected(cluster.id)}>
            <b>{cluster.name}</b><span>{cluster.id} · {cluster.region || "region belum diatur"}</span>
            <span className={`hl hl-${cluster.health.state === "healthy" ? "ok" : cluster.health.state === "unreachable" ? "bad" : "wait"}`}>
              {cluster.health.state}
            </span>
            <small>Konfigurasi {cluster.configuration.applied}/{cluster.configuration.target}
              {cluster.configuration.in_sync ? " · sinkron" : " · menunggu agent"}</small>
          </button>)}</div>}
    </section>
    {selected && me.role === "admin" && <section>
      <div className="master-section-heading"><div><h2>Konfigurasi: {selected}</h2>
        <p className="muted">Versi tersimpan: {config.version}. Perubahan diterapkan ke cluster dan memicu rolling restart.</p></div>
        <button className="primary" disabled={saving || loading || !catalog} onClick={saveConfig}>{saving ? "Menerbitkan…" : "Simpan & terapkan"}</button></div>
      {loading ? <p className="muted">Memuat konfigurasi…</p> : catalog && <>
        <div className="master-config-groups">{Object.entries(groupedSettings).map(([category, fields]) =>
          <section key={category}><h3>{category}</h3><div className="connector-fields">{fields.map(renderSetting)}</div></section>)}</div>
        <section><h3>Autoscaling Kubernetes</h3>
          <p className="muted">Engine diskalakan menurut lag Redis Streams (KEDA); API/Web menurut CPU (HPA). KEDA harus sudah dipasang pada cluster.</p>
          <div className="connector-fields">{catalog.autoscaling.map((field) => {
            const value = config.autoscaling[field.key] ?? field.default;
            return <label key={field.key}>{field.label}
              {field.kind === "boolean" ? <span className="connector-checkbox"><input type="checkbox" checked={Boolean(value)}
                onChange={(event) => setScale(field.key, event.target.checked)} /> Aktif</span> :
                <input type="number" min={field.minimum} max={field.maximum} value={Number(value)}
                  onChange={(event) => setScale(field.key, Number(event.target.value))} />}
            </label>;
          })}</div>
        </section>
        <section><h3>Konfigurasi konektor</h3>
          <p className="muted">Daftar JSON konektor yang berjalan pada cluster ini. Token vendor diatur terpisah di field Secret kategori Konektor.</p>
          <textarea className="master-json-editor" rows={12} value={connectorsDraft}
            onChange={(event) => setConnectorsDraft(event.target.value)} />
        </section>
      </>}
    </section>}
  </div>;
}
