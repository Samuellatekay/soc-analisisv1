import { useEffect, useState } from "react";
import { api } from "../api";
import type { Me } from "../App";
import { Empty, fmt } from "../components/ui";

type Field = { key: string; label: string; kind: string; required: boolean; default: string | number | boolean | null; help: string; options: string[] };
type ConnectorType = { label: string; fields: Field[] };
type ConnectorConfig = {
  name: string;
  type: string;
  enabled: boolean;
  poll_seconds: number;
  batch_size: number;
  initial_lookback_hours: number;
  params: Record<string, string | number | boolean>;
  tenant_id?: string;
};
type ConnectorStatus = Pick<ConnectorConfig, "name" | "type" | "enabled" | "poll_seconds"> & { state?: any };

const EMPTY_CONFIG = (type: string, catalog: Record<string, ConnectorType>): ConnectorConfig => ({
  name: "",
  type,
  enabled: false,
  poll_seconds: 60,
  batch_size: 500,
  initial_lookback_hours: 24,
  params: Object.fromEntries((catalog[type]?.fields || []).flatMap((field) =>
    field.default !== null ? [[field.key, field.default]] : [],
  )),
});

export default function Connectors({ me }: { me: Me }) {
  const [list, setList] = useState<ConnectorStatus[] | null>(null);
  const [catalog, setCatalog] = useState<Record<string, ConnectorType>>({});
  const [configs, setConfigs] = useState<ConnectorConfig[]>([]);
  const [msg, setMsg] = useState<Record<string, string>>({});
  const [err, setErr] = useState("");
  const [form, setForm] = useState<ConnectorConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const isAdmin = me.role === "admin";

  const load = () => api<ConnectorStatus[]>("/connectors").then(setList).catch((e) => setErr(e.message));
  const loadAdminConfig = async () => {
    if (!isAdmin) return;
    try {
      const [types, configured] = await Promise.all([
        api<Record<string, ConnectorType>>("/connectors/catalog"),
        api<ConnectorConfig[]>("/connectors/config"),
      ]);
      setCatalog(types);
      setConfigs(configured);
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  useEffect(() => {
    load();
    loadAdminConfig();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, []);

  const test = async (name: string) => {
    setMsg((current) => ({ ...current, [name]: "menguji…" }));
    const result = await api(`/connectors/${encodeURIComponent(name)}/test`, { method: "POST" })
      .catch((e) => ({ ok: false, error: e.message }));
    setMsg((current) => ({ ...current, [name]: result.ok ? `OK (${result.sample_count} event contoh)` : `GAGAL: ${result.error}` }));
  };
  const health = (connector: ConnectorStatus) => !connector.enabled ? "off" : !connector.state ? "wait" :
    connector.state.consecutive_failures > 0 ? "bad" : "ok";

  const edit = (name: string) => {
    const config = configs.find((item) => item.name === name);
    if (config) {
      const defaults = EMPTY_CONFIG(config.type, catalog);
      setForm({
        ...defaults,
        ...config,
        poll_seconds: config.poll_seconds || defaults.poll_seconds,
        batch_size: config.batch_size || defaults.batch_size,
        initial_lookback_hours: config.initial_lookback_hours || defaults.initial_lookback_hours,
        params: { ...defaults.params, ...config.params },
      });
    }
  };
  const updateForm = (update: Partial<ConnectorConfig>) => setForm((current) => current ? { ...current, ...update } : current);
  const updateParam = (key: string, value: string | number | boolean | undefined) => setForm((current) => {
    if (!current) return current;
    const params = { ...current.params };
    if (value === undefined) delete params[key];
    else params[key] = value;
    return { ...current, params };
  });
  const chooseType = (type: string) => {
    if (!form) return;
    updateForm({ type, params: EMPTY_CONFIG(type, catalog).params });
  };
  const save = async () => {
    if (!form) return;
    setSaving(true);
    setErr("");
    try {
      const { name, type, enabled, poll_seconds, batch_size, initial_lookback_hours, params } = form;
      await api(`/connectors/config/${encodeURIComponent(name)}`, {
        method: "PUT",
        body: { name, type, enabled, poll_seconds, batch_size, initial_lookback_hours, params },
      });
      setForm(null);
      await Promise.all([load(), loadAdminConfig()]);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <h2>Konektor</h2>
      <p className="muted">
        Kelola sumber alert. Konfigurasi tersimpan di database dan dipakai worker; perubahan diterapkan otomatis.
        Rahasia tetap disimpan di Secret/environment, bukan di formulir ini.
      </p>
      {err && <p className="err" role="alert">{err}</p>}
      {isAdmin && !form && <div className="actions">
        <button className="primary" disabled={!Object.keys(catalog).length}
          onClick={() => setForm(EMPTY_CONFIG(Object.keys(catalog)[0] || "splunk_es", catalog))}>
          Tambah konektor
        </button>
      </div>}
      {form && (
        <section className="connector-editor">
          <h3>{configs.some((item) => item.name === form.name) ? "Edit konektor" : "Tambah konektor"}</h3>
          <div className="connector-fields">
            <label>Nama konektor
              <input value={form.name} maxLength={64} disabled={configs.some((item) => item.name === form.name)}
                onChange={(event) => updateForm({ name: event.target.value })} placeholder="contoh: splunk-soc-01" />
            </label>
            <label>Produk
              <select value={form.type} onChange={(event) => chooseType(event.target.value)}>
                {Object.entries(catalog).map(([key, value]) => <option key={key} value={key}>{value.label}</option>)}
              </select>
            </label>
            <label>Interval polling (detik)
              <input type="number" min={10} max={86400} value={form.poll_seconds}
                onChange={(event) => updateForm({ poll_seconds: Number(event.target.value) })} />
            </label>
            <label>Ukuran batch
              <input type="number" min={1} max={10000} value={form.batch_size}
                onChange={(event) => updateForm({ batch_size: Number(event.target.value) })} />
            </label>
            <label>Jangkauan awal (jam)
              <input type="number" min={1} max={8760} value={form.initial_lookback_hours}
                onChange={(event) => updateForm({ initial_lookback_hours: Number(event.target.value) })} />
            </label>
            <label className="connector-checkbox"><input type="checkbox" checked={form.enabled}
              onChange={(event) => updateForm({ enabled: event.target.checked })} /> Aktifkan konektor</label>
            {(catalog[form.type]?.fields || []).map((field) => {
              const value = form.params[field.key];
              return <label key={field.key}>
                {field.label}{field.required && " *"}
                {field.kind === "boolean" ? (
                  <span className="connector-checkbox"><input type="checkbox" checked={Boolean(value)}
                    onChange={(event) => updateParam(field.key, event.target.checked)} /> Ya</span>
                ) : field.kind === "select" ? (
                  <select value={String(value ?? field.default ?? "")}
                    onChange={(event) => updateParam(field.key, event.target.value)}>
                    {field.options.map((option) => <option key={option} value={option}>{option}</option>)}
                  </select>
                ) : (
                  <input type={field.kind === "number" ? "number" : "text"}
                    min={field.kind === "number" ? 1 : undefined}
                    value={value === undefined ? "" : String(value)}
                    placeholder={field.kind === "secret_ref" ? "contoh: SPLUNK_TOKEN" : ""}
                    onChange={(event) => updateParam(field.key, field.kind === "number"
                      ? (event.target.value === "" ? undefined : Number(event.target.value))
                      : event.target.value)} />
                )}
                {field.help && <small className="muted">{field.help}</small>}
              </label>;
            })}
          </div>
          <p className="muted">
            Isian bertanda * wajib. Untuk field rahasia, masukkan nama environment variable/Secret, bukan nilai token atau password.
          </p>
          <div className="actions">
            <button className="primary" disabled={saving || !form.name.trim()} onClick={save}>{saving ? "Menyimpan…" : "Simpan konfigurasi"}</button>
            <button disabled={saving} onClick={() => setForm(null)}>Batal</button>
          </div>
        </section>
      )}
      {!list ? <p className="muted">Memuat…</p> : list.length === 0 ? (
        <Empty>{isAdmin ? "Belum ada konektor. Tambahkan konektor untuk mulai menerima alert." : "Belum ada konektor yang dikonfigurasi."}</Empty>
      ) : (
        <table><thead><tr><th>Status</th><th>Nama</th><th>Produk</th><th>Sukses terakhir</th><th>Event / ditolak</th><th>Catatan</th><th></th></tr></thead>
          <tbody>{list.map((connector) => {
            const state = health(connector);
            return <tr key={connector.name}>
              <td><span className={`hl hl-${state}`}>{{ off: "nonaktif", wait: "menunggu", bad: "bermasalah", ok: "sehat" }[state]}</span></td>
              <td><b>{connector.name}</b><br /><span className="muted">tiap {connector.poll_seconds}s</span></td>
              <td>{catalog[connector.type]?.label || connector.type}</td>
              <td>{connector.state?.last_success ? `${fmt(connector.state.last_success)} (${connector.state.seconds_since_success}s lalu)` : "–"}</td>
              <td className="num">{connector.state ? `${connector.state.events_total} / ${connector.state.rejected_total}` : "–"}</td>
              <td className="muted">{connector.state?.last_error ? <span className="err">{connector.state.last_error}</span> : connector.state?.last_warning || ""}
                {msg[connector.name] && <><br />{msg[connector.name]}</>}</td>
              <td className="actions">
                {isAdmin && <><button onClick={() => edit(connector.name)}>Edit</button><button onClick={() => test(connector.name)}>Uji koneksi</button></>}
              </td>
            </tr>;
          })}</tbody></table>)}
    </>
  );
}
