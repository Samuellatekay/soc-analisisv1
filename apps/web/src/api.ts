// Satu-satunya jalur ke data: SOC API. Token hanya di sessionStorage (dev); produksi: OIDC/SSO.
export const getToken = () => sessionStorage.getItem("soc_token") || "";
export const setToken = (t: string) => (t ? sessionStorage.setItem("soc_token", t) : sessionStorage.removeItem("soc_token"));

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const r = await fetch(`/api/v1${path}`, {
    method: opts.method || "GET",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${getToken()}` },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (r.status === 401) { setToken(""); window.dispatchEvent(new Event("soc-unauth")); throw new Error("Sesi tidak valid / kedaluwarsa"); }
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(typeof j.detail === "string" ? j.detail : `HTTP ${r.status}`); }
  return r.json();
}

