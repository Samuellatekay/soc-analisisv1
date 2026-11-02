import { setToken } from "./api";
import { AuthCfg, buildAuthUrl, challengeS256, parseCallback, randomString } from "./pkce";

const redirectUri = () => `${location.origin}/`;   // daftarkan URI ini pada client IdP

export async function loadAuthConfig(): Promise<AuthCfg> {
  const r = await fetch("/api/v1/auth/config");
  if (!r.ok) throw new Error(`konfigurasi login tidak tersedia (HTTP ${r.status})`);
  return r.json();
}

export async function startLogin(cfg: Extract<AuthCfg, { mode: "oidc" }>) {
  const verifier = randomString(48), state = randomString(16);
  sessionStorage.setItem("pkce_verifier", verifier); sessionStorage.setItem("pkce_state", state);
  location.assign(buildAuthUrl(cfg, { redirectUri: redirectUri(), state, challenge: await challengeS256(verifier) }));
}

/** Tangani redirect balik dari IdP. Return null bila bukan callback; string = pesan error; "ok" = token tersimpan. */
export async function handleCallback(cfg: Extract<AuthCfg, { mode: "oidc" }>): Promise<null | string> {
  const res = parseCallback(location.search, sessionStorage.getItem("pkce_state"));
  if (res.kind === "none") return null;
  const verifier = sessionStorage.getItem("pkce_verifier");
  sessionStorage.removeItem("pkce_state"); sessionStorage.removeItem("pkce_verifier");
  history.replaceState(null, "", "/#/");           // buang code/state dari URL (jangan tertinggal di riwayat)
  if (res.kind === "error") return res.message;
  if (!verifier) return "code_verifier hilang; ulangi login";
  const r = await fetch(cfg.token_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: res.code, redirect_uri: redirectUri(), client_id: cfg.client_id, code_verifier: verifier }) });
  if (!r.ok) return `pertukaran token gagal (HTTP ${r.status})`;
  const j = await r.json();
  if (!j.access_token) return "respons token tanpa access_token";
  setToken(j.access_token);                          // sessionStorage; hilang saat tab ditutup
  return "ok";
}

export function logout(cfg: AuthCfg | null) {
  setToken("");
  if (cfg && cfg.mode === "oidc" && cfg.end_session_endpoint) {
    const u = new URL(cfg.end_session_endpoint);
    u.searchParams.set("client_id", cfg.client_id); u.searchParams.set("post_logout_redirect_uri", redirectUri());
    location.assign(u.toString());
  } else location.hash = "#/";
}
