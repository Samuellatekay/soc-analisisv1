// Fungsi murni PKCE (RFC 7636) — dapat diuji tanpa browser.
export const b64url = (buf: ArrayBuffer | Uint8Array): string => {
  const a = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = ""; a.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export const randomString = (bytes = 32): string => { const a = new Uint8Array(bytes); crypto.getRandomValues(a); return b64url(a); };
export const challengeS256 = async (verifier: string): Promise<string> =>
  b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));

export type AuthCfg = { mode: "token" | "master" } | { mode: "oidc"; client_id: string; scope: string; authorization_endpoint: string; token_endpoint: string;
  end_session_endpoint?: string | null; extra_params?: Record<string, string> };

export function buildAuthUrl(cfg: Extract<AuthCfg, { mode: "oidc" }>, o: { redirectUri: string; state: string; challenge: string }): string {
  const u = new URL(cfg.authorization_endpoint);
  const p: Record<string, string> = { ...(cfg.extra_params || {}), response_type: "code", client_id: cfg.client_id, redirect_uri: o.redirectUri,
    scope: cfg.scope, state: o.state, code_challenge: o.challenge, code_challenge_method: "S256" };
  Object.entries(p).forEach(([k, v]) => u.searchParams.set(k, v));
  return u.toString();
}

export type CallbackResult = { kind: "none" } | { kind: "code"; code: string } | { kind: "error"; message: string };
export function parseCallback(search: string, expectedState: string | null): CallbackResult {
  const q = new URLSearchParams(search);
  if (!q.has("code") && !q.has("error")) return { kind: "none" };
  if (!expectedState || q.get("state") !== expectedState) return { kind: "error", message: "state tidak cocok (kemungkinan CSRF atau sesi login kedaluwarsa)" };
  if (q.has("error")) return { kind: "error", message: `${q.get("error")}: ${q.get("error_description") || ""}` };
  return { kind: "code", code: q.get("code")! };
}
