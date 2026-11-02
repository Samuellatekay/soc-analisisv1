import { describe, expect, it } from "vitest";
import { b64url, buildAuthUrl, challengeS256, parseCallback, randomString } from "../pkce";

const cfg = { mode: "oidc" as const, client_id: "soc-ui", scope: "openid profile", authorization_endpoint: "https://idp.example/auth", token_endpoint: "https://idp.example/token", extra_params: { audience: "soc-api" } };

describe("PKCE", () => {
  it("S256 sesuai vektor uji RFC 7636 Appendix B", async () => {
    expect(await challengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });
  it("base64url tanpa padding/karakter tidak aman", () => { expect(b64url(new Uint8Array([251, 255, 254]))).toBe("-__-"); expect(b64url(new Uint8Array([1]))).not.toMatch(/[=+/]/); });
  it("randomString panjang & unik, hanya karakter URL-safe", () => {
    const a = randomString(48), b = randomString(48);
    expect(a).not.toBe(b); expect(a.length).toBeGreaterThanOrEqual(43); expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
  });
  it("URL otorisasi memuat parameter wajib dan code_challenge_method=S256", () => {
    const u = new URL(buildAuthUrl(cfg, { redirectUri: "http://localhost:8000/", state: "st", challenge: "ch" }));
    expect(Object.fromEntries(u.searchParams)).toMatchObject({ response_type: "code", client_id: "soc-ui", redirect_uri: "http://localhost:8000/", state: "st",
      code_challenge: "ch", code_challenge_method: "S256", audience: "soc-api", scope: "openid profile" });
  });
  it("extra_params tidak boleh menimpa parameter keamanan", () => {
    const c = { ...cfg, extra_params: { code_challenge_method: "plain", response_type: "token" } };
    const u = new URL(buildAuthUrl(c, { redirectUri: "r", state: "s", challenge: "c" }));
    expect(u.searchParams.get("code_challenge_method")).toBe("S256"); expect(u.searchParams.get("response_type")).toBe("code");
  });
});

describe("callback", () => {
  it("bukan callback -> none", () => expect(parseCallback("", "x").kind).toBe("none"));
  it("state cocok -> code", () => expect(parseCallback("?code=abc&state=xyz", "xyz")).toEqual({ kind: "code", code: "abc" }));
  it("state tidak cocok / hilang ditolak (CSRF)", () => {
    expect(parseCallback("?code=abc&state=evil", "xyz").kind).toBe("error");
    expect(parseCallback("?code=abc", "xyz").kind).toBe("error");
    expect(parseCallback("?code=abc&state=xyz", null).kind).toBe("error");
  });
  it("error dari IdP diteruskan", () => {
    const r = parseCallback("?error=access_denied&error_description=ditolak&state=xyz", "xyz");
    expect(r.kind).toBe("error"); expect((r as any).message).toContain("access_denied");
  });
});
