import { describe, expect, test } from "bun:test";
import { analyzeJwt } from "../src/core/jwt";

function part(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function token(header: Record<string, unknown>, payload: Record<string, unknown>, signature = "c2ln"): string {
  return `${part(header)}.${part(payload)}.${signature}`;
}

describe("JWT analysis", () => {
  test("flags alg none, expiry and authorization claims", () => {
    const value = token(
      { alg: "none", typ: "JWT" },
      { sub: "user-1", role: "admin", exp: Math.floor(Date.now() / 1000) - 60 },
    );
    const analysis = analyzeJwt(value);
    expect(analysis.flags.some((flag) => flag.title.includes("Unsigned token"))).toBe(true);
    expect(analysis.flags.some((flag) => flag.title === "Token is expired")).toBe(true);
    expect(analysis.flags.some((flag) => flag.title === "Authorization claim: role")).toBe(true);
    expect(analysis.header.alg).toBe("none");
    expect(analysis.expiresAt).toBeDefined();
  });

  test("flags remote key URLs, kid and redacts sensitive claims", () => {
    const value = token(
      { alg: "HS256", typ: "JWT", jku: "https://attacker.example/keys", kid: "../../etc/passwd" },
      {
        sub: "user-1",
        iss: "https://issuer.example",
        aud: "api",
        api_key: "sk-super-secret-value",
        exp: Math.floor(Date.now() / 1000) + 3_600,
      },
    );
    const analysis = analyzeJwt(value);
    expect(analysis.flags.some((flag) => flag.title.includes("Remote key reference"))).toBe(true);
    expect(analysis.flags.some((flag) => flag.title === "Key ID present (kid)")).toBe(true);
    expect(analysis.flags.some((flag) => flag.title === "Sensitive claim: api_key")).toBe(true);
    expect(String(analysis.payload.api_key)).toContain("redacted");
    expect(JSON.stringify(analysis)).not.toContain("sk-super-secret-value");
  });

  test("accepts an empty signature and redacts nested sensitive claims", () => {
    const value = `${part({ alg: "none", typ: "JWT" })}.${part({
      sub: "user-1",
      profile: { password: "plain-text-password", token: "sk-nested-secret" },
    })}.`;
    const analysis = analyzeJwt(value);
    expect(analysis.flags.some((flag) => flag.title.includes("Unsigned token"))).toBe(true);
    expect(analysis.flags.find((flag) => flag.title.includes("Unsigned token"))?.detail).toContain("no signature");
    expect(JSON.stringify(analysis)).not.toContain("plain-text-password");
    expect(JSON.stringify(analysis)).not.toContain("sk-nested-secret");

    const signedHeaderValue = `${part({ alg: "HS256" })}.${part({ sub: "user-1" })}.`;
    expect(analyzeJwt(signedHeaderValue).flags.some((flag) => flag.title === "Empty signature")).toBe(true);
  });

  test("rejects malformed tokens without echoing the input", () => {
    expect(() => analyzeJwt("not-a-token")).toThrow(/three dot-separated parts/);
    expect(() => analyzeJwt("a.b")).toThrow(/three dot-separated parts/);
    expect(() => analyzeJwt("a.b.c")).toThrow(/header is not valid/);
  });
});
