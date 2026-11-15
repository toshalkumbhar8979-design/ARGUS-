import type { Severity } from "./types";

export interface JwtFlag {
  severity: Severity;
  title: string;
  detail: string;
}

export interface JwtAnalysis {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  flags: JwtFlag[];
  expiresAt?: string;
  issuedAt?: string;
}

const SENSITIVE_CLAIM = /pass(word)?|secret|api[_-]?key|token|session|cookie|credential|private[_-]?key|ssn|credit|card[_-]?number/i;
const AUTH_CLAIM = /^(role|roles|admin|is[_-]?admin|scope|scopes|permissions|groups|tenant|org)$/i;

function decodeJson(part: string, label: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as unknown;
  } catch {
    throw new Error(`${label} is not valid base64url JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${label} must be a JSON object`);
  return parsed as Record<string, unknown>;
}

function redact(value: unknown): unknown {
  if (typeof value === "string") return `[redacted ${value.length} chars]`;
  if (Array.isArray(value)) return `[redacted ${value.length} item(s)]`;
  if (value && typeof value === "object") return "[redacted object]";
  return "[redacted]";
}

function safeValue(value: unknown, depth = 0): unknown {
  if (depth > 4) return "[nested value]";
  if (Array.isArray(value)) return value.map((item) => safeValue(item, depth + 1));
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      output[key] = SENSITIVE_CLAIM.test(key) ? redact(entry) : safeValue(entry, depth + 1);
    }
    return output;
  }
  return value;
}

function safePayload(payload: Record<string, unknown>): Record<string, unknown> {
  return safeValue(payload) as Record<string, unknown>;
}

function numericDate(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function iso(value: number | undefined): string | undefined {
  return value === undefined ? undefined : new Date(value * 1000).toISOString();
}

/**
 * Decodes a JWT and reports structural/session risks. It never verifies the
 * signature because no key is supplied, and it redacts sensitive claim values.
 */
export function analyzeJwt(token: string): JwtAnalysis {
  const cleaned = token.trim().replace(/^Bearer\s+/i, "");
  const parts = cleaned.split(".");
  if (parts.length !== 3) throw new Error("not a JWT — expected three dot-separated parts");
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const unsigned = signaturePart.length === 0;
  const header = decodeJson(headerPart, "JWT header");
  const payload = decodeJson(payloadPart, "JWT payload");
  const flags: JwtFlag[] = [];
  const alg = typeof header.alg === "string" ? header.alg : "";

  if (!alg) {
    flags.push({ severity: "medium", title: "Missing alg", detail: "The header has no algorithm; test how the verifier handles it." });
  } else if (/^none$/i.test(alg)) {
    flags.push({
      severity: "critical",
      title: "Unsigned token (alg none)",
      detail: `The token declares alg=none${unsigned ? " and carries no signature" : ""}. If the verifier accepts it, an attacker can forge arbitrary claims.`,
    });
  } else if (/^HS/i.test(alg)) {
    flags.push({
      severity: "info",
      title: `HMAC algorithm (${alg})`,
      detail: "HMAC tokens are only as strong as the shared secret; test for default, short or leaked keys.",
    });
  }

  if (unsigned && !/^none$/i.test(alg)) {
    flags.push({
      severity: "high",
      title: "Empty signature",
      detail: `The header names ${alg || "no algorithm"} but the signature segment is empty. Test whether the verifier rejects it.`,
    });
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = numericDate(payload.exp);
  const nbf = numericDate(payload.nbf);
  const iat = numericDate(payload.iat);
  if (exp === undefined) {
    flags.push({ severity: "medium", title: "No expiration", detail: "The token has no exp claim, so it may remain valid indefinitely." });
  } else if (exp <= now) {
    flags.push({
      severity: "medium",
      title: "Token is expired",
      detail: `exp was ${new Date(exp * 1000).toISOString()}; confirm whether the server actually rejects it.`,
    });
  } else if (exp - now > 30 * 86_400) {
    flags.push({
      severity: "low",
      title: "Long-lived token",
      detail: `exp is ${Math.ceil((exp - now) / 86_400)} days away; long sessions increase the impact of theft.`,
    });
  }
  if (nbf !== undefined && nbf > now + 60) {
    flags.push({ severity: "low", title: "Not valid yet", detail: "The nbf claim is in the future; check clock-skew handling." });
  }

  for (const key of ["jku", "x5u", "jwk"]) {
    if (header[key] !== undefined) {
      flags.push({
        severity: "high",
        title: `Remote key reference (${key})`,
        detail: `The header supplies ${key}. Test whether the verifier fetches an attacker-controlled key URL (SSRF/key injection).`,
      });
    }
  }
  if (header.kid !== undefined) {
    flags.push({
      severity: "info",
      title: "Key ID present (kid)",
      detail: "Test the key lookup for path traversal, SQL injection or a key confusion issue.",
    });
  }

  const sensitive = Object.keys(payload).filter((key) => SENSITIVE_CLAIM.test(key));
  for (const key of sensitive) {
    flags.push({
      severity: "high",
      title: `Sensitive claim: ${key}`,
      detail: `The value is redacted in this report (${String(payload[key] ?? "").length} chars in the raw claim). Never paste the token into a report.`,
    });
  }
  const authClaims = Object.keys(payload).filter((key) => AUTH_CLAIM.test(key));
  for (const key of authClaims) {
    flags.push({
      severity: "info",
      title: `Authorization claim: ${key}`,
      detail: "Test whether changing this claim changes server-side authorization, and whether the signature is actually checked.",
    });
  }

  if (typeof payload.iss !== "string") {
    flags.push({ severity: "low", title: "Missing issuer", detail: "No iss claim; check that the verifier only accepts tokens from the expected issuer." });
  }
  if (typeof payload.aud !== "string" && !Array.isArray(payload.aud)) {
    flags.push({ severity: "low", title: "Missing audience", detail: "No aud claim; a token from another service may be replayable." });
  }
  if (typeof payload.sub !== "string") {
    flags.push({ severity: "low", title: "Missing subject", detail: "No sub claim; confirm which identity the token represents." });
  }

  return {
    header,
    payload: safePayload(payload),
    flags,
    expiresAt: iso(exp),
    issuedAt: iso(iat),
  };
}
