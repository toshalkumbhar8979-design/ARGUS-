import dns from "node:dns/promises";
import { isIP } from "node:net";
import type { HttpResponse, Target } from "./types";
import { SECRET_PATTERNS, TAKEOVER_FINGERPRINTS, TECH_SIGNATURES, TECHNOLOGY_VERSION_PATTERNS, WAF_SIGNATURES } from "./signatures";
import { dedupe, maskSecret, truncate } from "./util";

export interface DnsReport {
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: Array<{ exchange: string; priority: number }>;
  ns: string[];
  txt: string[];
  caa: Array<{ critical: number; issue?: string; issuewild?: string; iodef?: string }>;
  dmarc: string[];
  wildcardDns: boolean;
  reverse: string[];
}

export async function resolveDns(host: string, timeoutMs = 5000): Promise<DnsReport> {
  const report: DnsReport = { a: [], aaaa: [], cname: [], mx: [], ns: [], txt: [], caa: [], dmarc: [], wildcardDns: false, reverse: [] };
  if (isIP(host)) {
    report.reverse = await withTimeout(dns.reverse(host), timeoutMs, []);
    return report;
  }
  const [a, aaaa, cname, mx, ns, txt, caa] = await Promise.all([
    withTimeout(dns.resolve4(host), timeoutMs, []),
    withTimeout(dns.resolve6(host), timeoutMs, []),
    withTimeout(dns.resolveCname(host), timeoutMs, []),
    withTimeout(dns.resolveMx(host), timeoutMs, []),
    withTimeout(dns.resolveNs(host), timeoutMs, []),
    withTimeout(dns.resolveTxt(host), timeoutMs, []),
    withTimeout(dns.resolveCaa(host), timeoutMs, []),
  ]);
  report.a = dedupe(a);
  report.aaaa = dedupe(aaaa);
  report.cname = dedupe(cname);
  report.mx = mx;
  report.ns = dedupe(ns);
  report.txt = txt.map((parts) => parts.join(""));
  report.caa = caa as DnsReport["caa"];
  const apex = registrableDomain(host);
  report.dmarc = (await withTimeout(dns.resolveTxt(`_dmarc.${apex}`), timeoutMs, [])).map((parts) => parts.join(""));
  const random = `argus-${Math.random().toString(36).slice(2, 10)}.${apex}`;
  const wildcard = await withTimeout(dns.resolve4(random), Math.min(timeoutMs, 2500), []);
  report.wildcardDns = wildcard.length > 0;
  return report;
}

export async function resolveIps(host: string, timeoutMs = 5000): Promise<string[]> {
  if (isIP(host)) return [host];
  const [a, aaaa] = await Promise.all([
    withTimeout(dns.resolve4(host), timeoutMs, []),
    withTimeout(dns.resolve6(host), timeoutMs, []),
  ]);
  return dedupe([...a, ...aaaa]);
}

export async function reverseDns(ip: string): Promise<string[]> {
  return withTimeout(dns.reverse(ip), 3000, []);
}

export function registrableDomain(host: string): string {
  const clean = host.toLowerCase().replace(/\.$/, "");
  if (isIP(clean)) return clean;
  const parts = clean.split(".").filter(Boolean);
  if (parts.length <= 2) return clean;
  const secondLevelSuffixes = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "co.in", "com.br", "com.mx", "com.tr", "co.za", "com.sg", "co.nz", "com.hk", "com.tw"]);
  const lastTwo = parts.slice(-2).join(".");
  if (secondLevelSuffixes.has(lastTwo) && parts.length >= 3) return parts.slice(-3).join(".");
  return lastTwo;
}

export interface TechHit {
  name: string;
  category: string;
  version?: string;
}

export function detectTechnologies(response: HttpResponse): TechHit[] {
  const hits = new Map<string, TechHit>();
  const body = response.body.slice(0, 500_000);
  const cookieHeader = response.headers["set-cookie"] ?? "";
  for (const signature of TECH_SIGNATURES) {
    let matched = false;
    for (const header of signature.headers ?? []) {
      const value = response.headers[header.name];
      if (value && header.pattern.test(value)) matched = true;
    }
    for (const pattern of signature.body ?? []) {
      if (pattern.test(body)) matched = true;
    }
    for (const pattern of signature.cookie ?? []) {
      if (pattern.test(cookieHeader)) matched = true;
    }
    if (matched) hits.set(signature.name, { name: signature.name, category: signature.category });
  }
  const haystack = `${Object.entries(response.headers).map(([key, value]) => `${key}: ${value}`).join("\n")}\n${response.body.slice(0, 200_000)}`;
  for (const versionPattern of TECHNOLOGY_VERSION_PATTERNS) {
    for (const pattern of versionPattern.patterns) {
      const match = pattern.exec(haystack);
      if (match?.[1]) {
        const existing = hits.get(versionPattern.name);
        hits.set(versionPattern.name, { name: versionPattern.name, category: existing?.category ?? "technology", version: match[1] });
        break;
      }
    }
  }
  return [...hits.values()];
}

export function detectWaf(response: HttpResponse): string[] {
  const haystack = `${Object.entries(response.headers).map(([key, value]) => `${key}: ${value}`).join("\n")}\n${response.body.slice(0, 100_000)}`;
  return WAF_SIGNATURES.filter((signature) => signature.patterns.some((pattern) => pattern.test(haystack))).map((signature) => signature.name);
}

export function extractTitle(html: string): string {
  const match = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  if (!match?.[1]) return "";
  return decodeHtmlEntities(match[1].replace(/\s+/g, " ").trim()).slice(0, 200);
}

export function extractMetaGenerator(html: string): string {
  const match = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(html);
  return match?.[1] ?? "";
}

export interface CookieInfo {
  name: string;
  valueLength: number;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  domain?: string;
  path?: string;
  expires?: string;
  maxAge?: string;
  flags: string[];
}

export function parseCookies(response: HttpResponse): CookieInfo[] {
  const lines = (response.rawHeaders["set-cookie"] ?? []).flatMap((value) => value.split(/\n/));
  const cookies: CookieInfo[] = [];
  for (const line of lines) {
    const parts = line.split(";").map((part) => part.trim());
    const [pair, ...attributes] = parts;
    if (!pair?.includes("=")) continue;
    const [name, ...valueParts] = pair.split("=");
    const info: CookieInfo = {
      name: name!.trim(),
      valueLength: valueParts.join("=").length,
      secure: false,
      httpOnly: false,
      flags: attributes,
    };
    for (const attribute of attributes) {
      const [rawKey, ...rawValue] = attribute.split("=");
      const key = rawKey!.toLowerCase();
      const value = rawValue.join("=");
      if (key === "secure") info.secure = true;
      if (key === "httponly") info.httpOnly = true;
      if (key === "samesite") info.sameSite = value;
      if (key === "domain") info.domain = value;
      if (key === "path") info.path = value;
      if (key === "expires") info.expires = value;
      if (key === "max-age") info.maxAge = value;
    }
    cookies.push(info);
  }
  return cookies;
}

export interface SecretHit {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "confirmed" | "likely" | "possible";
  description: string;
  match: string;
  masked: string;
  line: number;
  context: string;
}

export function scanTextForSecrets(text: string, options: { limit?: number; source?: string } = {}): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  const limit = options.limit ?? 50;
  for (const pattern of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags.includes("g") ? pattern.regex.flags : `${pattern.regex.flags}g`);
    let match: RegExpExecArray | null;
    let guard = 0;
    while ((match = regex.exec(text)) !== null && guard < 200) {
      guard += 1;
      const value = match[0];
      if (isPlaceholder(value)) continue;
      const key = `${pattern.id}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const index = match.index;
      const line = text.slice(0, index).split(/\r?\n/).length;
      const lineStart = text.lastIndexOf("\n", index) + 1;
      const lineEnd = text.indexOf("\n", index);
      const context = truncate(text.slice(lineStart, lineEnd === -1 ? index + 160 : lineEnd).trim(), 220);
      hits.push({
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        confidence: pattern.confidence,
        description: pattern.description,
        match: value,
        masked: maskSecret(value),
        line,
        context,
      });
      if (hits.length >= limit) return hits;
    }
  }
  return hits;
}

export function decodeHtmlEntities(value: string): string {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&#x2F;/g, "/")
    .replace(/&nbsp;/g, " ");
}

export function findTakeoverSignals(body: string, cnameTargets: string[]): Array<{ provider: string; cname?: string; evidence: string }> {
  const signals: Array<{ provider: string; cname?: string; evidence: string }> = [];
  for (const fingerprint of TAKEOVER_FINGERPRINTS) {
    const cname = cnameTargets.find((target) => fingerprint.cnameSuffixes.some((suffix) => target.toLowerCase().endsWith(suffix)));
    const bodyMatch = fingerprint.body.find((pattern) => pattern.test(body));
    if (cname || bodyMatch) {
      signals.push({ provider: fingerprint.provider, cname, evidence: bodyMatch?.exec(body)?.[0] ?? cname ?? "" });
    }
  }
  return signals;
}

export async function externalJson<T>(url: string, timeoutMs = 15_000, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: { "user-agent": "Argus/0.1 (authorized assessment)", accept: "application/json", ...(init?.headers ?? {}) },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`External request failed: HTTP ${response.status} ${url}`);
  return (await response.json()) as T;
}

export async function crtshSubdomains(domain: string, timeoutMs = 20_000): Promise<string[]> {
  const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
  const data = await externalJson<Array<{ name_value?: string; common_name?: string }>>(url, timeoutMs);
  const names = new Set<string>();
  for (const row of data) {
    for (const value of [row.name_value, row.common_name]) {
      if (!value) continue;
      for (const line of value.split(/\n/)) {
        const host = line.trim().toLowerCase().replace(/^\*\./, "");
        if (host.endsWith(domain) && /^[a-z0-9][a-z0-9.-]*$/.test(host) && host !== domain && !host.includes("*")) names.add(host);
      }
    }
  }
  return [...names].sort().slice(0, 500);
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type?: string; score?: string }> | string;
  database_specific?: { severity?: string };
}

export async function queryOsv(names: Array<{ name: string; version?: string; ecosystem?: string }>): Promise<Array<{ name: string; version?: string; ecosystem?: string; vulns: OsvVulnerability[] }>> {
  if (names.length === 0) return [];
  const entries = names.filter((item) => item.ecosystem);
  if (entries.length === 0) return [];
  const queries = entries.map((item) => ({ package: { name: item.name, ecosystem: item.ecosystem }, version: item.version }));
  const data = await externalJson<{ results?: Array<{ vulns?: OsvVulnerability[] }> }>(
    "https://api.osv.dev/v1/querybatch",
    30_000,
    { method: "POST", body: JSON.stringify({ queries }), headers: { "content-type": "application/json" } },
  );
  const output: Array<{ name: string; version?: string; ecosystem?: string; vulns: OsvVulnerability[] }> = [];
  for (const [index, result] of (data.results ?? []).entries()) {
    const input = entries[index];
    if (!input || !result.vulns?.length) continue;
    output.push({ name: input.name, version: input.version, ecosystem: input.ecosystem, vulns: result.vulns });
  }
  return output;
}
export function expandCidrHosts(cidr: string, maxHosts = 256): { hosts: string[]; total: number; truncated: boolean } {
  const [address, suffix] = cidr.split("/");
  if (!address || suffix === undefined) return { hosts: [cidr], total: 1, truncated: false };
  const version = isIP(address);
  if (version !== 4) return { hosts: [address], total: 1, truncated: false };
  const bits = Number(suffix);
  const total = 2 ** (32 - bits);
  const base = address.split(".").reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
  const start = bits >= 31 ? base : base + 1;
  const end = bits >= 31 ? base + total - 1 : base + total - 2;
  const hosts: string[] = [];
  for (let current = start; current <= end && hosts.length < maxHosts; current += 1) {
    hosts.push([current >>> 24, (current >>> 16) & 255, (current >>> 8) & 255, current & 255].join("."));
  }
  return { hosts, total: Math.max(0, end - start + 1), truncated: total > maxHosts + 2 };
}

export function targetUrlForPort(target: Target, port: number, secure: boolean, path = "/"): string {
  const host = target.host ?? target.ip;
  if (!host) throw new Error("Target has no host");
  const displayHost = isIP(host) === 6 ? `[${host}]` : host;
  return `${secure ? "https" : "http"}://${displayHost}:${port}${path}`;
}

export function baseTargetUrl(target: Target): string {
  if (target.url) return target.url;
  if (target.kind === "network" && target.host) {
    return targetUrlForPort(target, target.port ?? 443, true);
  }
  return `https://${target.host ?? target.path}`;
}

export function htmlSignature(body: string): string {
  return body
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 5000);
}

export function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise<T>((resolvePromise) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolvePromise(fallback);
    }, ms);
    promise
      .then((value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolvePromise(value);
      })
      .catch(() => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolvePromise(fallback);
      });
  });
}

export function isPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  return (
    /x{6,}|123456|changeme|example|sample|placeholder|dummy|your[_-]?key|fake|test[_-]?key|redacted|^\$\{/.test(lower) ||
    /<[^>]+>/.test(value)
  );
}
