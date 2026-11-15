import { isIP } from "node:net";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import type { ProfileId, ScopePolicy, ScopeValidation, Target } from "./types";
import { expandHome } from "./util";

type AllowEntry =
  | { kind: "url"; scheme: "http" | "https"; host: string; wildcard: boolean; port?: number; pathPrefix: string; raw: string }
  | { kind: "host"; host: string; wildcard: boolean; port?: number; raw: string }
  | { kind: "cidr"; network: bigint; bits: number; version: 4 | 6; raw: string }
  | { kind: "path"; path: string; raw: string };

const METADATA_HOSTS = new Set([
  "169.254.169.254",
  "metadata.google.internal",
  "metadata.goog",
  "100.100.100.200",
  "fd00:ec2::254",
  "instance-data",
]);

export function validateScope(scope: ScopePolicy, now = new Date()): ScopeValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!scope || typeof scope !== "object") {
    return {
      ok: false,
      errors: ["Scope must be a JSON object."],
      warnings,
      expired: true,
      active: false,
      intrusive: false,
      external: false,
      allowedCount: 0,
    };
  }
  if (scope.version !== 1) errors.push("scope.version must be 1.");
  if (!scope.name || scope.name.trim().length < 3) errors.push("scope.name is required (min 3 chars).");
  if (!scope.authorizedBy || scope.authorizedBy.trim().length < 3) errors.push("scope.authorizedBy is required.");
  if (!scope.authorizationRef || scope.authorizationRef.trim().length < 3) {
    errors.push("scope.authorizationRef is required - cite the signed authorization / rules of engagement.");
  }
  if (!Array.isArray(scope.allow) || scope.allow.length === 0) errors.push("scope.allow must list at least one target.");

  let expires = Number.NaN;
  if (!scope.expiresAt) {
    errors.push("scope.expiresAt is required (ISO timestamp).");
  } else {
    expires = Date.parse(scope.expiresAt);
    if (!Number.isFinite(expires)) errors.push("scope.expiresAt is not a valid ISO timestamp.");
  }
  const expired = Number.isFinite(expires) ? expires <= now.getTime() : true;
  if (Number.isFinite(expires) && expired) errors.push("Authorization has expired.");
  if (Number.isFinite(expires) && expires - now.getTime() > 365 * 24 * 60 * 60 * 1000) {
    warnings.push("Authorization window is longer than one year.");
  }

  let validEntries = 0;
  for (const entry of scope.allow ?? []) {
    const parsed = parseAllowEntry(entry);
    if (!parsed) {
      errors.push(`Invalid allow entry: ${entry}`);
      continue;
    }
    validEntries += 1;
    if (parsed.kind === "cidr" && parsed.bits === 0) warnings.push(`Very broad scope entry: ${entry}`);
    if (parsed.kind === "host" && parsed.wildcard && parsed.host.split(".").filter(Boolean).length <= 2) {
      warnings.push(`Broad wildcard scope entry: ${entry}`);
    }
    if (parsed.kind === "url" && parsed.pathPrefix === "/" && parsed.wildcard) {
      warnings.push(`Wildcard URL scope: ${entry}`);
    }
  }
  for (const entry of scope.deny ?? []) {
    if (!parseAllowEntry(entry)) errors.push(`Invalid deny entry: ${entry}`);
  }
  if (!scope.deny || scope.deny.length === 0) {
    warnings.push("No deny-list configured. Add destructive or out-of-bounds paths.");
  }
  if (scope.allowActive && !scope.allowIntrusive) {
    warnings.push("Active mode is enabled; intrusive tools remain locked.");
  }
  if (scope.allowIntrusive && !scope.allowActive) {
    errors.push("allowIntrusive requires allowActive=true.");
  }
  if (scope.maxRps !== undefined && (!Number.isFinite(scope.maxRps) || scope.maxRps <= 0)) {
    errors.push("scope.maxRps must be a positive number.");
  }
  if (scope.allowedPorts?.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
    errors.push("scope.allowedPorts contains an invalid port.");
  }
  if (scope.allowActive && !scope.allowedPorts?.length) {
    warnings.push("Active mode without allowedPorts permits scanning every port on allowed hosts.");
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    expired,
    active: Boolean(scope.allowActive),
    intrusive: Boolean(scope.allowIntrusive),
    external: Boolean(scope.allowExternal),
    allowedCount: validEntries,
  };
}

/**
 * Records an interactive approval: the operator explicitly authorized active,
 * state-changing testing against this scope. The original authorization
 * reference is kept and the approval is appended, so the scope file remains an
 * audit trail of who allowed what and when.
 */
export function authorizeIntrusive(scope: ScopePolicy, at: Date = new Date()): ScopePolicy {
  const stamp = at.toISOString();
  const alreadyApproved = /INTERACTIVE-APPROVAL/.test(scope.authorizationRef);
  return {
    ...scope,
    allowActive: true,
    allowIntrusive: true,
    authorizedBy: /interactive/i.test(scope.authorizedBy)
      ? scope.authorizedBy
      : `${scope.authorizedBy} + interactive approval`,
    authorizationRef: alreadyApproved
      ? scope.authorizationRef
      : `${scope.authorizationRef} + INTERACTIVE-APPROVAL ${stamp}`,
  };
}

/**
 * A workspace-only scope for source review. It cannot authorize a network
 * target: the only allow rule is the local checkout, and active/intrusive modes
 * are off. A prompt that names a network target is handled by prompt-scope,
 * which records that target and merges it with this baseline.
 */
export function localScopePolicy(workspace = process.cwd(), now = new Date()): ScopePolicy {
  const root = resolve(expandHome(workspace));
  return {
    version: 1,
    name: "Local workspace review (auto-created)",
    authorizedBy: "local operator",
    authorizationRef: "LOCAL-SOURCE-REVIEW: workspace-only; no network requests",
    expiresAt: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    allow: [root],
    deny: [resolve(root, ".git"), resolve(root, "node_modules")],
    maxRps: 5,
    allowedPorts: [],
    allowActive: false,
    allowIntrusive: false,
    allowExternal: false,
  };
}

export interface EnsureLocalScopeResult {
  path: string;
  scope: ScopePolicy;
  created: boolean;
}

/**
 * Creates the local-only scope when the file does not exist yet. Existing files
 * are read, never overwritten. This is what lets the agent begin a source review
 * on its own without pretending it has network authorization.
 */
export async function ensureLocalScope(
  scopePath: string,
  workspace = process.cwd(),
  now = new Date(),
): Promise<EnsureLocalScopeResult> {
  const path = resolve(expandHome(scopePath));
  if (existsSync(path)) {
    let scope: ScopePolicy;
    try {
      scope = JSON.parse(await readFile(path, "utf8")) as ScopePolicy;
    } catch (error) {
      throw new Error(`Cannot read scope at ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
    return { path, scope, created: false };
  }

  const scope = localScopePolicy(workspace, now);
  await mkdir(dirname(path), { recursive: true });
  try {
    await writeFile(path, `${JSON.stringify(scope, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
    return { path, scope, created: true };
  } catch (error) {
    // A parallel process may have won the race; use the file it wrote.
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      const existing = JSON.parse(await readFile(path, "utf8")) as ScopePolicy;
      return { path, scope: existing, created: false };
    }
    throw error;
  }
}

export class ScopeGuard {
  readonly scope: ScopePolicy;
  readonly validation: ScopeValidation;
  private readonly allow: AllowEntry[];
  private readonly deny: AllowEntry[];

  constructor(scope: ScopePolicy) {
    this.scope = scope;
    this.validation = validateScope(scope);
    this.allow = (scope.allow ?? []).map(parseAllowEntry).filter((entry): entry is AllowEntry => entry !== null);
    this.deny = (scope.deny ?? []).map(parseAllowEntry).filter((entry): entry is AllowEntry => entry !== null);
  }

  assertUsable(): void {
    if (!this.validation.ok) {
      throw new Error(`Scope rejected: ${this.validation.errors.join(" ")}`);
    }
  }

  checkUrl(rawUrl: string): { allowed: boolean; reason?: string } {
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      return { allowed: false, reason: "Malformed URL." };
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return { allowed: false, reason: `Protocol ${url.protocol} is not permitted.` };
    }
    if (url.username || url.password) return { allowed: false, reason: "URLs with embedded credentials are blocked." };
    const host = normalizeHost(url.hostname);
    if (isBlockedMetadata(host)) return { allowed: false, reason: "Cloud metadata endpoints are hard-blocked." };
    if (!this.validation.ok) return { allowed: false, reason: "Scope authorization is invalid or expired." };
    if (this.matchesAny(this.deny, url, host)) return { allowed: false, reason: `Blocked by deny rule for ${host}.` };
    if (!this.matchesAny(this.allow, url, host)) {
      return { allowed: false, reason: `${host}${url.port ? `:${url.port}` : ""} is outside the authorized scope.` };
    }
    return { allowed: true };
  }

  assertUrl(rawUrl: string): URL {
    const result = this.checkUrl(rawUrl);
    if (!result.allowed) throw new Error(`Scope violation: ${result.reason}`);
    return new URL(rawUrl);
  }

  checkHost(rawHost: string, port?: number, scheme: "http" | "https" = "https"): { allowed: boolean; reason?: string } {
    const host = normalizeHost(rawHost);
    if (!host) return { allowed: false, reason: "Empty host." };
    if (isBlockedMetadata(host)) return { allowed: false, reason: "Cloud metadata endpoints are hard-blocked." };
    if (!this.validation.ok) return { allowed: false, reason: "Scope authorization is invalid or expired." };
    const url = new URL(`${scheme}://${formatHostForUrl(host)}${port ? `:${port}` : ""}/`);
    if (this.matchesAny(this.deny, url, host)) return { allowed: false, reason: `Blocked by deny rule for ${host}.` };
    if (!this.matchesAny(this.allow, url, host)) {
      return { allowed: false, reason: `${host}${port ? `:${port}` : ""} is outside the authorized scope.` };
    }
    return { allowed: true };
  }

  checkNetworkRange(cidr: string): { allowed: boolean; reason?: string } {
    const range = parseCidr(cidr);
    if (!range) return { allowed: false, reason: `Invalid CIDR: ${cidr}` };
    if (!this.validation.ok) return { allowed: false, reason: "Scope authorization is invalid or expired." };
    const denied = this.deny.some((entry) =>
      entry.kind === "cidr" ? rangesOverlap(entry, range) : false,
    );
    if (denied) return { allowed: false, reason: `Range ${cidr} overlaps a deny rule.` };
    const allowed = this.allow.some((entry) => {
      if (entry.kind !== "cidr") return false;
      return entry.version === range.version && entry.bits <= range.bits && samePrefix(entry, range);
    });
    if (!allowed) return { allowed: false, reason: `Range ${cidr} is outside the authorized scope.` };
    return { allowed: true };
  }

  checkPort(port: number): { allowed: boolean; reason?: string } {
    if (!Number.isInteger(port) || port < 1 || port > 65535) return { allowed: false, reason: "Invalid port." };
    const ports = this.scope.allowedPorts;
    if (ports && ports.length > 0 && !ports.includes(port)) {
      return { allowed: false, reason: `Port ${port} is not in scope.allowedPorts.` };
    }
    return { allowed: true };
  }

  checkLocalPath(rawPath: string): { allowed: boolean; reason?: string } {
    const path = resolve(expandHome(rawPath));
    if (!existsSync(path)) return { allowed: false, reason: `Local path does not exist: ${path}` };
    if (!this.validation.ok) return { allowed: false, reason: "Scope authorization is invalid or expired." };
    const denyPath = this.deny.find((entry) => entry.kind === "path" && pathWithin(path, entry.path));
    if (denyPath) return { allowed: false, reason: `Path blocked by deny rule: ${denyPath.raw}` };
    const allowPath = this.allow.find((entry) => entry.kind === "path" && pathWithin(path, entry.path));
    if (!allowPath) return { allowed: false, reason: `Path ${path} is outside the authorized scope.` };
    return { allowed: true };
  }

  resolveTarget(raw: string, profile: ProfileId): Target {
    this.assertUsable();
    const target = detectTarget(raw, profile);
    if (target.kind === "repo") {
      const result = this.checkLocalPath(target.path!);
      if (!result.allowed) throw new Error(`Scope violation: ${result.reason}`);
    } else if (target.kind === "network") {
      if (target.host && isCidr(target.host)) {
        const rangeResult = this.checkNetworkRange(target.host);
        if (!rangeResult.allowed) throw new Error(`Scope violation: ${rangeResult.reason}`);
        if (this.scope.allowedPorts?.length) {
          for (const port of this.scope.allowedPorts) {
            const portResult = this.checkPort(port);
            if (!portResult.allowed) throw new Error(`Scope violation: ${portResult.reason}`);
          }
        }
      } else {
        const result = this.checkHost(target.host!, target.port, "https");
        if (!result.allowed) throw new Error(`Scope violation: ${result.reason}`);
        if (target.port) {
          const portResult = this.checkPort(target.port);
          if (!portResult.allowed) throw new Error(`Scope violation: ${portResult.reason}`);
        }
      }
    } else {
      const result = this.checkUrl(target.url!);
      if (!result.allowed) throw new Error(`Scope violation: ${result.reason}`);
    }
    return target;
  }

  expiresInDays(now = new Date()): number {
    const expires = Date.parse(this.scope.expiresAt);
    if (!Number.isFinite(expires)) return 0;
    return Math.ceil((expires - now.getTime()) / (24 * 60 * 60 * 1000));
  }

  private matchesAny(entries: AllowEntry[], url: URL, host: string): boolean {
    return entries.some((entry) => entryMatches(entry, url, host));
  }
}

export function detectTarget(raw: string, profile: ProfileId): Target {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("Target is empty.");
  const isExistingPath = !/^https?:\/\//i.test(trimmed) && existsSync(trimmed);
  if (isExistingPath && (profile === "repo" || /[\\/]/.test(trimmed))) {
    const path = resolve(expandHome(trimmed));
    return { raw, kind: "repo", path, display: path };
  }

  if (/^https?:\/\//i.test(trimmed)) {
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      throw new Error(`Invalid URL: ${trimmed}`);
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Only http/https targets are supported.");
    return {
      raw,
      kind: profile === "api" ? "api" : "web",
      host: normalizeHost(url.hostname),
      port: Number(url.port || (url.protocol === "https:" ? 443 : 80)),
      scheme: url.protocol === "https:" ? "https" : "http",
      url: url.toString(),
      baseUrl: url.origin,
      display: `${url.host}${url.pathname === "/" ? "" : url.pathname}`,
    };
  }

  const ipVersion = isIP(stripBrackets(trimmed));
  if (ipVersion) {
    const host = stripBrackets(trimmed);
    return { raw, kind: "network", host, display: host };
  }

  if (isCidr(trimmed)) {
    return { raw, kind: "network", host: trimmed, display: trimmed };
  }

  if (profile === "repo") {
    const path = resolve(expandHome(trimmed));
    return { raw, kind: "repo", path, display: path };
  }

  if (profile === "network") {
    const { host, port } = splitHostPort(trimmed);
    return { raw, kind: "network", host, port, display: trimmed };
  }

  if (/^[a-z0-9.-]+:\d{1,5}(\/.*)?$/i.test(trimmed)) {
    const { host, port, rest } = splitHostPort(trimmed);
    const scheme = port === 443 || port === 8443 ? "https" : "http";
    const normalized = `${scheme}://${formatHostForUrl(host)}:${port}${rest || "/"}`;
    return {
      raw,
      kind: profile === "api" ? "api" : "web",
      host,
      port,
      scheme,
      url: normalized,
      baseUrl: `${scheme}://${formatHostForUrl(host)}:${port}`,
      display: `${host}:${port}${rest || ""}`,
    };
  }

  const slash = trimmed.indexOf("/");
  const hostPart = slash === -1 ? trimmed : trimmed.slice(0, slash);
  const pathPart = slash === -1 ? "" : trimmed.slice(slash);
  const host = normalizeHost(hostPart);
  if (!isPlausibleHostname(host)) throw new Error(`Cannot interpret target: ${trimmed}`);
  const url = `https://${formatHostForUrl(host)}${pathPart || "/"}`;
  return {
    raw,
    kind: profile === "api" ? "api" : "web",
    host,
    port: 443,
    scheme: "https",
    url,
    baseUrl: `https://${formatHostForUrl(host)}`,
    display: `${host}${pathPart}`,
  };
}

export function parseAllowEntry(input: string): AllowEntry | null {
  const trimmed = input.trim();
  if (!trimmed || trimmed === "*") return null;

  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const url = new URL(trimmed);
      const host = normalizeHost(url.hostname);
      const wildcard = host.startsWith("*.");
      const cleanHost = wildcard ? host.slice(2) : host;
      if (!cleanHost || !isPlausibleHostname(cleanHost)) return null;
      if (url.username || url.password) return null;
      return {
        kind: "url",
        scheme: url.protocol === "https:" ? "https" : "http",
        host: cleanHost,
        wildcard,
        port: url.port ? Number(url.port) : undefined,
        pathPrefix: url.pathname || "/",
        raw: trimmed,
      };
    } catch {
      return null;
    }
  }

  if (/^[a-zA-Z]:[\\/]/.test(trimmed) || trimmed.startsWith("/") || trimmed.startsWith("~/")) {
    return { kind: "path", path: resolve(expandHome(trimmed)), raw: trimmed };
  }

  if (isCidr(trimmed)) {
    const parsed = parseCidr(trimmed);
    if (!parsed) return null;
    return { kind: "cidr", ...parsed, raw: trimmed };
  }

  if (isIP(stripBrackets(trimmed))) {
    const version = isIP(stripBrackets(trimmed)) as 4 | 6;
    return {
      kind: "cidr",
      network: ipToBigInt(stripBrackets(trimmed)),
      bits: version === 4 ? 32 : 128,
      version,
      raw: trimmed,
    };
  }

  const { host: rawHost, port, rest } = splitHostPort(trimmed);
  const host = normalizeHost(rawHost);
  const wildcard = host.startsWith("*.");
  const cleanHost = wildcard ? host.slice(2) : host;
  if (!cleanHost || !isPlausibleHostname(cleanHost)) return null;
  if (rest && rest !== "/") return null;
  if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) return null;
  return { kind: "host", host: cleanHost, wildcard, port, raw: trimmed };
}

function entryMatches(entry: AllowEntry, url: URL, host: string): boolean {
  if (entry.kind === "path") return false;
  if (entry.kind === "cidr") {
    if (!isIP(host)) return false;
    if ((isIP(host) as number) !== entry.version) return false;
    const value = ipToBigInt(host);
    const shift = BigInt((entry.version === 4 ? 32 : 128) - entry.bits);
    return (value >> shift) === (entry.network >> shift);
  }
  if (entry.kind === "host") {
    if (entry.port !== undefined && Number(url.port || defaultPort(url)) !== entry.port) return false;
    if (!matchesHost(host, entry.host, entry.wildcard)) return false;
    return true;
  }
  if (entry.scheme !== (url.protocol === "https:" ? "https" : "http")) return false;
  if (!matchesHost(host, entry.host, entry.wildcard)) return false;
  const port = Number(url.port || defaultPort(url));
  if (entry.port !== undefined && port !== entry.port) return false;
  if (entry.pathPrefix !== "/" && !url.pathname.startsWith(entry.pathPrefix)) return false;
  return true;
}

function matchesHost(host: string, allowed: string, wildcard: boolean): boolean {
  if (wildcard) return host.endsWith(`.${allowed}`);
  return host === allowed;
}

function defaultPort(url: URL): number {
  return url.protocol === "https:" ? 443 : 80;
}

function isBlockedMetadata(host: string): boolean {
  return METADATA_HOSTS.has(host.toLowerCase());
}

export function isPrivateIp(value: string): boolean {
  const version = isIP(stripBrackets(value));
  if (version === 4) {
    const [a, b] = value.split(".").map(Number) as [number, number, number, number];
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127 || (a === 169 && b === 254);
  }
  if (version === 6) {
    const normalized = stripBrackets(value).toLowerCase();
    return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80");
  }
  return false;
}

export function isCidr(value: string): boolean {
  return /^[^/\s]+\/\d{1,3}$/.test(value) && Boolean(parseCidr(value));
}

export function parseCidr(value: string): { network: bigint; bits: number; version: 4 | 6 } | null {
  const [address, suffix] = value.split("/");
  if (!address || suffix === undefined) return null;
  const version = isIP(stripBrackets(address));
  if (!version) return null;
  const bits = Number(suffix);
  const max = version === 4 ? 32 : 128;
  if (!Number.isInteger(bits) || bits < 0 || bits > max) return null;
  const ip = ipToBigInt(stripBrackets(address));
  const shift = BigInt(max - bits);
  return { network: (ip >> shift) << shift, bits, version: version as 4 | 6 };
}

function ipToBigInt(value: string): bigint {
  const version = isIP(value);
  if (version === 4) {
    return value.split(".").reduce((acc, part) => (acc << 8n) + BigInt(Number(part)), 0n);
  }
  if (version === 6) {
    const [head, tail] = value.toLowerCase().split("::");
    const headParts = head ? head.split(":") : [];
    const tailParts = tail ? tail.split(":") : [];
    const missing = 8 - headParts.length - tailParts.length;
    const parts = [...headParts, ...Array.from({ length: Math.max(0, missing) }, () => "0"), ...tailParts];
    return parts.reduce((acc, part) => (acc << 16n) + BigInt(parseInt(part || "0", 16)), 0n);
  }
  return 0n;
}

function samePrefix(a: { network: bigint; bits: number; version: 4 | 6 }, b: { network: bigint; bits: number; version: 4 | 6 }): boolean {
  if (a.version !== b.version) return false;
  const width = a.version === 4 ? 32 : 128;
  const bits = Math.min(a.bits, b.bits);
  const shift = BigInt(width - bits);
  return a.network >> shift === b.network >> shift;
}

function rangesOverlap(a: { network: bigint; bits: number; version: 4 | 6 }, b: { network: bigint; bits: number; version: 4 | 6 }): boolean {
  return samePrefix(a, b);
}
function pathWithin(candidate: string, root: string): boolean {
  const resolvedRoot = resolve(root);
  const resolvedCandidate = resolve(candidate);
  return resolvedCandidate === resolvedRoot || resolvedCandidate.startsWith(resolvedRoot.endsWith(sep) ? resolvedRoot : `${resolvedRoot}${sep}`);
}

function stripBrackets(value: string): string {
  return value.replace(/^\[|\]$/g, "");
}

function formatHostForUrl(host: string): string {
  return isIP(host) === 6 ? `[${host}]` : host;
}

function splitHostPort(value: string): { host: string; port?: number; rest: string } {
  const match = value.match(/^(\[[^\]]+\]|[^:/]+)(?::(\d{1,5}))?(\/.*)?$/);
  if (!match) return { host: value, rest: "" };
  const host = stripBrackets(match[1]!);
  const port = match[2] ? Number(match[2]) : undefined;
  return { host, port, rest: match[3] ?? "" };
}

function normalizeHost(host: string): string {
  return stripBrackets(host).toLowerCase().replace(/\.$/, "");
}

function isPlausibleHostname(host: string): boolean {
  if (!host) return false;
  if (host === "localhost") return true;
  if (isIP(host)) return true;
  return /^(?=.{1,253}$)(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(host);
}
