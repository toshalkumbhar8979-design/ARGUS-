import { existsSync, statSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { inferAllowedTargets } from "./agent";
import { loadScopeFile } from "./config";
import { ensureLocalScope, isCidr } from "./scope";
import type { ProfileId, ScopePolicy } from "./types";
import { expandHome, sha256 } from "./util";

export interface PromptScopeSignal {
  /** Explicitly asked for a read-only / no-request pass. */
  passive: boolean;
  /** Explicitly asked for state-changing or aggressive checks. */
  intrusive: boolean;
  /** Registry, OSV and subdomain intelligence are allowed. */
  external: boolean;
  /** The operator asked to widen or replace the current scope. */
  override: boolean;
  /** Include subdomains / the whole domain. */
  broad: boolean;
  /** Explicitly remove deny rules from the current scope. */
  clearDeny: boolean;
}

export interface PromptScopeOptions {
  workspace?: string;
  targets?: string[];
  profile?: ProfileId;
  previous?: ScopePolicy;
  maxRps?: number;
  now?: Date;
  passive?: boolean;
  intrusive?: boolean;
  external?: boolean;
  override?: boolean;
  broad?: boolean;
  clearDeny?: boolean;
}

export interface EnsurePromptScopeResult {
  path: string;
  scope: ScopePolicy;
  created: boolean;
  updated: boolean;
  source: "prompt" | "local" | "manual";
}

const PASSIVE_PATTERN = /\b(passive(?:\s+only)?|read[- ]?only|no\s+active|do\s+not\s+(?:send|touch|request)|offline|static\s+only)\b/i;
const INTRUSIVE_PATTERN =
  /\b(intrusive|aggressive|state[- ]?changing|write\s+(?:tests?|checks?|payloads?)|destructive|full|everything|all\s+checks|no\s+limits|unrestricted|override|overrule|bypass)\b/i;
const NO_EXTERNAL_PATTERN = /\b(no\s+external|offline|local\s+only|no\s+network\s+lookups?|do\s+not\s+query|no\s+registry)\b/i;
const OVERRIDE_PATTERN = /\b(override|overrule|widen|expand|replace\s+(?:the\s+)?scope|ignore\s+(?:the\s+)?scope|new\s+scope|clear\s+(?:the\s+)?deny|ignore\s+deny)\b/i;
const BROAD_PATTERN = /\b(subdomains?|whole\s+domain|entire\s+domain|wildcard|all\s+hosts|all\s+subdomains)\b/i;
const CLEAR_DENY_PATTERN = /\b(clear\s+(?:the\s+)?deny|ignore\s+deny|no\s+deny\s+rules?)\b/i;

const ATTACK_PATTERN =
  /\b(attack|hack|hacking|exploit|pwn|compromise|break\s+in|take\s+(?:it\s+)?over|ruthless(?:ly)?|hit\s+it\s+hard|brute[- ]?force|fuzz(?:ing)?|sql\s*injection|command\s+injection|xss|ssrf|rce|idor)\b/i;

/**
 * The verbs that ask to break in. Technique names (xss, ssrf, idor) are left
 * out on purpose: mentioning one while asking what it is must never look like a
 * request to attack, so it cannot trigger the authorization prompt.
 */
const ATTACK_VERB_PATTERN =
  /\b(attack|hack|hacking|exploit|pwn|compromise|break\s+in|take\s+(?:it\s+)?over|ruthless(?:ly)?|hit\s+it\s+hard|brute[- ]?force|fuzz(?:ing)?)\b/i;

/**
 * True when the sentence asks to break in. The TUI shows the intrusive
 * authorization prompt for these requests instead of quietly refusing.
 */
export function wantsAttackRequest(prompt: string): boolean {
  return ATTACK_VERB_PATTERN.test(prompt) || INTRUSIVE_PATTERN.test(prompt);
}

/**
 * True when the sentence is a request to break in rather than review. The TUI
 * turns this into an explicit authorization prompt when the current scope still
 * locks intrusive testing, instead of quietly running read-only checks and
 * leaving the operator thinking the tool refused.
 */
export function wantsAggressiveScope(prompt: string): boolean {
  return INTRUSIVE_PATTERN.test(prompt) || ATTACK_PATTERN.test(prompt);
}

/** Plain-English switches; no magic flags or scope file are required. */
export function parsePromptScopeSignal(prompt: string): PromptScopeSignal {
  return {
    passive: PASSIVE_PATTERN.test(prompt),
    intrusive: INTRUSIVE_PATTERN.test(prompt),
    external: !NO_EXTERNAL_PATTERN.test(prompt),
    override: OVERRIDE_PATTERN.test(prompt),
    broad: BROAD_PATTERN.test(prompt),
    clearDeny: CLEAR_DENY_PATTERN.test(prompt),
  };
}

function resolveSignal(prompt: string, options: PromptScopeOptions): PromptScopeSignal {
  const parsed = parsePromptScopeSignal(prompt);
  return {
    passive: options.passive ?? parsed.passive,
    intrusive: options.intrusive ?? parsed.intrusive,
    external: options.external ?? parsed.external,
    override: options.override ?? parsed.override,
    broad: options.broad ?? parsed.broad,
    clearDeny: options.clearDeny ?? parsed.clearDeny,
  };
}

function unique(values: string[]): string[] {
  const seen = new Set<string>();
  const output: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(trimmed);
  }
  return output;
}

function hostForTarget(target: string): { host: string; port?: number } | undefined {
  try {
    if (/^https?:\/\//i.test(target)) {
      const url = new URL(target);
      return { host: url.hostname, port: url.port ? Number(url.port) : undefined };
    }
  } catch {
    return undefined;
  }
  if (target.includes("/") || target.includes("\\")) return undefined;
  const match = target.match(/^(\[[^\]]+\]|[^:]+)(?::(\d{1,5}))?$/);
  if (!match) return undefined;
  const host = match[1]!.replace(/^\[|\]$/g, "");
  const port = match[2] ? Number(match[2]) : undefined;
  return { host, port };
}

function allowEntriesFor(target: string, broad: boolean): { allow: string[]; ports: number[] } {
  const trimmed = target.trim();
  if (!trimmed) return { allow: [], ports: [] };
  if (existsSync(trimmed)) return { allow: [resolve(expandHome(trimmed))], ports: [] };
  if (isCidr(trimmed)) return { allow: [trimmed], ports: [] };

  const parsed = hostForTarget(trimmed);
  if (!parsed) return { allow: [], ports: [] };
  const host = parsed.host.toLowerCase();
  if (!host) return { allow: [], ports: [] };

  const renderedHost = host.includes(":") ? `[${host}]` : host;
  const entries = [parsed.port ? `${renderedHost}:${parsed.port}` : renderedHost];
  const isDomain = !isCidr(host) && host !== "localhost" && host.includes(".") && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
  // A bare domain names the site and its subdomains. An explicit URL or port
  // stays exact, so `https://app.example.com` does not silently widen.
  const bareDomain = isDomain && !/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) && !parsed.port;
  if ((broad || bareDomain) && isDomain) entries.push(`*.${host}`);
  return { allow: entries, ports: parsed.port ? [parsed.port] : [] };
}

function targetSummary(targets: string[]): string {
  const readable = targets.map((target) => target.replace(/\\/g, "/").split("/").filter(Boolean).pop() ?? target);
  const head = readable.slice(0, 3).join(", ");
  return readable.length > 3 ? `${head} +${readable.length - 3} more` : head;
}

export function hasNetworkTarget(targets: string[]): boolean {
  return targets.some((target) => {
    if (existsSync(target)) return false;
    return /^https?:\/\//i.test(target) || isCidr(target) || Boolean(hostForTarget(target));
  });
}

/**
 * Builds a scope from the operator's sentence. The target list is the only
 * authorization input; the scope file is a durable record, not a setup step.
 */
export function promptScopePolicy(prompt: string, options: PromptScopeOptions = {}): ScopePolicy | undefined {
  const workspace = resolve(expandHome(options.workspace ?? process.cwd()));
  const targets = unique(
    options.targets ??
      inferAllowedTargets(prompt, {
        workspace,
        scopeTargets: options.previous?.allow,
      }),
  );
  if (targets.length === 0) return undefined;

  const signal = resolveSignal(prompt, options);
  const allow: string[] = [];
  const ports: number[] = [];
  for (const target of targets) {
    const entries = allowEntriesFor(target, signal.broad);
    allow.push(...entries.allow);
    ports.push(...entries.ports);
  }
  const dedupedAllow = unique(allow);
  if (dedupedAllow.length === 0) return undefined;

  const now = options.now ?? new Date();
  const localOnly = !hasNetworkTarget(targets);
  const previousDeny = signal.clearDeny ? [] : (options.previous?.deny ?? []);
  const localDeny = targets.some((target) => existsSync(target))
    ? [resolve(workspace, ".git"), resolve(workspace, "node_modules")]
    : [];
  const deny = unique([...previousDeny, ...localDeny]);
  const allowedPorts = unique(ports.map(String)).map(Number).filter((port) => Number.isInteger(port));
  const excerpt = sha256(prompt.trim().toLowerCase()).slice(0, 16);

  return {
    version: 1,
    name: localOnly ? `Prompt review: ${targetSummary(targets)}` : `Prompt assessment: ${targetSummary(targets)}`,
    authorizedBy: "operator prompt",
    authorizationRef: `PROMPT ${now.toISOString()} ${excerpt}`,
    expiresAt: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    allow: dedupedAllow,
    deny,
    maxRps: options.maxRps ?? options.previous?.maxRps ?? 40,
    allowedPorts: allowedPorts.length > 0 ? allowedPorts : undefined,
    allowActive: !signal.passive && !localOnly,
    allowIntrusive: !signal.passive && !localOnly && signal.intrusive,
    allowExternal: signal.external,
  };
}

/** Local directories a prompt scope explicitly authorizes for read/search. */
export function localRootsForScope(scope: ScopePolicy | undefined): string[] {
  if (!scope) return [];
  const roots: string[] = [];
  for (const entry of scope.allow ?? []) {
    if (/^https?:\/\//i.test(entry) || isCidr(entry)) continue;
    const path = resolve(expandHome(entry));
    try {
      if (statSync(path).isDirectory()) roots.push(path);
    } catch {
      // non-existent or non-file entries are not read roots
    }
  }
  return unique(roots);
}

/** Scopes written by Argus itself are safe to update in place. */
export function isGeneratedScope(scope: ScopePolicy): boolean {
  return (
    scope.authorizedBy === "operator prompt" ||
    scope.authorizationRef.startsWith("PROMPT ") ||
    scope.authorizationRef.startsWith("LOCAL-SOURCE-REVIEW") ||
    /auto-created|prompt review|prompt assessment/i.test(scope.name)
  );
}

function mergeScope(base: ScopePolicy, derived: ScopePolicy, signal: PromptScopeSignal): ScopePolicy {
  const allow = unique([...(base.allow ?? []), ...(derived.allow ?? [])]);
  const deny = signal.clearDeny ? unique(derived.deny ?? []) : unique([...(base.deny ?? []), ...(derived.deny ?? [])]);
  const ports = derived.allowedPorts?.length
    ? unique([...(base.allowedPorts ?? []), ...derived.allowedPorts].map(String))
        .map(Number)
        .filter((port) => Number.isInteger(port))
    : [];
  return {
    ...derived,
    allow,
    deny,
    maxRps: derived.maxRps ?? base.maxRps,
    allowedPorts: ports.length > 0 ? ports : undefined,
    allowActive: signal.passive ? false : Boolean(base.allowActive) || Boolean(derived.allowActive),
    allowIntrusive: signal.passive ? false : Boolean(base.allowIntrusive) || Boolean(derived.allowIntrusive),
    allowExternal: signal.external ? Boolean(base.allowExternal) || Boolean(derived.allowExternal) : false,
  };
}

async function readScope(path: string): Promise<ScopePolicy | undefined> {
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(await readFile(path, "utf8")) as ScopePolicy;
  } catch {
    return undefined;
  }
}

async function writeScope(path: string, scope: ScopePolicy): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(scope, null, 2)}\n`, "utf8");
}

/**
 * Resolves and persists the active scope for a prompt. Existing operator files
 * are never overwritten; a prompt-derived sibling (`scope.prompt.json`) is used
 * instead, and its allow-list grows as the operator names new targets.
 */
export async function ensurePromptScope(
  scopePath: string,
  prompt: string,
  options: PromptScopeOptions = {},
): Promise<EnsurePromptScopeResult> {
  const path = resolve(expandHome(scopePath));
  const workspace = resolve(expandHome(options.workspace ?? process.cwd()));
  const signal = resolveSignal(prompt, options);
  const existing = options.previous ?? (await readScope(path));
  const derived = promptScopePolicy(prompt, { ...options, workspace, previous: existing });
  if (!derived) {
    if (existing) {
      return { path, scope: existing, created: false, updated: false, source: isGeneratedScope(existing) ? "prompt" : "manual" };
    }
    const local = await ensureLocalScope(path, workspace, options.now);
    return { path: local.path, scope: local.scope, created: local.created, updated: false, source: "local" };
  }

  let targetPath = path;
  let base = existing;
  if (existing && !isGeneratedScope(existing)) {
    targetPath = basename(path).toLowerCase() === "scope.prompt.json"
      ? join(dirname(path), "scope.session.json")
      : join(dirname(path), "scope.prompt.json");
    const sibling = await readScope(targetPath);
    if (sibling) {
      // Keep the prompt file's switches (full/aggressive can persist) while
      // retaining every target and deny rule from the operator file.
      base = {
        ...sibling,
        allow: unique([...(existing.allow ?? []), ...(sibling.allow ?? [])]),
        deny: unique([...(existing.deny ?? []), ...(sibling.deny ?? [])]),
        allowedPorts: sibling.allowedPorts?.length ? sibling.allowedPorts : existing.allowedPorts,
      };
    }
  }

  const scope = base ? mergeScope(base, derived, signal) : derived;
  const existed = Boolean(await readScope(targetPath));
  await writeScope(targetPath, scope);
  return {
    path: targetPath,
    scope,
    created: !existed,
    updated: existed,
    source: "prompt",
  };
}
