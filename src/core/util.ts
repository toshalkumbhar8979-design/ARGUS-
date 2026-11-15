import { createHash, randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { SEVERITIES, SEVERITY_RANK, type Confidence, type Severity, type SeverityCounts } from "./types";

export function newId(prefix: string): string {
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  return `${prefix}-${stamp}-${randomBytes(3).toString("hex")}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function expandHome(input: string): string {
  if (input === "~") return homedir();
  if (input.startsWith("~/") || input.startsWith("~\\")) return resolve(homedir(), input.slice(2));
  return resolve(input);
}

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function countSeverities(severities: Severity[]): SeverityCounts {
  const counts = emptyCounts();
  for (const severity of severities) counts[severity] += 1;
  return counts;
}

export function sortFindings<T extends { severity: Severity; timestamp: string; title: string }>(findings: T[]): T[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return a.timestamp.localeCompare(b.timestamp) || a.title.localeCompare(b.title);
  });
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 100,
  high: 70,
  medium: 40,
  low: 15,
  info: 5,
};

const CONFIDENCE_WEIGHT: Record<Confidence, number> = {
  confirmed: 18,
  likely: 9,
  possible: 2,
};

/**
 * Deterministic exploitability ordering for the terminal report. The engine
 * does not assign CVSS scores, so this is a transparent triage score: severity
 * dominates, confirmation level breaks ties, and high-impact categories get a
 * small nudge. It never changes a finding's stored severity or confidence.
 */
export function findingRiskScore(finding: {
  severity: Severity;
  confidence: Confidence;
  title: string;
  category: string;
}): number {
  const text = `${finding.title} ${finding.category}`.toLowerCase();
  const categoryBoost = /rce|remote code|auth|session|secret|credential|sqli|injection|traversal|ssrf|idor/.test(text)
    ? 8
    : /header|cookie|tls|certificate|config|version|exposure/.test(text)
      ? 2
      : 0;
  return SEVERITY_WEIGHT[finding.severity] + CONFIDENCE_WEIGHT[finding.confidence] + categoryBoost;
}

export function rankFindings<
  T extends { severity: Severity; confidence: Confidence; title: string; category: string; timestamp?: string },
>(findings: T[]): T[] {
  return [...findings].sort((a, b) => {
    const byRisk = findingRiskScore(b) - findingRiskScore(a);
    if (byRisk !== 0) return byRisk;
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return (a.timestamp ?? "").localeCompare(b.timestamp ?? "") || a.title.localeCompare(b.title);
  });
}

export function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

export function severityAtLeast(value: Severity, minimum: Severity): boolean {
  return SEVERITY_RANK[value] <= SEVERITY_RANK[minimum];
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

export function oneLine(value: string, max = 160): string {
  const flat = value.replace(/\s+/g, " ").trim();
  return truncate(flat, max);
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function fingerprint(parts: Array<string | undefined | null>): string {
  return sha256(parts.filter(Boolean).join("|")).slice(0, 24);
}

export function maskSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 8) return "********";
  return `${trimmed.slice(0, 4)}…${trimmed.slice(-4)}`;
}

export function timestampSlug(date = new Date()): string {
  return date.toISOString().replace(/[:.TZ]/g, "-");
}

export function safeFilename(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "argus";
}

export function parseList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(/[,\n]/)
    .map((part) => part.trim())
    .filter(Boolean);
}

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      resolvePromise();
    }, ms);
    const onAbort = () => {
      cleanup();
      reject(new Error("aborted"));
    };
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    if (signal?.aborted) {
      cleanup();
      reject(new Error("aborted"));
      return;
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.max(0, Math.round(ms))}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.round((ms % 60_000) / 1000);
  return `${minutes}m ${seconds}s`;
}

export function stripAnsi(value: string): string {
  return value.replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "");
}

export function jsonBlock(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function dedupe<T>(items: T[]): T[] {
  return [...new Set(items)];
}

export function chunk<T>(items: T[], size: number): T[][] {
  const output: T[][] = [];
  for (let index = 0; index < items.length; index += size) output.push(items.slice(index, index + size));
  return output;
}
