import type { Finding } from "./types";

/**
 * Candidate patches for validated repository findings.
 *
 * The goal is a patch a human can read and apply, not a vague instruction:
 * every repo finding resolves to a path and line, and where a specific rule
 * has a safe mechanical fix we emit the exact replacement plus a one-line
 * unified diff. Rules without a safe mechanical rewrite still get the exact
 * file and line, and say so instead of inventing code.
 *
 * Nothing here writes to disk. A candidate patch is a proposal for the human
 * review gate.
 */

export interface CandidatePatchFile {
  path: string;
  line: number;
  /** The exact change: `before -> after` for a diff, or the required fix. */
  change: string;
  diff?: string;
}

export interface RepoLocation {
  path: string;
  line: number;
  rule?: string;
  source?: string;
}

const CODE_CATEGORIES = new Set(["code", "iac", "secrets", "supply-chain"]);

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function asLine(value: unknown): number | undefined {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number.parseInt(value, 10) : Number.NaN;
  return Number.isFinite(parsed) && parsed > 0 ? Math.trunc(parsed) : undefined;
}

/** Path and line for a repo finding, from metadata first and evidence second. */
export function repoLocation(finding: Finding): RepoLocation | undefined {
  const meta = (finding.metadata ?? {}) as Record<string, unknown>;
  const metaPath = asString(meta.path);
  const metaLine = asLine(meta.line);
  if (metaPath && metaLine) {
    return {
      path: metaPath,
      line: metaLine,
      rule: asString(meta.rule)?.toLowerCase(),
      source: asString(meta.source),
    };
  }
  if (!CODE_CATEGORIES.has(finding.category.trim().toLowerCase())) return undefined;
  const match = /^(.+?):(\d+)(?:\r?\n|$)/.exec(finding.evidence);
  if (!match || match[1]!.includes("://")) return undefined;
  const path = match[1]!.trim();
  const line = asLine(match[2]);
  if (!path || !line) return undefined;
  const rest = finding.evidence.slice(match[0].length).split(/\r?\n/)[0]?.trim();
  return { path, line, source: rest || undefined };
}

type Rewrite = (source: string) => string | undefined;

function swap(pattern: RegExp, replacement: string): Rewrite {
  return (source) => (pattern.test(source) ? source.replace(pattern, replacement) : undefined);
}

/**
 * Mechanical fixes that are safe enough to propose as a one-line diff. Rules
 * that need design work (SQL concatenation, eval removal, CORS allowlists,
 * credential rotation) are deliberately absent.
 */
const disablePrivileged = swap(/privileged(\s*):(\s*)true/i, "privileged$1:$2false");

const REWRITES: Record<string, Rewrite> = {
  innerhtml: swap(/\.innerHTML(\s*)=/, ".textContent$1="),
  "yaml-load": swap(/yaml\.load\(/, "yaml.safe_load("),
  "tls-verify-off": (source) => {
    if (/rejectUnauthorized\s*:\s*false/.test(source)) return source.replace(/rejectUnauthorized(\s*):(\s*)false/, "rejectUnauthorized$1:$2true");
    if (/NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/.test(source)) return source.replace(/(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?)0/, "$11");
    if (/verify\s*=\s*False/.test(source)) return source.replace(/verify(\s*)=(\s*)False/, "verify$1=$2True");
    if (/CURLOPT_SSL_VERIFYPEER\s*,\s*false/i.test(source)) return source.replace(/(CURLOPT_SSL_VERIFYPEER\s*,\s*)false/i, "$1true");
    return undefined;
  },
  "django-debug": (source) => {
    if (/\bDEBUG\s*=\s*True/.test(source)) return source.replace(/(\bDEBUG\s*=\s*)True/, "$1False");
    if (/debug\s*=\s*True/.test(source)) return source.replace(/(debug\s*=\s*)True/, "$1False");
    return undefined;
  },
  privileged: disablePrivileged,
  "k8s-priv": disablePrivileged,
  "k8s-net": swap(/hostNetwork(\s*):(\s*)true/i, "hostNetwork$1:$2false"),
  "k8s-esc": swap(/allowPrivilegeEscalation(\s*):(\s*)true/i, "allowPrivilegeEscalation$1:$2false"),
  encryption: swap(/encrypted(\s*)=(\s*)false/i, "encrypted$1=$2true"),
};

/** One-hunk unified diff for a single changed line. */
export function lineDiff(path: string, line: number, before: string, after: string): string {
  return [`--- a/${path}`, `+++ b/${path}`, `@@ -${line},1 +${line},1 @@`, `-${before}`, `+${after}`].join("\n");
}

/** Turn one finding into the exact file and change a patch would make. */
export function patchFileFor(finding: Finding): CandidatePatchFile | undefined {
  const location = repoLocation(finding);
  if (!location) return undefined;
  const rewrite = location.rule ? REWRITES[location.rule] : undefined;
  const after = rewrite && location.source ? rewrite(location.source) : undefined;
  if (after && location.source && after !== location.source) {
    return {
      path: location.path,
      line: location.line,
      change: `${location.source.trim()}  ->  ${after.trim()}`,
      diff: lineDiff(location.path, location.line, location.source, after),
    };
  }
  return {
    path: location.path,
    line: location.line,
    change: finding.remediation.trim() || "requires a design change; no mechanical rewrite",
  };
}

/** Deduplicated patch files for a group of findings, ordered by path and line. */
export function patchFilesFor(findings: Finding[]): CandidatePatchFile[] {
  const seen = new Set<string>();
  const files: CandidatePatchFile[] = [];
  for (const finding of findings) {
    const file = patchFileFor(finding);
    if (!file) continue;
    const key = `${file.path}:${file.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    files.push(file);
  }
  return files.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line);
}
