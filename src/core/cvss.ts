/**
 * CVSS v3.1 scoring: base, temporal and environmental groups.
 *
 * Base metrics are required. Temporal metrics (E, RL, RC) and environmental
 * metrics (CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA) are optional; when a
 * group is absent its score is undefined rather than silently equal to base.
 * Vectors that are malformed, incomplete or carry unknown metrics are rejected.
 */
import type { Severity } from "./types";

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
const E: Record<string, number> = { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 };
const RL: Record<string, number> = { X: 1, U: 0.95, W: 0.96, T: 0.97, O: 1 };
const RC: Record<string, number> = { X: 1, U: 0.92, R: 0.96, C: 1 };
const CR_IR_AR: Record<string, number> = { X: 1, L: 0.5, M: 1, H: 1.5 };

const REQUIRED = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"] as const;
const TEMPORAL = ["E", "RL", "RC"] as const;
const ENVIRONMENTAL = ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"] as const;

export interface CvssResult {
  vector: string;
  /** Base score. Kept as `score` for backwards compatibility. */
  score: number;
  baseScore: number;
  temporalScore?: number;
  environmentalScore?: number;
  severity: Severity;
}

function roundUp(value: number): number {
  const scaled = Number((value * 10).toFixed(6));
  return Math.ceil(scaled) / 10;
}

export function severityForScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

function metric(metrics: Map<string, string>, key: string, fallback: string): string {
  const value = metrics.get(key) ?? fallback;
  return value === "X" ? fallback : value;
}

function baseMetrics(metrics: Map<string, string>): boolean {
  const scope = metrics.get("S");
  if (scope !== "U" && scope !== "C") return false;
  if (!(metrics.get("AV")! in AV)) return false;
  if (!(metrics.get("AC")! in AC)) return false;
  if (!(metrics.get("PR")! in PR_UNCHANGED)) return false;
  if (!(metrics.get("UI")! in UI)) return false;
  return ["C", "I", "A"].every((key) => metrics.get(key)! in CIA);
}

function optionalMetrics(metrics: Map<string, string>): boolean {
  for (const key of TEMPORAL) {
    if (metrics.has(key) && !(metrics.get(key)! in (key === "E" ? E : key === "RL" ? RL : RC))) return false;
  }
  for (const key of ENVIRONMENTAL) {
    if (!metrics.has(key)) continue;
    const value = metrics.get(key)!;
    if (key === "CR" || key === "IR" || key === "AR") {
      if (!(value in CR_IR_AR)) return false;
    } else if (key === "MAV") {
      if (!(value in AV)) return false;
    } else if (key === "MAC") {
      if (!(value in AC)) return false;
    } else if (key === "MPR") {
      if (!(value in PR_UNCHANGED)) return false;
    } else if (key === "MUI") {
      if (!(value in UI)) return false;
    } else if (key === "MS") {
      if (value !== "X" && value !== "U" && value !== "C") return false;
    } else if (!(value in CIA)) {
      return false;
    }
  }
  return true;
}

function impactScore(scope: "U" | "C", c: number, i: number, a: number): number {
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  return scope === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
}

function baseScore(metrics: Map<string, string>): number {
  const scope = metrics.get("S") === "C" ? "C" : "U";
  const pr = scope === "C" ? PR_CHANGED[metrics.get("PR")!]! : PR_UNCHANGED[metrics.get("PR")!]!;
  const impact = impactScore(scope, CIA[metrics.get("C")!]!, CIA[metrics.get("I")!]!, CIA[metrics.get("A")!]!);
  if (impact <= 0) return 0;
  const exploitability = 8.22 * AV[metrics.get("AV")!]! * AC[metrics.get("AC")!]! * pr * UI[metrics.get("UI")!]!;
  return scope === "U"
    ? roundUp(Math.min(impact + exploitability, 10))
    : roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

function temporalScore(metrics: Map<string, string>, base: number): number | undefined {
  const present = TEMPORAL.some((key) => metrics.has(key));
  if (!present) return undefined;
  const e = E[metric(metrics, "E", "X")] ?? 1;
  const rl = RL[metric(metrics, "RL", "X")] ?? 1;
  const rc = RC[metric(metrics, "RC", "X")] ?? 1;
  return roundUp(base * e * rl * rc);
}

function environmentalScore(metrics: Map<string, string>, base: number): number | undefined {
  const present = ENVIRONMENTAL.some((key) => metrics.has(key));
  if (!present) return undefined;
  const scope = metric(metrics, "MS", metric(metrics, "S", "U")) === "C" ? "C" : "U";
  const mav = AV[metric(metrics, "MAV", metric(metrics, "AV", "N"))] ?? 0.85;
  const mac = AC[metric(metrics, "MAC", metric(metrics, "AC", "L"))] ?? 0.77;
  const rawPr = metric(metrics, "MPR", metric(metrics, "PR", "N"));
  const mui = UI[metric(metrics, "MUI", metric(metrics, "UI", "N"))] ?? 0.85;
  const mc = CIA[metric(metrics, "MC", metric(metrics, "C", "N"))] ?? 0;
  const mi = CIA[metric(metrics, "MI", metric(metrics, "I", "N"))] ?? 0;
  const ma = CIA[metric(metrics, "MA", metric(metrics, "A", "N"))] ?? 0;
  const cr = CR_IR_AR[metric(metrics, "CR", "X")] ?? 1;
  const ir = CR_IR_AR[metric(metrics, "IR", "X")] ?? 1;
  const ar = CR_IR_AR[metric(metrics, "AR", "X")] ?? 1;
  const mpr = scope === "C" ? (PR_CHANGED[rawPr] ?? 0.85) : (PR_UNCHANGED[rawPr] ?? 0.85);
  const modifiedImpact = impactScore(scope, mc, mi, ma);
  if (modifiedImpact <= 0) return 0;
  const modifiedExploitability = 8.22 * mav * mac * mpr * mui;
  const combined =
    scope === "U"
      ? roundUp(Math.min(modifiedImpact + modifiedExploitability, 10))
      : roundUp(Math.min(1.08 * (modifiedImpact + modifiedExploitability), 10));
  void base;
  return roundUp(Math.min(combined * cr * ir * ar, 10));
}

/** Parses a CVSS v3.0/3.1 vector and returns base, temporal and environmental scores. */
export function parseCvssVector(input: string): CvssResult | undefined {
  const trimmed = input.trim();
  if (!trimmed) return undefined;
  const body = trimmed.replace(/^CVSS:3\.[01]\//i, "");
  const metrics = new Map<string, string>();
  for (const part of body.split("/")) {
    const [key, value, ...rest] = part.split(":");
    if (!key || !value || rest.length > 0) return undefined;
    const metricKey = key.toUpperCase();
    if (metrics.has(metricKey)) return undefined;
    metrics.set(metricKey, value.toUpperCase());
  }
  if (!REQUIRED.every((key) => metrics.has(key))) return undefined;
  const allowed = new Set<string>([...REQUIRED, ...TEMPORAL, ...ENVIRONMENTAL]);
  if ([...metrics.keys()].some((key) => !allowed.has(key))) return undefined;
  if (!baseMetrics(metrics) || !optionalMetrics(metrics)) return undefined;

  const base = baseScore(metrics);
  const temporal = temporalScore(metrics, base);
  const environmental = environmentalScore(metrics, base);
  const effective = environmental ?? temporal ?? base;
  return {
    vector: trimmed,
    score: base,
    baseScore: base,
    ...(temporal !== undefined ? { temporalScore: temporal } : {}),
    ...(environmental !== undefined ? { environmentalScore: environmental } : {}),
    severity: severityForScore(base),
  };
}

/** Accepts either a vector or a bare numeric score. */
export function normalizeCvss(input: string | number | undefined): CvssResult | undefined {
  if (input === undefined) return undefined;
  if (typeof input === "number") {
    if (!Number.isFinite(input) || input < 0 || input > 10) return undefined;
    const score = Number(input.toFixed(1));
    return { vector: `CVSS:3.1 (score ${score})`, score, baseScore: score, severity: severityForScore(score) };
  }
  const numeric = Number(input.trim());
  if (Number.isFinite(numeric) && /^\d+(?:\.\d+)?$/.test(input.trim())) {
    return normalizeCvss(numeric);
  }
  return parseCvssVector(input);
}
