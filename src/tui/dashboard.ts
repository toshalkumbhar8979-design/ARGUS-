import { buildPipeline } from "../core/pipeline";
import { buildFixPlan } from "../core/remediation";
import { SEVERITIES, type DependencyGraphSnapshot, type Finding, type Severity, type SeverityCounts } from "../core/types";
import { emptyCounts, findingRiskScore, sortFindings, truncate } from "../core/util";
import { GLYPH, severityTag } from "./theme";

export type DashTone = "text" | "muted" | "faint" | "accent" | "ok" | "warn" | "error" | Severity;

export interface DashLine {
  text: string;
  tone: DashTone;
  /** When set, the panel draws this as a coloured chip before the text. */
  tag?: string;
  /** Section heading: the panel fills the rest of the row with a hairline. */
  rule?: boolean;
}

export interface DashboardPhase {
  id: string;
  label: string;
  status: string;
  durationMs?: number;
  tasks?: Array<{ status: string }>;
}

export interface DashboardInput {
  target?: string;
  profile?: string;
  status?: string;
  runId?: string;
  findings: Finding[];
  phases: DashboardPhase[];
  elapsedMs?: number;
  dependencies?: DependencyGraphSnapshot;
}

const WEIGHT: Record<Severity, number> = {
  critical: 35,
  high: 15,
  medium: 6,
  low: 1.5,
  info: 0.2,
};

const LABEL = 12;
const GAP = "  ";

export function severityCounts(findings: Finding[]): SeverityCounts {
  const counts = emptyCounts();
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/** Capped, deterministic risk score so the same findings always render the same gauge. */
export function riskScore(findings: Finding[]): number {
  let score = 0;
  for (const finding of findings) {
    const base = WEIGHT[finding.severity];
    const confidence = finding.confidence === "confirmed" ? 1 : finding.confidence === "likely" ? 0.7 : 0.45;
    score += base * confidence;
  }
  return Math.min(100, Math.round(score));
}

export function riskGrade(score: number): { label: string; tone: DashTone } {
  if (score === 0) return { label: "clean", tone: "ok" };
  if (score < 10) return { label: "low", tone: "ok" };
  if (score < 30) return { label: "guarded", tone: "info" };
  if (score < 60) return { label: "elevated", tone: "warn" };
  if (score < 85) return { label: "high", tone: "high" };
  return { label: "critical", tone: "critical" };
}

/**
 * Solid block gauge: ██████░░░░. Blocks read as a chart in every terminal that
 * can render the box-drawing range, unlike a run of equals signs.
 */
export function bar(value: number, max: number, width: number): string {
  const size = Math.max(4, Math.floor(width));
  const ratio = max <= 0 ? 0 : Math.min(1, value / max);
  const filled = value <= 0 ? 0 : Math.max(1, Math.round(ratio * size));
  return `${"█".repeat(Math.min(size, filled))}${"░".repeat(Math.max(0, size - filled))}`;
}

function pct(value: number, total: number): string {
  if (total <= 0) return "0%";
  return `${Math.round((value / total) * 100)}%`;
}

function shortStamp(ms?: number): string {
  if (!ms || ms <= 0) return "-";
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
}

function row(label: string, value: string, tone: DashTone = "text", tag?: string): DashLine {
  return { text: `${truncate(label, LABEL).padEnd(LABEL)}${GAP}${value}`, tone, tag };
}

/** Section heading; the panel fills the rest of the row with a hairline. */
function section(lines: DashLine[], title: string, _width: number): void {
  lines.push({ text: "", tone: "faint" });
  lines.push({ text: title.toUpperCase(), tone: "accent", rule: true });
}

function categoryCounts(findings: Finding[]): Array<{ label: string; count: number }> {
  const map = new Map<string, number>();
  for (const finding of findings) {
    const label = finding.category || "uncategorized";
    map.set(label, (map.get(label) ?? 0) + 1);
  }
  return [...map.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

function taskSummary(phases: DashboardPhase[]): { total: number; done: number; failed: number; running: number } {
  let total = 0;
  let done = 0;
  let failed = 0;
  let running = 0;
  for (const phase of phases) {
    for (const task of phase.tasks ?? []) {
      total += 1;
      if (task.status === "done") done += 1;
      else if (task.status === "failed") failed += 1;
      else if (task.status === "running") running += 1;
    }
  }
  return { total, done, failed, running };
}

function statusTag(status: string): string {
  if (status === "done" || status === "completed") return GLYPH.done;
  if (status === "failed" || status === "error") return GLYPH.fail;
  if (status === "running") return "~";
  if (status === "skipped" || status === "aborted") return GLYPH.note;
  return ".";
}

function statusTone(status: string): DashTone {
  if (status === "done" || status === "completed") return "ok";
  if (status === "failed" || status === "error") return "error";
  if (status === "running") return "info";
  return "faint";
}

function latestCheckLabel(check: DependencyGraphSnapshot["summary"]["latestCheck"]): string {
  if (check === "registry") return "npm registry queried";
  if (check === "failed") return "registry unreachable";
  return "skipped (scope.allowExternal=false)";
}

function graphTree(snapshot: DependencyGraphSnapshot, limit = 8): DashLine[] {
  if (snapshot.nodes.length === 0) return [{ text: "no dependency nodes resolved", tone: "faint" }];
  const byKey = new Map(snapshot.nodes.map((node) => [node.key, node]));
  const children = new Map<string, typeof snapshot.nodes>();
  for (const edge of snapshot.edges) {
    const node = byKey.get(edge.to);
    if (!node) continue;
    const list = children.get(edge.from) ?? [];
    if (!list.some((entry) => entry.key === node.key)) list.push(node);
    children.set(edge.from, list);
  }
  const output: DashLine[] = [{ text: "root", tone: "faint" }];
  const direct = snapshot.nodes.filter((node) => node.direct).slice(0, 4);
  for (const node of direct) {
    output.push({ text: `+- ${truncate(`${node.name} ${node.version}`, 42)}`, tone: node.outdated ? "warn" : "muted" });
    const child = (children.get(node.key) ?? []).filter((entry) => entry.key !== "root").slice(0, 2);
    for (const entry of child) {
      output.push({ text: `|  +- ${truncate(`${entry.name} ${entry.version}`, 36)}`, tone: "faint" });
    }
    const extra = (children.get(node.key) ?? []).length - child.length;
    if (extra > 0) output.push({ text: `|  +- ${extra} more`, tone: "faint" });
    if (output.length >= limit) break;
  }
  if (output.length < limit) {
    const hidden = snapshot.summary.nodes - direct.length;
    if (hidden > 0) output.push({ text: `+- ${hidden} other node(s) in lockfile`, tone: "faint" });
  }
  return output.slice(0, limit);
}

export function buildDashboard(input: DashboardInput, width: number): DashLine[] {
  const inner = Math.max(40, Math.floor(width));
  const findings = sortFindings(input.findings);
  const counts = severityCounts(findings);
  const total = findings.length;
  const score = riskScore(findings);
  const grade = riskGrade(score);
  const lines: DashLine[] = [];
  const gaugeWidth = Math.max(10, Math.min(28, inner - 36));

  lines.push({ text: "OVERVIEW", tone: "accent" });
  lines.push(row("target", input.target ?? "no target", "muted"));
  lines.push(row("profile", input.profile ?? "default", "faint"));
  lines.push(row("status", `${statusTag(input.status ?? "pending")} ${input.status ?? "pending"}`, statusTone(input.status ?? "pending")));
  lines.push(row("run", `${input.runId ?? "-"}${GAP}·${GAP}elapsed ${shortStamp(input.elapsedMs)}`, "faint"));
  lines.push(row("findings", String(total), total > 0 ? "warn" : "ok"));

  section(lines, "risk", inner);
  lines.push(row("score", `${String(score).padStart(3, " ")}/100${GAP}${bar(score, 100, gaugeWidth)}${GAP}${grade.label.toUpperCase()}`, grade.tone));
  lines.push(
    row(
      "confidence",
      `confirmed ${findings.filter((finding) => finding.confidence === "confirmed").length}${GAP}·${GAP}likely ${findings.filter((finding) => finding.confidence === "likely").length}${GAP}·${GAP}possible ${findings.filter((finding) => finding.confidence === "possible").length}`,
      "faint",
    ),
  );

  if (total > 0) {
    section(lines, "severity", inner);
    const maxSeverity = Math.max(1, ...SEVERITIES.map((severity) => counts[severity]));
    const severityBar = Math.max(8, Math.min(24, inner - 34));
    for (const severity of SEVERITIES) {
      lines.push({
        text: `${severity.padEnd(9)}${GAP}${String(counts[severity]).padStart(3, " ")}${GAP}${pct(counts[severity], total).padStart(4, " ")}${GAP}${bar(counts[severity], maxSeverity, severityBar)}`,
        tone: severity,
      });
    }
  }

  const categories = categoryCounts(findings).slice(0, 8);
  if (categories.length > 0) {
    section(lines, "categories", inner);
    const maxCategory = Math.max(...categories.map((entry) => entry.count));
    for (const entry of categories) {
      lines.push({
        text: `${truncate(entry.label, 18).padEnd(18)}${GAP}${String(entry.count).padStart(3, " ")}${GAP}${bar(entry.count, maxCategory, Math.min(20, inner - 28))}`,
        tone: "info",
      });
    }
  }

  if (input.phases.length > 0) {
    section(lines, "coverage", inner);
    const tasks = taskSummary(input.phases);
    if (tasks.total > 0) {
      lines.push(
        row(
          "probes",
          `${tasks.done}/${tasks.total} done${GAP}·${GAP}${tasks.failed} failed${GAP}·${GAP}${tasks.running} running${GAP}${bar(tasks.done, tasks.total, Math.min(22, inner - 50))}`,
          tasks.failed > 0 ? "warn" : "ok",
        ),
      );
    }
    const phaseBar = Math.max(6, Math.min(16, inner - 56));
    for (const phase of input.phases) {
      const phaseTasks = phase.tasks ?? [];
      const done = phaseTasks.filter((task) => task.status === "done").length;
      const failed = phaseTasks.filter((task) => task.status === "failed").length;
      const suffix = phaseTasks.length > 0 ? `${done}/${phaseTasks.length}` : "";
      lines.push({
        text: `${truncate(phase.label, 18).padEnd(18)} ${statusTag(phase.status)} ${(phaseTasks.length ? bar(done, phaseTasks.length, phaseBar) : " ".repeat(phaseBar + 2))}${GAP}${suffix}${failed > 0 ? `${GAP}·${GAP}${failed} failed` : ""}${GAP}${shortStamp(phase.durationMs)}`,
        tone: phase.status === "failed" ? "warn" : statusTone(phase.status),
      });
    }
  }

  if (input.dependencies) {
    const snapshot = input.dependencies;
    section(lines, "dependencies", inner);
    const sources = [...snapshot.manifests, ...snapshot.lockfiles].slice(0, 3).join(" | ") || "none";
    lines.push(row("source", `${truncate(sources, Math.max(20, inner - LABEL - 2))}${GAP}·${GAP}${snapshot.summary.packageManager}`, "faint"));
    lines.push(
      row(
        "graph",
        `${snapshot.summary.nodes} nodes${GAP}·${GAP}${snapshot.summary.direct} direct${GAP}·${GAP}${snapshot.summary.transitive} transitive${GAP}·${GAP}${snapshot.summary.edges} edges`,
        "muted",
      ),
    );
    const outdatedValue =
      snapshot.summary.latestCheck === "registry"
        ? `${snapshot.summary.outdated} of ${snapshot.summary.direct} direct outdated`
        : `not checked${GAP}·${GAP}${latestCheckLabel(snapshot.summary.latestCheck)}`;
    lines.push(
      row(
        "outdated",
        outdatedValue,
        snapshot.summary.latestCheck !== "registry" ? "faint" : snapshot.summary.outdated > 0 ? "warn" : "ok",
      ),
    );
    const direct = snapshot.nodes
      .filter((node) => node.direct)
      .sort((a, b) => Number(Boolean(b.outdated)) - Number(Boolean(a.outdated)) || a.name.localeCompare(b.name))
      .slice(0, 6);
    for (const node of direct) {
      const suffix = node.latest
        ? `${node.version} -> ${node.latest}${node.outdated ? "  outdated" : "  current"}`
        : `${node.version}  latest unknown`;
      lines.push({
        text: `  ${truncate(node.name, 24).padEnd(24)} ${suffix}`,
        tone: node.outdated ? "warn" : "faint",
      });
    }
    if (snapshot.nodes.length > 0) {
      lines.push({ text: "", tone: "faint" });
      lines.push({ text: "GRAPH", tone: "accent", rule: true });
      lines.push(...graphTree(snapshot, 8));
    }
    for (const note of snapshot.notes.slice(0, 2)) lines.push({ text: `note  ${truncate(note, Math.max(20, inner - 6))}`, tone: "faint" });
  }

  const plan = buildFixPlan(findings, 5);
  if (plan.length > 0) {
    section(lines, "remediation", inner);
    for (const action of plan) {
      lines.push({
        text: `${action.priority}${GAP}${truncate(action.remediation, Math.max(24, inner - 6))}`,
        tone: action.severity,
      });
      lines.push({
        text: `     ${action.count} finding(s) | ${truncate(action.examples.join(" | "), Math.max(24, inner - 8))}`,
        tone: "faint",
      });
    }
  }

  section(lines, `findings · ${total}`, inner);
  if (findings.length === 0) {
    lines.push({ text: `${statusTag("done")} clean pass - no findings recorded`, tone: "ok" });
  } else {
    const limit = 14;
    for (const finding of findings.slice(0, limit)) {
      lines.push({
        tag: severityTag[finding.severity],
        text: `risk ${String(findingRiskScore(finding)).padStart(3, " ")}${GAP}${truncate(finding.title, Math.max(20, inner - 30))}`,
        tone: finding.severity,
      });
      lines.push({
        text: `       ${finding.confidence} | ${finding.category} | ${truncate(finding.url ?? finding.target, Math.max(20, inner - 22))}`,
        tone: "faint",
      });
    }
    if (findings.length > limit) {
      lines.push({ text: `+${findings.length - limit} more | /findings --all`, tone: "faint" });
    }
  }

  const pipeline = buildPipeline(findings);
  section(lines, "pipeline", inner);
  lines.push({
    text: truncate(
      pipeline.stages
        .slice(0, 3)
        .map((stage) => `${stage.count} ${stage.id}`)
        .join(`${GAP}·${GAP}`),
      Math.max(24, inner - 4),
    ),
    tone: "info",
  });
  lines.push({
    text: truncate(
      pipeline.stages
        .slice(3)
        .map((stage) => `${stage.count} ${stage.id}`)
        .join(`${GAP}·${GAP}`),
      Math.max(24, inner - 4),
    ),
    tone: pipeline.review.status === "awaiting" ? "info" : "faint",
  });

  if (input.phases.some((phase) => (phase.tasks ?? []).some((task) => task.status === "failed"))) {
    lines.push({ text: "", tone: "faint" });
    lines.push({ text: `${statusTag("failed")} coverage gaps above - retry with /scan <target> --retries 3`, tone: "warn" });
  }

  return lines;
}
