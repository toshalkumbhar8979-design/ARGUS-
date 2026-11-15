import type { ArgusEvent, EventLevel } from "../core/events";
import type { Finding, ProfileId, RunStatus, Severity, SeverityCounts, TaskStatus } from "../core/types";
import { emptyCounts } from "../core/util";

const MAX_LOGS = 400;

export type TranscriptKind = "user" | "system" | "info" | "ok" | "warn" | "error" | "dim" | "phase" | "finding";

export interface TranscriptEntry {
  id: number;
  kind: TranscriptKind;
  text: string;
  severity?: Severity;
}

export interface TaskView {
  id: string;
  label: string;
  phase: string;
  status: TaskStatus;
  durationMs?: number;
  message?: string;
}

export interface PhaseView {
  id: string;
  label: string;
  status: TaskStatus;
  durationMs?: number;
  tasks: TaskView[];
}

export interface LogView {
  at: string;
  level: EventLevel;
  message: string;
  source?: string;
}

export interface ScanState {
  runId?: string;
  target?: string;
  profile?: ProfileId;
  status: RunStatus;
  startedAt?: number;
  finishedAt?: number;
  phases: PhaseView[];
  findings: Finding[];
  logs: LogView[];
  counts: SeverityCounts;
  dependencies?: import("../core/types").DependencyGraphSnapshot;
  error?: string;
}

export function createScanState(seed: Partial<Pick<ScanState, "target" | "profile" | "status" | "startedAt">> = {}): ScanState {
  return {
    target: seed.target,
    profile: seed.profile,
    status: seed.status ?? "pending",
    startedAt: seed.startedAt,
    phases: [],
    findings: [],
    logs: [],
    counts: emptyCounts(),
  };
}

type TaskPatch = {
  id: string;
  label?: string;
  status?: TaskStatus;
  durationMs?: number;
  message?: string;
};

function ensurePhase(phases: PhaseView[], id: string, label?: string): PhaseView[] {
  if (phases.some((phase) => phase.id === id)) return phases;
  return [...phases, { id, label: label ?? id, status: "running", tasks: [] }];
}

function patchPhase(phases: PhaseView[], id: string, patch: Partial<Omit<PhaseView, "id" | "tasks">>): PhaseView[] {
  const next = ensurePhase(phases, id, patch.label);
  return next.map((phase) => {
    if (phase.id !== id) return phase;
    return {
      ...phase,
      label: patch.label ?? phase.label,
      status: patch.status ?? phase.status,
      durationMs: patch.durationMs ?? phase.durationMs,
    };
  });
}

function patchTask(phases: PhaseView[], phaseId: string, patch: TaskPatch): PhaseView[] {
  const next = ensurePhase(phases, phaseId);
  return next.map((phase) => {
    if (phase.id !== phaseId) return phase;
    const existing = phase.tasks.find((task) => task.id === patch.id);
    if (!existing) {
      return {
        ...phase,
        tasks: [
          ...phase.tasks,
          {
            id: patch.id,
            label: patch.label ?? patch.id,
            phase: phaseId,
            status: patch.status ?? "pending",
            durationMs: patch.durationMs,
            message: patch.message,
          },
        ],
      };
    }
    return {
      ...phase,
      tasks: phase.tasks.map((task) =>
        task.id !== patch.id
          ? task
          : {
              ...task,
              label: patch.label ?? task.label,
              status: patch.status ?? task.status,
              durationMs: patch.durationMs ?? task.durationMs,
              message: patch.message ?? task.message,
            },
      ),
    };
  });
}

function pushLog(logs: LogView[], entry: LogView): LogView[] {
  const next = [...logs, entry];
  return next.length > MAX_LOGS ? next.slice(next.length - MAX_LOGS) : next;
}

function recount(findings: Finding[]): SeverityCounts {
  const counts = emptyCounts();
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

function readTime(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/**
 * Folds an engine event into the live scan view model. Kept pure so the
 * terminal UI can be reasoned about (and tested) without a renderer.
 */
export function reduceScanEvent(state: ScanState, event: ArgusEvent): ScanState {
  switch (event.type) {
    case "run:start":
      return {
        ...state,
        runId: event.runId,
        target: event.target.display,
        profile: event.profile,
        status: "running",
        startedAt: readTime(event.at) ?? Date.now(),
      };
    case "phase:start":
      return {
        ...state,
        phases: patchPhase(state.phases, event.phase, { label: event.label, status: "running" }),
      };
    case "phase:end":
      return {
        ...state,
        phases: patchPhase(state.phases, event.phase, { status: event.status, durationMs: event.durationMs }),
      };
    case "task:start":
      return {
        ...state,
        phases: patchTask(state.phases, event.phase, { id: event.task, label: event.label, status: "running" }),
      };
    case "task:end":
      return {
        ...state,
        phases: patchTask(state.phases, event.phase, {
          id: event.task,
          status: event.status,
          durationMs: event.durationMs,
          message: event.message,
        }),
      };
    case "finding": {
      if (state.findings.some((finding) => finding.id === event.finding.id)) return state;
      const findings = [...state.findings, event.finding];
      return { ...state, findings, counts: recount(findings) };
    }
    case "log":
      return {
        ...state,
        logs: pushLog(state.logs, {
          at: event.at,
          level: event.level,
          message: event.message,
          source: event.source,
        }),
      };
    case "tool:status":
      return {
        ...state,
        logs: pushLog(state.logs, {
          at: event.at,
          level: event.status === "failed" ? "error" : "debug",
          message: `${event.tool} ${event.status}${event.message ? ` - ${event.message}` : ""}`,
          source: "tool",
        }),
      };
    case "mcp:status":
      return {
        ...state,
        logs: pushLog(state.logs, {
          at: event.at,
          level: event.status === "error" ? "error" : "debug",
          message: `${event.server} ${event.status}${event.message ? ` - ${event.message}` : ""}`,
          source: "mcp",
        }),
      };
    case "connector:status":
      return {
        ...state,
        logs: pushLog(state.logs, {
          at: event.at,
          level: event.status === "failed" ? "error" : "debug",
          message: `${event.connector} ${event.status}${event.message ? ` - ${event.message}` : ""}`,
          source: "connector",
        }),
      };
    case "run:end":
      return {
        ...state,
        status: event.status,
        finishedAt: readTime(event.at) ?? Date.now(),
        counts: event.counts,
      };
    default:
      return state;
  }
}

export interface ScanProgress {
  total: number;
  done: number;
  failed: number;
  skipped: number;
  phase?: PhaseView;
  task?: TaskView;
}

export function scanProgress(state: ScanState): ScanProgress {
  const progress: ScanProgress = { total: 0, done: 0, failed: 0, skipped: 0 };
  for (const phase of state.phases) {
    for (const task of phase.tasks) {
      progress.total += 1;
      if (task.status === "done") progress.done += 1;
      else if (task.status === "failed") progress.failed += 1;
      else if (task.status === "skipped") progress.skipped += 1;
      if (task.status === "running") {
        progress.phase = phase;
        progress.task = task;
      }
    }
    if (!progress.phase && phase.status === "running") progress.phase = phase;
  }
  return progress;
}

/** ASCII meter, e.g. [####------] - safe in any terminal and in log capture. */
export function meter(done: number, total: number, width = 10): string {
  const safeTotal = Math.max(1, total);
  const filled = Math.max(0, Math.min(width, Math.round((done / safeTotal) * width)));
  return `[${"#".repeat(filled)}${"-".repeat(width - filled)}]`;
}

export function elapsedMs(state: ScanState, now = Date.now()): number {
  if (!state.startedAt) return 0;
  return Math.max(0, (state.finishedAt ?? now) - state.startedAt);
}

export function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (hours > 0) return `${hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

export function formatStamp(iso: string | undefined): string {
  if (!iso) return " - ";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return " - ";
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function formatDurationMs(ms: number | undefined): string {
  if (ms === undefined) return "";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m`;
}

export function clampIndex(index: number, length: number): number {
  if (length <= 0) return 0;
  return Math.min(Math.max(0, index), length - 1);
}

export function moveIndex(index: number, delta: number, length: number): number {
  if (length <= 0) return 0;
  return (index + delta + length) % length;
}

export function windowed<T>(items: T[], selected: number, size: number): { items: T[]; offset: number } {
  const visible = Math.max(1, Math.floor(size));
  if (items.length <= visible) return { items, offset: 0 };
  const start = clampIndex(selected - Math.floor(visible / 2), items.length - visible + 1);
  return { items: items.slice(start, start + visible), offset: start };
}

export function totalFindings(counts: SeverityCounts): number {
  return counts.critical + counts.high + counts.medium + counts.low + counts.info;
}

/** Greedy word wrap that also hard-breaks overlong tokens. */
export function wrapText(text: string, width: number): string[] {
  const limit = Math.max(1, Math.floor(width));
  const output: string[] = [];
  for (const rawLine of text.replace(/\r\n/g, "\n").split("\n")) {
    const line = rawLine.replace(/\t/g, "  ").trimEnd();
    if (line.length === 0) {
      output.push("");
      continue;
    }
    let current = "";
    for (const word of line.split(/\s+/)) {
      if (!word) continue;
      if (current.length === 0) {
        current = word;
      } else if (current.length + 1 + word.length <= limit) {
        current = `${current} ${word}`;
      } else {
        output.push(current);
        current = word;
      }
      while (current.length > limit) {
        output.push(current.slice(0, limit));
        current = current.slice(limit);
      }
    }
    if (current.length > 0) output.push(current);
  }
  return output;
}

function labeled(label: string, value: string, width: number): string[] {
  const indent = " ".repeat(label.length + 2);
  const wrapped = wrapText(value, Math.max(12, width - label.length - 2));
  if (wrapped.length === 0) return [`${label}  `];
  const first = wrapped[0] ?? "";
  const rest = wrapped.slice(1).map((line) => `${indent}${line}`);
  return [`${label}  ${first}`, ...rest];
}

function section(title: string, body: string, width: number): string[] {
  return ["", title.toUpperCase(), "-".repeat(Math.min(width, Math.max(8, title.length + 4))), ...wrapText(body, width)];
}

export function buildFindingDetail(finding: Finding, width: number): string[] {
  const wide = Math.max(24, Math.floor(width));
  const lines: string[] = [];
  lines.push(...labeled("target", finding.target, wide));
  if (finding.url) lines.push(...labeled("url", finding.url, wide));
  lines.push(...labeled("category", `${finding.category} | ${finding.confidence} confidence`, wide));
  const standards = [finding.cwe, finding.owasp].filter((value): value is string => Boolean(value)).join(" | ");
  lines.push(...labeled("tool", standards ? `${finding.tool} | ${standards}` : finding.tool, wide));
  lines.push(...section("evidence", finding.evidence.trim() || "(no evidence captured)", wide));
  lines.push(...section("description", finding.description, wide));
  lines.push(...section("remediation", finding.remediation, wide));
  if (finding.references.length > 0) {
    lines.push(...section("references", finding.references.map((reference) => `- ${reference}`).join("\n"), wide));
  }
  return lines;
}

export function scanHeadline(state: ScanState): string {
  if (state.status === "running") return "assessment running";
  if (state.status === "aborted") return "assessment aborted";
  if (state.status === "failed") return "assessment failed";
  if (state.status === "completed") return "assessment complete";
  return "idle";
}
