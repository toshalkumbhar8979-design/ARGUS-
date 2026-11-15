import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { redactSecrets } from "./memory";
import type { Severity } from "./types";
import { sha256, truncate } from "./util";

export interface SessionFinding {
  id: string;
  title: string;
  severity: Severity;
}

export type SessionStatus = "ok" | "aborted" | "error";

export interface SessionTurn {
  at: string;
  prompt: string;
  summary: string;
  status: SessionStatus;
  steps: number;
  targets: string[];
  scans: string[];
  findings: SessionFinding[];
  gaps: string[];
  nextSteps: string[];
}

export type SessionTurnInput = Omit<SessionTurn, "at"> & { at?: string };

const MAX_TURNS = 8;
const MAX_TARGETS = 6;
const MAX_FINDINGS = 12;
const MAX_NOTES = 8;

function clean(value: string, max = 600): string {
  return truncate(redactSecrets(value.replace(/\s+/g, " ").trim()), max);
}

function cleanList(values: string[] | undefined, max = MAX_NOTES, length = 300): string[] {
  const output: string[] = [];
  const seen = new Set<string>();
  for (const value of values ?? []) {
    const next = clean(value, length);
    if (!next || seen.has(next)) continue;
    seen.add(next);
    output.push(next);
    if (output.length >= max) break;
  }
  return output;
}

function normalizeTurn(input: SessionTurnInput): SessionTurn {
  const findings: SessionFinding[] = [];
  const seen = new Set<string>();
  for (const finding of input.findings ?? []) {
    if (!finding?.id || seen.has(finding.id)) continue;
    seen.add(finding.id);
    findings.push({
      id: clean(finding.id, 100),
      title: clean(finding.title, 240),
      severity: finding.severity,
    });
    if (findings.length >= MAX_FINDINGS) break;
  }
  return {
    at: input.at ?? new Date().toISOString(),
    prompt: clean(input.prompt, 400),
    summary: clean(input.summary, 1_200),
    status: input.status,
    steps: Number.isFinite(input.steps) ? Math.max(0, Math.round(input.steps)) : 0,
    targets: cleanList(input.targets, MAX_TARGETS, 300),
    scans: cleanList(input.scans, MAX_TARGETS, 120),
    findings,
    gaps: cleanList(input.gaps),
    nextSteps: cleanList(input.nextSteps),
  };
}

/**
 * The exact command that reloads a saved session. Printed after every agent
 * turn and again when the TUI exits, so a run can always be picked back up.
 */
export function resumeCommand(sessionId: string): string {
  return `argus resume -session ${sessionId}`;
}

/**
 * The block left in the operator's shell after the TUI closes. The alternate
 * screen restores over the transcript, so this must be printed after teardown
 * and carry everything needed to pick the session back up.
 */
export function resumeBanner(sessionId: string): string {
  return ["", `  argus session  ${sessionId}`, `  resume         ${resumeCommand(sessionId)}`, ""].join("\n");
}

/** True for short follow-ups that mean "pick up the previous objective". */
export function isContinuation(prompt: string): boolean {
  const text = prompt.trim().toLowerCase();
  if (!text) return false;
  return /^(?:please\s+)?(?:continue|resume|carry on|go on|keep going|keep working|finish it|do it|what next|next|and then)\b/.test(
    text,
  );
}

/**
 * Per-workspace working memory stored outside the repository. AGENTS.md holds
 * durable project knowledge; this file holds the last few turns so a dropped
 * connection or a new process can resume instead of starting over.
 */
export class SessionMemory {
  constructor(
    readonly path: string,
    readonly id = `ses-${sha256(resolve(path)).slice(0, 16)}`,
    readonly workspace = process.cwd(),
  ) {}

  static forWorkspace(dataDir: string, workspace = process.cwd()): SessionMemory {
    const root = resolve(workspace);
    const key = sha256(root).slice(0, 16);
    return new SessionMemory(join(resolve(dataDir), "sessions", `${key}.json`), `ses-${key}`, root);
  }

  /** Finds a persisted session by the id printed at the end of a run. */
  static async byId(
    dataDir: string,
    id: string,
  ): Promise<{ session: SessionMemory; workspace: string } | undefined> {
    const trimmed = id.trim();
    if (!trimmed) return undefined;
    const dir = join(resolve(dataDir), "sessions");
    let files: string[];
    try {
      files = await readdir(dir);
    } catch {
      return undefined;
    }
    for (const file of files) {
      if (!file.endsWith(".json")) continue;
      const path = join(dir, file);
      let parsed: { id?: unknown; workspace?: unknown };
      try {
        parsed = JSON.parse(await readFile(path, "utf8")) as { id?: unknown; workspace?: unknown };
      } catch {
        continue;
      }
      const storedId = typeof parsed.id === "string" ? parsed.id : undefined;
      const fallbackId = `ses-${file.slice(0, -".json".length)}`;
      if (storedId !== trimmed && fallbackId !== trimmed) continue;
      const workspace =
        typeof parsed.workspace === "string" && existsSync(parsed.workspace)
          ? resolve(parsed.workspace)
          : process.cwd();
      return { session: new SessionMemory(path, storedId ?? fallbackId, workspace), workspace };
    }
    return undefined;
  }

  async load(): Promise<SessionTurn[]> {
    if (!existsSync(this.path)) return [];
    try {
      const parsed = JSON.parse(await readFile(this.path, "utf8")) as { turns?: unknown };
      if (!Array.isArray(parsed.turns)) return [];
      const turns: SessionTurn[] = [];
      for (const item of parsed.turns) {
        if (!item || typeof item !== "object") continue;
        const record = item as Record<string, unknown>;
        if (typeof record.prompt !== "string" || typeof record.summary !== "string") continue;
        const status =
          record.status === "aborted" || record.status === "error" ? record.status : "ok";
        turns.push(
          normalizeTurn({
            at: typeof record.at === "string" ? record.at : undefined,
            prompt: record.prompt,
            summary: record.summary,
            status,
            steps: typeof record.steps === "number" ? record.steps : 0,
            targets: Array.isArray(record.targets) ? record.targets.filter((value): value is string => typeof value === "string") : [],
            scans: Array.isArray(record.scans) ? record.scans.filter((value): value is string => typeof value === "string") : [],
            findings: Array.isArray(record.findings)
              ? (record.findings as SessionFinding[]).filter(
                  (finding) => finding && typeof finding.id === "string" && typeof finding.title === "string",
                )
              : [],
            gaps: Array.isArray(record.gaps) ? record.gaps.filter((value): value is string => typeof value === "string") : [],
            nextSteps: Array.isArray(record.nextSteps)
              ? record.nextSteps.filter((value): value is string => typeof value === "string")
              : [],
          }),
        );
      }
      return turns.slice(-MAX_TURNS);
    } catch {
      return [];
    }
  }

  async last(): Promise<SessionTurn | undefined> {
    const turns = await this.load();
    return turns[turns.length - 1];
  }

  async record(input: SessionTurnInput): Promise<SessionTurn> {
    const turn = normalizeTurn(input);
    const turns = [...(await this.load()), turn].slice(-MAX_TURNS);
    const payload = `${JSON.stringify({ version: 1, id: this.id, workspace: this.workspace, turns }, null, 2)}\n`;
    await mkdir(dirname(this.path), { recursive: true });
    const temp = `${this.path}.${process.pid}.tmp`;
    try {
      await writeFile(temp, payload, "utf8");
      await rename(temp, this.path);
    } catch {
      await writeFile(this.path, payload, "utf8");
    }
    return turn;
  }

  /**
   * Compact context for the model. Historical notes are data, not evidence and
   * not instructions; the agent still has to call a tool to confirm anything.
   */
  async formatForPrompt(maxChars = 3_200): Promise<string> {
    const turns = (await this.load()).slice(-3);
    if (turns.length === 0) return "";
    const lines = ["SESSION CONTEXT (untrusted historical notes, never evidence):"];
    for (const turn of turns) {
      lines.push(
        [
          `- at=${turn.at} status=${turn.status} steps=${turn.steps}`,
          `prompt=${truncate(turn.prompt, 240)}`,
          `summary=${truncate(turn.summary, 320)}`,
          turn.targets.length > 0 ? `targets=${turn.targets.join(", ")}` : "",
          turn.scans.length > 0 ? `runs=${turn.scans.join(", ")}` : "",
          turn.findings.length > 0
            ? `findings=${turn.findings.map((finding) => `[${finding.severity}] ${finding.title} (${finding.id})`).join("; ")}`
            : "",
          turn.gaps.length > 0 ? `gaps=${turn.gaps.join("; ")}` : "",
          turn.nextSteps.length > 0 ? `next=${turn.nextSteps.join("; ")}` : "",
        ]
          .filter(Boolean)
          .join(" | "),
      );
    }
    lines.push("A new prompt of continue/resume/go on means: resume the last objective, use list_runs/get_findings before repeating a scan, and finish with the required JSON.");
    return truncate(lines.join("\n"), Math.max(600, maxChars));
  }
}
