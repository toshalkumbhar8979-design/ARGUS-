/**
 * Attack journal: every tool the agent runs, what it pointed at, and whether it
 * worked. It is written automatically (not by the model), so the final report can
 * name the tools used and the surfaces attacked even if the model forgets.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { truncate } from "./util";

export interface JournalEntry {
  at: string;
  tool: string;
  target?: string;
  ok: boolean;
  detail?: string;
}

/** Pull the most useful "what was attacked" value out of a tool's arguments. */
export function journalTarget(args: Record<string, unknown>): string | undefined {
  const keys = ["target", "url", "command", "path", "host", "package", "name", "query", "pattern", "topic"];
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) return truncate(value.trim().replace(/\s+/g, " "), 180);
  }
  return undefined;
}

export class AttackJournal {
  readonly entries: JournalEntry[] = [];
  readonly startedAt = new Date().toISOString();

  record(entry: { tool: string; target?: string; ok: boolean; detail?: string }): void {
    this.entries.push({
      at: new Date().toISOString(),
      tool: entry.tool,
      ...(entry.target ? { target: entry.target } : {}),
      ok: entry.ok,
      ...(entry.detail ? { detail: truncate(entry.detail.replace(/\s+/g, " "), 220) } : {}),
    });
  }

  get size(): number {
    return this.entries.length;
  }

  /** Distinct tools with their call counts, most used first. */
  toolsUsed(): Array<{ tool: string; count: number }> {
    const counts = new Map<string, number>();
    for (const entry of this.entries) counts.set(entry.tool, (counts.get(entry.tool) ?? 0) + 1);
    return [...counts.entries()]
      .map(([tool, count]) => ({ tool, count }))
      .sort((a, b) => b.count - a.count || a.tool.localeCompare(b.tool));
  }

  /** Surfaces the agent actually pointed tools at, deduped. */
  attacked(): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const entry of this.entries) {
      if (!entry.target || seen.has(entry.target)) continue;
      seen.add(entry.target);
      out.push(entry.target);
    }
    return out;
  }

  toMarkdown(): string {
    if (this.entries.length === 0) return "";
    const tools = this.toolsUsed();
    const lines: string[] = [];
    lines.push("## Attack journal");
    lines.push("");
    lines.push(`Automatic record of every tool call in this turn, started ${this.startedAt}.`);
    lines.push("");
    lines.push("### Tools used");
    lines.push("");
    for (const entry of tools) lines.push(`- \`${entry.tool}\` x${entry.count}`);
    lines.push("");
    const surfaces = this.attacked();
    if (surfaces.length > 0) {
      lines.push("### Surfaces and packages touched");
      lines.push("");
      for (const surface of surfaces.slice(0, 60)) lines.push(`- \`${surface.replace(/`/g, "'")}\``);
      if (surfaces.length > 60) lines.push(`- ...and ${surfaces.length - 60} more`);
      lines.push("");
    }
    lines.push("### Chronological attempts");
    lines.push("");
    lines.push("| time | tool | target / action | result |");
    lines.push("| --- | --- | --- | --- |");
    for (const entry of this.entries.slice(-120)) {
      const cell = (value: string) => value.replace(/\|/g, "\\|").replace(/\n/g, " ");
      lines.push(
        `| ${entry.at} | ${cell(entry.tool)} | ${cell(entry.target ?? entry.detail ?? "")} | ${entry.ok ? "ok" : "failed"} |`,
      );
    }
    return lines.join("\n");
  }

  async save(dataDir: string, name = "turn"): Promise<string> {
    const path = join(dataDir, "journals", `${name}-${this.startedAt.replace(/[:.]/g, "-")}.md`);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${this.toMarkdown()}\n`);
    return path;
  }
}
