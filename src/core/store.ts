import { mkdir, appendFile, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ArgusEvent } from "./events";
import type { Finding, RunHandle, RunRecord } from "./types";
import { emptyCounts, sortFindings } from "./util";

const RUN_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}$/;

export class RunStore {
  readonly dataDir: string;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
  }

  runDir(runId: string): string {
    if (!RUN_ID_PATTERN.test(runId)) throw new Error(`Invalid run id: ${runId}`);
    return join(this.dataDir, "runs", runId);
  }

  async init(): Promise<void> {
    await mkdir(join(this.dataDir, "runs"), { recursive: true });
    await mkdir(join(this.dataDir, "exports"), { recursive: true });
  }

  async saveRun(record: RunRecord): Promise<void> {
    const dir = this.runDir(record.id);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "run.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
  }

  async appendFinding(runId: string, finding: Finding): Promise<void> {
    const dir = this.runDir(runId);
    await mkdir(dir, { recursive: true });
    await appendFile(join(dir, "findings.jsonl"), `${JSON.stringify(finding)}\n`, "utf8");
  }

  async appendEvent(runId: string, event: ArgusEvent): Promise<void> {
    const dir = this.runDir(runId);
    await mkdir(dir, { recursive: true });
    await appendFile(join(dir, "events.jsonl"), `${JSON.stringify(event)}\n`, "utf8");
  }

  async load(runId: string): Promise<RunHandle | null> {
    let dir: string;
    try {
      dir = this.runDir(runId);
    } catch {
      return null;
    }
    if (!existsSync(join(dir, "run.json"))) return null;
    const record = JSON.parse(await readFile(join(dir, "run.json"), "utf8")) as RunRecord;
    const findings = await this.readJsonLines<Finding>(join(dir, "findings.jsonl"));
    return { record, findings: sortFindings(findings) };
  }

  async list(limit = 40): Promise<RunRecord[]> {
    const root = join(this.dataDir, "runs");
    if (!existsSync(root)) return [];
    const entries = await readdir(root, { withFileTypes: true });
    const records: RunRecord[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const file = join(root, entry.name, "run.json");
      if (!existsSync(file)) continue;
      try {
        const record = JSON.parse(await readFile(file, "utf8")) as RunRecord;
        records.push(record);
      } catch {
        // ignore corrupt run
      }
    }
    return records.sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, limit);
  }

  async listEvents(runId: string, limit = 500): Promise<ArgusEvent[]> {
    const events = await this.readJsonLines<ArgusEvent>(join(this.runDir(runId), "events.jsonl"));
    return events.slice(-limit);
  }

  async writeArtifact(runId: string, filename: string, content: string): Promise<string> {
    const safe = filename.replace(/[^a-zA-Z0-9._-]+/g, "-");
    const dir = this.runDir(runId);
    await mkdir(dir, { recursive: true });
    const path = join(dir, safe);
    await writeFile(path, content, "utf8");
    return path;
  }

  async listArtifacts(runId: string): Promise<Array<{ name: string; size: number; modified: string }>> {
    const dir = this.runDir(runId);
    if (!existsSync(dir)) return [];
    const entries = await readdir(dir, { withFileTypes: true });
    const artifacts: Array<{ name: string; size: number; modified: string }> = [];
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const info = await stat(join(dir, entry.name));
      artifacts.push({ name: entry.name, size: info.size, modified: info.mtime.toISOString() });
    }
    return artifacts.sort((a, b) => a.name.localeCompare(b.name));
  }

  async recoverStaleRuns(): Promise<number> {
    const runs = await this.list(200);
    let recovered = 0;
    for (const record of runs) {
      if (record.status === "running") {
        record.status = "failed";
        record.finishedAt = new Date().toISOString();
        record.error = "Run was interrupted before completion.";
        record.counts = record.counts ?? emptyCounts();
        await this.saveRun(record);
        recovered += 1;
      }
    }
    return recovered;
  }

  private async readJsonLines<T>(path: string): Promise<T[]> {
    if (!existsSync(path)) return [];
    const raw = await readFile(path, "utf8");
    const output: T[] = [];
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        output.push(JSON.parse(trimmed) as T);
      } catch {
        // skip truncated line
      }
    }
    return output;
  }
}
