import { existsSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { truncate } from "./util";

export const MEMORY_FILENAME = "AGENTS.md";
export const MEMORY_SECTION = "## Argus memory";

const MAX_ENTRIES = 24;
const MAX_BYTES = 48_000;

const TEMPLATE = `# Project memory

This file is the project's durable memory for authorized security work.
Argus reads it before an assessment and appends verified outcomes after one.
Keep it factual. Never store API keys, session tokens, passwords, or personal data.

${MEMORY_SECTION}
`;

export interface MemoryAppendResult {
  path: string;
  appended: boolean;
}

export function memoryPath(workspace = process.cwd()): string {
  return resolve(workspace, MEMORY_FILENAME);
}

function memoryEnabled(): boolean {
  return process.env.ARGUS_MEMORY !== "off";
}

/** Creates AGENTS.md when it does not exist yet. Existing files are never rewritten. */
export async function ensureProjectMemory(workspace = process.cwd()): Promise<string> {
  const path = memoryPath(workspace);
  if (!memoryEnabled()) return path;
  if (existsSync(path)) return path;
  await mkdir(dirname(path), { recursive: true });
  try {
    await writeFile(path, TEMPLATE, { encoding: "utf8", flag: "wx" });
  } catch {
    // another process created it first; use theirs
  }
  return path;
}

export async function readProjectMemory(workspace = process.cwd()): Promise<string> {
  try {
    return await readFile(memoryPath(workspace), "utf8");
  } catch {
    return "";
  }
}

/**
 * Memory is injected as data, capped so a long-lived file cannot crowd out the
 * actual request. It is deliberately not treated as instructions.
 */
export async function memoryForPrompt(workspace = process.cwd(), maxChars = 6000): Promise<string> {
  const content = (await readProjectMemory(workspace)).trim();
  if (!content) return "";
  return truncate(content, Math.max(500, maxChars));
}

function sanitizeTitle(title: string): string {
  return truncate(title.replace(/\s+/g, " ").trim(), 90);
}

/** Memory is long-lived; never persist recognizable credentials by accident. */
export function redactSecrets(value: string): string {
  return value
    .replace(
      /\b(?:sk-|sk_live_|sk_test_|nvapi-|gsk_|xai-|AIza|ghp_|github_pat_|whsec_|AKIA|ASIA)[A-Za-z0-9_-]{8,}\b/g,
      "[redacted]",
    )
    .replace(/\bBearer\s+[A-Za-z0-9._-]{8,}\b/gi, "Bearer [redacted]");
}

function splitEntries(body: string): string[] {
  return body
    .split(/\n(?=### )/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/** Keeps the newest entries and the original header, so memory stays readable and bounded. */
export function pruneMemory(content: string): string {
  const index = content.indexOf(MEMORY_SECTION);
  if (index < 0) return content;
  const head = content.slice(0, index + MEMORY_SECTION.length).trimEnd();
  const entries = splitEntries(content.slice(index + MEMORY_SECTION.length));
  if (entries.length === 0) return `${head}\n`;

  let kept = entries.slice(-MAX_ENTRIES);
  let next = `${head}\n\n${kept.join("\n\n")}\n`;
  if (next.length > MAX_BYTES) {
    kept = kept.slice(-8);
    next = `${head}\n\n${kept.join("\n\n")}\n`;
  }
  return next;
}

let appendQueue: Promise<unknown> = Promise.resolve();

/**
 * Appends one dated block. A dedupe key makes repeated runs of the same scan
 * idempotent instead of filling the file with copies. Writes are serialized in
 * this process so parallel subagents cannot lose each other's notes.
 */
export function appendProjectMemory(
  workspace: string,
  entry: string,
  options: { title?: string; key?: string } = {},
): Promise<MemoryAppendResult> {
  const task = appendQueue.then(() => appendProjectMemoryUnlocked(workspace, entry, options));
  appendQueue = task.then(
    () => undefined,
    () => undefined,
  );
  return task;
}

async function appendProjectMemoryUnlocked(
  workspace: string,
  entry: string,
  options: { title?: string; key?: string } = {},
): Promise<MemoryAppendResult> {
  const path = memoryPath(workspace);
  if (!memoryEnabled()) return { path, appended: false };
  const body = redactSecrets(entry.trim());
  if (!body) return { path, appended: false };

  await ensureProjectMemory(workspace);
  const existing = await readProjectMemory(workspace);
  const marker = options.key ? `<!-- argus-key: ${options.key} -->` : undefined;
  if (marker && existing.includes(marker)) return { path, appended: false };

  const stamp = new Date().toISOString().replace("T", " ").slice(0, 16);
  const heading = `### ${stamp}${options.title ? ` — ${sanitizeTitle(options.title)}` : ""}`;
  const block = [heading, marker, body].filter((line): line is string => Boolean(line)).join("\n");

  const base = existing.trim()
    ? existing.includes(MEMORY_SECTION)
      ? existing.trimEnd()
      : `${existing.trimEnd()}\n\n${MEMORY_SECTION}`
    : TEMPLATE.trimEnd();

  const next = pruneMemory(`${base}\n\n${block}\n`);
  const temp = `${path}.${process.pid}.tmp`;
  try {
    await writeFile(temp, next, "utf8");
    await rename(temp, path);
  } catch {
    await writeFile(path, next, "utf8");
  }
  return { path, appended: true };
}
