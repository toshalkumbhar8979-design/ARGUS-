import { basename } from "node:path";
import type { AgentPreviewPayload } from "../core/agent";
import { truncate } from "../core/util";

/**
 * One preview payload shared by the `/preview` command, the terminal panel and
 * the agent's read-only `preview` tool. It is plain data so the panel stays a
 * pure render of what the tool or the operator asked to look at.
 */
export type PreviewPayload = AgentPreviewPayload;

export type PreviewTone = "text" | "add" | "del" | "hunk" | "meta";

export interface PreviewRow {
  /** Source line number, when the payload knows it. */
  no?: number;
  marker: string;
  text: string;
  tone: PreviewTone;
}

const MAX_ROWS = 4000;

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  ts: "typescript",
  tsx: "tsx",
  mts: "typescript",
  cts: "typescript",
  js: "javascript",
  jsx: "jsx",
  mjs: "javascript",
  cjs: "javascript",
  json: "json",
  jsonc: "json",
  md: "markdown",
  markdown: "markdown",
  yml: "yaml",
  yaml: "yaml",
  toml: "toml",
  py: "python",
  rb: "ruby",
  go: "go",
  rs: "rust",
  java: "java",
  kt: "kotlin",
  c: "c",
  h: "c",
  cc: "cpp",
  cpp: "cpp",
  hpp: "cpp",
  cs: "csharp",
  php: "php",
  swift: "swift",
  sh: "bash",
  bash: "bash",
  zsh: "bash",
  ps1: "powershell",
  sql: "sql",
  html: "html",
  htm: "html",
  css: "css",
  scss: "scss",
  xml: "xml",
  dockerfile: "dockerfile",
  env: "bash",
};

/** Best-effort language label; highlighting is optional, the label never is. */
export function languageFor(path: string): string {
  const name = basename(path).toLowerCase();
  if (name === "dockerfile") return "dockerfile";
  if (name === ".env" || name.startsWith(".env.")) return "bash";
  const ext = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1) : "";
  return LANGUAGE_BY_EXTENSION[ext] ?? "text";
}

/** Numbered source lines, the same shape the agent's `preview` tool returns. */
export function textPreview(
  path: string,
  content: string,
  options: { start?: number; end?: number; source?: "agent" | "operator" } = {},
): PreviewPayload {
  const all = content.split(/\r?\n/);
  const start = Math.max(1, Math.floor(options.start ?? 1));
  const end = Math.min(all.length, Math.max(start, Math.floor(options.end ?? start + 199)));
  return {
    path,
    mode: "text",
    exists: true,
    source: options.source ?? "operator",
    start,
    end,
    totalLines: all.length,
    preview: all
      .slice(start - 1, end)
      .map((line, index) => `${start + index}| ${line}`)
      .join("\n"),
    truncated: start > 1 || end < all.length,
    note: "read-only preview; nothing is written",
  };
}

/** Rows the panel draws: numbered source lines, or a parsed unified diff. */
export function previewRows(payload: PreviewPayload, limit = MAX_ROWS): PreviewRow[] {
  const rows: PreviewRow[] = [];
  if (payload.mode === "diff") {
    for (const line of (payload.diff ?? "").split(/\r?\n/).slice(0, limit)) {
      if (line.startsWith("@@")) {
        rows.push({ marker: "@", text: line, tone: "hunk" });
        continue;
      }
      if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff ")) {
        rows.push({ marker: " ", text: line, tone: "meta" });
        continue;
      }
      if (line.startsWith("+")) {
        rows.push({ marker: "+", text: line.slice(1), tone: "add" });
        continue;
      }
      if (line.startsWith("-")) {
        rows.push({ marker: "-", text: line.slice(1), tone: "del" });
        continue;
      }
      rows.push({ marker: " ", text: line.startsWith(" ") ? line.slice(1) : line, tone: "text" });
    }
    return rows;
  }

  for (const raw of (payload.preview ?? "").split(/\r?\n/).slice(0, limit)) {
    const match = raw.match(/^(\d+)\|\s?(.*)$/);
    if (match) {
      rows.push({ no: Number(match[1]), marker: " ", text: match[2] ?? "", tone: "text" });
      continue;
    }
    if (raw.trim()) rows.push({ marker: " ", text: raw, tone: "meta" });
  }
  return rows;
}

export function previewTitle(payload: PreviewPayload): string {
  return `Preview ${basename(payload.path) || payload.path}`;
}

/** One dense status line for the panel header. */
export function previewSubtitle(payload: PreviewPayload): string {
  // Details first, path last: the path already sits in the panel border title.
  const bits: string[] = [];
  if (payload.mode === "diff") {
    bits.push(payload.exists ? "would change" : "would create");
    bits.push(payload.unchanged ? "no changes" : `+${payload.additions ?? 0}/-${payload.deletions ?? 0}`);
  } else {
    bits.push(`${payload.totalLines ?? 0} lines`);
    if (payload.start !== undefined && payload.end !== undefined) bits.push(`showing ${payload.start}-${payload.end}`);
  }
  bits.push(languageFor(payload.path));
  if (payload.source === "agent") bits.push("from the agent");
  if (payload.truncated) bits.push("truncated");
  bits.push(payload.path);
  return bits.join(" | ");
}

/** Compact one-line note the transcript prints when a preview opens. */
export function previewNote(payload: PreviewPayload, width = 120): string {
  const detail =
    payload.mode === "diff"
      ? payload.unchanged
        ? "no changes"
        : `+${payload.additions ?? 0}/-${payload.deletions ?? 0}`
      : `${payload.totalLines ?? 0} lines`;
  return `${truncate(payload.path, Math.max(20, width - 32))} | ${detail} | esc closes`;
}
