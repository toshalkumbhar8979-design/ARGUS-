import { ClipboardTarget } from "@opentui/core";
import type { TranscriptEntry } from "./state";
import { severityTag } from "./theme";

export type CopyChannel = "terminal" | "native";

export interface CopyResult {
  ok: boolean;
  channels: CopyChannel[];
  error?: string;
}

export interface ClipboardRenderer {
  copyToClipboardOSC52(text: string, target?: ClipboardTarget): boolean;
}

interface SpawnPlan {
  command: string[];
}

function nativePlans(text: string): SpawnPlan[] {
  if (process.env.ARGUS_CLIPBOARD === "off") return [];
  if (process.platform === "win32") {
    // clip.exe is fast but uses the console code page; PowerShell preserves Unicode.
    if (/[^\x00-\x7F]/.test(text)) {
      return [{ command: ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$input | Set-Clipboard"] }];
    }
    return [{ command: ["clip.exe"] }];
  }
  if (process.platform === "darwin") return [{ command: ["pbcopy"] }];
  return [
    { command: ["wl-copy"] },
    { command: ["xclip", "-selection", "clipboard"] },
    { command: ["xsel", "--clipboard", "--input"] },
  ];
}

async function runNative(command: string[], text: string): Promise<boolean> {
  let proc: ReturnType<typeof Bun.spawn> | undefined;
  try {
    proc = Bun.spawn(command, { stdin: "pipe", stdout: "ignore", stderr: "ignore" });
    const timer = setTimeout(() => {
      try {
        proc?.kill();
      } catch {
        // process already exited
      }
    }, 4_000);
    try {
      const sink = proc.stdin;
      if (!sink || typeof sink === "number") return false;
      sink.write(text);
      sink.end();
    } catch {
      // the command may exit before reading stdin; exit code decides success
    }
    const code = await proc.exited;
    clearTimeout(timer);
    return code === 0;
  } catch {
    return false;
  }
}

async function copyNative(text: string): Promise<boolean> {
  for (const plan of nativePlans(text)) {
    if (await runNative(plan.command, text)) return true;
  }
  return false;
}

function readPlans(): SpawnPlan[] {
  if (process.env.ARGUS_CLIPBOARD === "off") return [];
  if (process.platform === "win32") {
    return [{ command: ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"] }];
  }
  if (process.platform === "darwin") return [{ command: ["pbpaste"] }];
  return [
    { command: ["wl-paste", "--no-newline"] },
    { command: ["xclip", "-selection", "clipboard", "-o"] },
    { command: ["xsel", "--clipboard", "--output"] },
  ];
}

async function runRead(command: string[]): Promise<string | undefined> {
  let proc: ReturnType<typeof Bun.spawn> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    proc = Bun.spawn(command, { stdin: "ignore", stdout: "pipe", stderr: "ignore" });
    timer = setTimeout(() => {
      try {
        proc?.kill();
      } catch {
        // process already exited
      }
    }, 4_000);
    const text = await new Response(proc.stdout as ReadableStream<Uint8Array>).text();
    const code = await proc.exited;
    return code === 0 ? text.slice(0, 8_192) : undefined;
  } catch {
    return undefined;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Reads the platform clipboard. Used by key entry, where relying on the
 * terminal's paste shortcut alone leaves Ctrl+V doing nothing in many
 * terminals. Returns undefined when no native clipboard tool is available.
 */
export async function readClipboardText(): Promise<string | undefined> {
  for (const plan of readPlans()) {
    const text = await runRead(plan.command);
    if (text !== undefined) return text;
  }
  return undefined;
}

/**
 * Writes text through OSC 52 (works over SSH and inside most modern terminals)
 * and through the platform clipboard as a fallback. OSC 52 can be silently
 * ignored by a terminal, so both are attempted; success means at least one
 * channel accepted the text.
 */
export async function copyText(renderer: ClipboardRenderer, text: string): Promise<CopyResult> {
  const value = text.replace(/\r/g, "");
  if (!value.trim()) return { ok: false, channels: [], error: "nothing to copy" };
  const channels: CopyChannel[] = [];
  let terminal = false;
  try {
    terminal = renderer.copyToClipboardOSC52(value, ClipboardTarget.Clipboard);
  } catch {
    terminal = false;
  }
  if (terminal) channels.push("terminal");
  const native = await copyNative(value);
  if (native) channels.push("native");
  if (channels.length > 0) return { ok: true, channels };
  return {
    ok: false,
    channels,
    error:
      "clipboard unavailable - this terminal rejects OSC 52 and no native clipboard tool was found (install wl-clipboard/xclip, or shift+drag to use terminal selection)",
  };
}

const COPY_PREFIX: Record<string, string> = {
  user: "> ",
  ok: "+ ",
  warn: "! ",
  error: "x ",
  info: "- ",
  phase: ":: ",
};

/** Plain-text transcript for /copy all, matching the on-screen line markers. */
export function transcriptToText(entries: TranscriptEntry[]): string {
  return entries
    .map((entry) => {
      if (entry.kind === "finding") return `[${severityTag[entry.severity ?? "info"].trim()}] ${entry.text}`;
      const text = entry.kind === "system" ? entry.text.toUpperCase() : entry.text;
      return `${COPY_PREFIX[entry.kind] ?? ""}${text}`;
    })
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
