/**
 * WSL execution backend: use a real Kali Linux distribution when the host is
 * Windows and WSL is installed.
 *
 * Detection is read-only. Installing Kali is a separate, operator-approved
 * action (`wsl --install -d kali-linux`); nothing here elevates by itself.
 * Commands run as the distro's default user, which is the operator's own
 * account - so scope, not a container, is the boundary.
 */
import { spawn } from "node:child_process";

export const DEFAULT_WSL_DISTRO = process.env.ARGUS_WSL_DISTRO?.trim() || "kali-linux";
export const WSL_INSTALL_ARGS = ["--install", "-d", "kali-linux", "--no-launch"] as const;

export interface WslDistro {
  name: string;
  state: string;
  version: string;
  default: boolean;
}

export interface WslStatus {
  available: boolean;
  distros: WslDistro[];
  kali?: string;
  defaultDistro?: string;
  error?: string;
}

export interface WslRunOptions {
  distro?: string;
  command: string;
  /** Linux-side working directory; Windows paths are not valid here. */
  cwd?: string;
  timeoutMs?: number;
  /** Receives output while the command is still running. */
  onOutput?: (chunk: string, stream: "stdout" | "stderr") => void;
  /** Run as root inside the distro (needed for apt without a sudo password). */
  root?: boolean;
}

export interface WslRunResult {
  stdout: string;
  stderr: string;
  code: number;
  timedOut: boolean;
  durationMs: number;
  distro: string;
}

export function wslExecutable(): string {
  return process.env.ARGUS_WSL?.trim() || "wsl.exe";
}

/** Some WSL builds emit UTF-16LE even with WSL_UTF8; normalize both. */
export function decodeWslOutput(raw: Buffer): string {
  if (raw.includes(0)) return raw.toString("utf16le").replace(/\0/g, "");
  return raw.toString("utf8");
}

export function parseWslDistros(raw: string): WslDistro[] {
  const out: WslDistro[] = [];
  for (const line of raw.replace(/\0/g, "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || /^NAME\s+STATE\s+VERSION$/i.test(trimmed)) continue;
    const isDefault = trimmed.startsWith("*");
    const body = isDefault ? trimmed.slice(1).trim() : trimmed;
    const parts = body.split(/\s+/);
    if (parts.length < 3) continue;
    const version = parts[parts.length - 1]!;
    const state = parts[parts.length - 2]!;
    if (!/^\d+$/.test(version)) continue;
    const name = parts.slice(0, -2).join(" ").trim();
    if (!name) continue;
    out.push({ name, state, version, default: isDefault });
  }
  return out;
}

/** Prefer the canonical Kali distro name, then any distro mentioning Kali. */
export function findKali(distoes: WslDistro[]): string | undefined {
  return (
    distoes.find((entry) => /^kali-linux$/i.test(entry.name))?.name ??
    distoes.find((entry) => /kali/i.test(entry.name))?.name
  );
}

export function wslArgs(options: { distro?: string; command: string; cwd?: string; root?: boolean }): string[] {
  const command = options.cwd ? `cd ${shellQuote(options.cwd)} && ${options.command}` : options.command;
  const args: string[] = [];
  if (options.distro) args.push("-d", options.distro);
  if (options.root) args.push("-u", "root");
  args.push("--", "bash", "-lc", command);
  return args;
}

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function spawnCapture(
  argv: string[],
  timeoutMs: number,
  onOutput?: (chunk: string, stream: "stdout" | "stderr") => void,
): Promise<{ stdout: string; stderr: string; code: number; timedOut: boolean; durationMs: number }> {
  return new Promise((done) => {
    const started = Date.now();
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    const child = spawn(argv[0]!, argv.slice(1), {
      windowsHide: true,
      env: { ...process.env, WSL_UTF8: "1" },
    });
    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.stdout?.on("data", (chunk: Buffer) => {
      const text = decodeWslOutput(chunk);
      if (stdout.length < 400_000) stdout += text;
      onOutput?.(text, "stdout");
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      const text = decodeWslOutput(chunk);
      if (stderr.length < 200_000) stderr += text;
      onOutput?.(text, "stderr");
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      done({ stdout: "", stderr: error.message, code: 127, timedOut: false, durationMs: Date.now() - started });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      done({ stdout, stderr, code: code ?? 1, timedOut, durationMs: Date.now() - started });
    });
  });
}

export async function detectWsl(): Promise<WslStatus> {
  if (process.platform !== "win32") {
    return { available: false, distros: [], error: "WSL is only available on Windows" };
  }
  const listed = await spawnCapture([wslExecutable(), "-l", "-v"], 15_000);
  const text = `${listed.stdout}\n${listed.stderr}`;
  const distros = parseWslDistros(listed.stdout || listed.stderr);
  const noDistros = /no installed distributions|WSL_E_DISTRO_NOT_FOUND/i.test(text);
  if (listed.code !== 0 && !noDistros) {
    return { available: false, distros: [], error: text.trim().slice(0, 800) || `wsl exited ${listed.code}` };
  }
  const kali = findKali(distros);
  const defaultDistro = distros.find((entry) => entry.default)?.name;
  return {
    available: true,
    distros,
    ...(kali ? { kali } : {}),
    ...(defaultDistro ? { defaultDistro } : {}),
    ...(noDistros ? { error: "WSL is installed but no distribution is installed yet" } : {}),
  };
}

export async function runWsl(options: WslRunOptions): Promise<WslRunResult> {
  const distro = options.distro?.trim() || DEFAULT_WSL_DISTRO;
  const result = await spawnCapture(
    [
      wslExecutable(),
      ...wslArgs({
        distro,
        command: options.command,
        ...(options.cwd ? { cwd: options.cwd } : {}),
        ...(options.root ? { root: true } : {}),
      }),
    ],
    options.timeoutMs ?? 300_000,
    options.onOutput,
  );
  return { ...result, distro };
}

export async function installKaliLinux(): Promise<WslRunResult> {
  const result = await spawnCapture([wslExecutable(), ...WSL_INSTALL_ARGS], 900_000);
  return { ...result, distro: "kali-linux" };
}
