/**
 * Opt-in Docker sandbox for running offensive tooling off the host.
 *
 * Mirrors the settings Strix uses for its Kali sandbox: the workspace bind
 * mounted at /work, NET_ADMIN/NET_RAW for raw-socket tools such as nmap,
 * host.docker.internal mapped to the host gateway, bounded json-file logs so a
 * runaway tool cannot fill the disk, and optional memory/CPU/PID caps.
 *
 * Nothing here pulls an image implicitly. `status` reports what is missing and
 * `pull` is an explicit action, so a scan never blocks on a multi-gigabyte
 * download the operator did not ask for.
 */
import { spawn } from "node:child_process";
import { resolve } from "node:path";

export const DEFAULT_SANDBOX_IMAGE = process.env.ARGUS_SANDBOX_IMAGE?.trim() || "kalilinux/kali-rolling";
export const SANDBOX_MOUNT = "/work";

export type SandboxNetwork = "none" | "bridge" | "host";

export interface SandboxOptions {
  workspace: string;
  image?: string;
  network?: SandboxNetwork;
  /** Read-only workspace mount; useful for pure source triage. */
  readOnly?: boolean;
  memory?: string;
  cpus?: string;
  pidsLimit?: number;
  timeoutMs?: number;
}

export interface SandboxResult {
  stdout: string;
  stderr: string;
  code: number;
  timedOut: boolean;
  durationMs: number;
}

function clip(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}\n… truncated ${value.length - max} bytes` : value;
}

function positive(value: string | undefined, label: string): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  const numeric = Number(trimmed.replace(/[a-z]+$/i, ""));
  if (!Number.isFinite(numeric) || numeric <= 0) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return trimmed;
}

/** Pure argument builder, so the container contract is testable without Docker. */
export function sandboxArgs(options: SandboxOptions, command: string, name = "argus-sandbox"): string[] {
  const workspace = resolve(options.workspace);
  const network = options.network ?? "none";
  const args = [
    "run",
    "--rm",
    "--name",
    name,
    "--network",
    network,
    "--add-host",
    "host.docker.internal:host-gateway",
    "--log-driver",
    "json-file",
    "--log-opt",
    "max-size=50m",
    "--log-opt",
    "max-file=3",
    "--pids-limit",
    String(options.pidsLimit ?? 512),
    "-v",
    `${workspace}:${SANDBOX_MOUNT}${options.readOnly ? ":ro" : ""}`,
    "-w",
    SANDBOX_MOUNT,
  ];
  if (network !== "none") {
    args.push("--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN");
  }
  const memory = positive(options.memory, "memory limit");
  if (memory) args.push("--memory", memory);
  const cpus = positive(options.cpus, "cpu limit");
  if (cpus) args.push("--cpus", cpus);
  args.push(options.image?.trim() || DEFAULT_SANDBOX_IMAGE, "sh", "-lc", command);
  return args;
}

function runProcess(argv: string[], timeoutMs: number): Promise<SandboxResult> {
  return new Promise((done) => {
    const started = Date.now();
    let stdout = "";
    let stderr = "";
    let settled = false;
    const child = spawn(argv[0]!, argv.slice(1), { windowsHide: true });
    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      child.kill();
    }, timeoutMs);
    let timedOut = false;
    child.stdout?.on("data", (chunk: Buffer) => {
      if (stdout.length < 400_000) stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length < 200_000) stderr += chunk.toString();
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
      done({
        stdout: clip(stdout, 120_000),
        stderr: clip(stderr, 60_000),
        code: code ?? (timedOut ? 124 : 1),
        timedOut,
        durationMs: Date.now() - started,
      });
    });
  });
}

export async function dockerAvailable(): Promise<boolean> {
  const result = await runProcess(["docker", "version", "--format", "{{.Server.Version}}"], 8_000);
  return result.code === 0 && result.stdout.trim().length > 0;
}

export async function dockerImagePresent(image = DEFAULT_SANDBOX_IMAGE): Promise<boolean> {
  const result = await runProcess(["docker", "image", "inspect", image], 8_000);
  return result.code === 0;
}

export async function pullSandboxImage(image = DEFAULT_SANDBOX_IMAGE): Promise<SandboxResult> {
  return runProcess(["docker", "pull", image], 15 * 60_000);
}

export async function sandboxStatus(options: SandboxOptions): Promise<{
  docker: boolean;
  image: string;
  imagePresent: boolean;
  network: SandboxNetwork;
}> {
  const docker = await dockerAvailable();
  const image = options.image?.trim() || DEFAULT_SANDBOX_IMAGE;
  return {
    docker,
    image,
    imagePresent: docker ? await dockerImagePresent(image) : false,
    network: options.network ?? "none",
  };
}

export async function runInSandbox(options: SandboxOptions, command: string): Promise<SandboxResult> {
  if (!command.trim()) throw new Error("sandbox command is empty");
  if (!(await dockerAvailable())) {
    throw new Error("Docker is not available. Install Docker Desktop/Engine, start it, then retry.");
  }
  const image = options.image?.trim() || DEFAULT_SANDBOX_IMAGE;
  if (!(await dockerImagePresent(image))) {
    throw new Error(`Sandbox image ${image} is not present locally. Run the sandbox pull action first.`);
  }
  const name = `argus-sandbox-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e4)}`;
  return runProcess(["docker", ...sandboxArgs(options, command, name)], options.timeoutMs ?? 120_000);
}
