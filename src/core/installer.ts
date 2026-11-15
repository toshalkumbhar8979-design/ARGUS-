import type { ToolAvailability } from "../core/types";
import { truncate } from "../core/util";

export type InstallPlatform = "win32" | "darwin" | "linux";

export interface InstallPlan {
  id: string;
  name: string;
  manager: string;
  command: string[] | null;
  display: string;
  available: boolean;
  requiresAdmin: boolean;
  note?: string;
}

interface Candidate {
  manager: string;
  command: string[];
  display: string;
  requiresAdmin: boolean;
  note?: string;
}

export interface InstallRunResult {
  id: string;
  name: string;
  ok: boolean;
  code: number;
  output: string;
}

const GO_PACKAGES: Record<string, string> = {
  subfinder: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
  naabu: "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
  nuclei: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
  ffuf: "github.com/ffuf/ffuf/v2@latest",
  gitleaks: "github.com/gitleaks/gitleaks/v8@latest",
  "osv-scanner": "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest",
  trivy: "github.com/aquasecurity/trivy/cmd/trivy@latest",
};

const WINGET_IDS: Record<string, string> = {
  nmap: "Insecure.Nmap",
  nikto: "Nikto",
  gitleaks: "gitleaks.gitleaks",
  trivy: "AquaSecurity.Trivy",
};

const BREW_FORMULAS: Record<string, string> = {
  nmap: "nmap",
  nikto: "nikto",
  whatweb: "whatweb",
  sqlmap: "sqlmap",
  semgrep: "semgrep",
  gitleaks: "gitleaks",
  trivy: "trivy",
};

const APT_PACKAGES: Record<string, string> = {
  nmap: "nmap",
  nikto: "nikto",
  whatweb: "whatweb",
  sqlmap: "sqlmap",
  trivy: "trivy",
};

const DNF_PACKAGES: Record<string, string> = {
  nmap: "nmap",
  nikto: "nikto",
  whatweb: "whatweb",
  sqlmap: "sqlmap",
};

const PACMAN_PACKAGES: Record<string, string> = {
  nmap: "nmap",
  nikto: "nikto",
  sqlmap: "sqlmap",
};

function displayOf(command: string[]): string {
  return command.join(" ");
}

function goCandidate(pkg: string): Candidate {
  return {
    manager: "go",
    command: ["go", "install", pkg],
    display: displayOf(["go", "install", pkg]),
    requiresAdmin: false,
    note: "installs into $(go env GOPATH)/bin; add that directory to PATH if needed",
  };
}

function brewCandidate(formula: string): Candidate {
  return {
    manager: "brew",
    command: ["brew", "install", formula],
    display: displayOf(["brew", "install", formula]),
    requiresAdmin: false,
  };
}

function wingetCandidate(id: string): Candidate {
  const command = [
    "winget",
    "install",
    "--id",
    id,
    "-e",
    "--accept-source-agreements",
    "--accept-package-agreements",
    "--silent",
  ];
  return {
    manager: "winget",
    command,
    display: displayOf(command),
    requiresAdmin: false,
    note: "Windows may show a UAC prompt; no sudo is used",
  };
}

function chocoCandidate(pkg: string): Candidate {
  return {
    manager: "choco",
    command: ["choco", "install", "-y", pkg],
    display: displayOf(["choco", "install", "-y", pkg]),
    requiresAdmin: true,
    note: "requires an elevated shell; /install will not run it",
  };
}

function aptCandidate(pkg: string): Candidate {
  const command = ["apt-get", "install", "-y", pkg];
  return {
    manager: "apt-get",
    command,
    display: `sudo ${displayOf(command)}`,
    requiresAdmin: true,
    note: "requires an elevated shell; /install will not run it",
  };
}

function dnfCandidate(pkg: string): Candidate {
  const command = ["dnf", "install", "-y", pkg];
  return {
    manager: "dnf",
    command,
    display: `sudo ${displayOf(command)}`,
    requiresAdmin: true,
    note: "requires an elevated shell; /install will not run it",
  };
}

function pacmanCandidate(pkg: string): Candidate {
  const command = ["pacman", "-S", "--noconfirm", pkg];
  return {
    manager: "pacman",
    command,
    display: `sudo ${displayOf(command)}`,
    requiresAdmin: true,
    note: "requires an elevated shell; /install will not run it",
  };
}

function gemCandidate(pkg: string): Candidate {
  return {
    manager: "gem",
    command: ["gem", "install", pkg],
    display: displayOf(["gem", "install", pkg]),
    requiresAdmin: false,
  };
}

function pipCandidates(pkg: string): Candidate[] {
  return [
    {
      manager: "python",
      command: ["python", "-m", "pip", "install", pkg],
      display: displayOf(["python", "-m", "pip", "install", pkg]),
      requiresAdmin: false,
      note: "installs into the active Python environment",
    },
    {
      manager: "pip",
      command: ["pip", "install", pkg],
      display: displayOf(["pip", "install", pkg]),
      requiresAdmin: false,
      note: "installs into the active Python environment",
    },
    {
      manager: "pip3",
      command: ["pip3", "install", pkg],
      display: displayOf(["pip3", "install", pkg]),
      requiresAdmin: false,
      note: "installs into the active Python environment",
    },
  ];
}

function candidatesFor(id: string, platform: InstallPlatform): Candidate[] {
  if (platform === "win32") {
    if (WINGET_IDS[id]) {
      const candidates: Candidate[] = [wingetCandidate(WINGET_IDS[id]!)];
      if (id === "nmap" || id === "nikto") candidates.push(chocoCandidate(id === "nmap" ? "nmap" : "nikto"));
      if (id === "gitleaks" && GO_PACKAGES.gitleaks) candidates.push(goCandidate(GO_PACKAGES.gitleaks));
      return candidates;
    }
    if (id === "whatweb") return [gemCandidate("whatweb")];
    if (id === "sqlmap" || id === "semgrep" || id === "bandit") return pipCandidates(id);
    if (GO_PACKAGES[id]) return [goCandidate(GO_PACKAGES[id]!)];
    return [];
  }

  if (platform === "darwin") {
    const candidates: Candidate[] = [];
    if (GO_PACKAGES[id] && (id === "subfinder" || id === "naabu" || id === "nuclei" || id === "ffuf" || id === "osv-scanner")) {
      candidates.push(goCandidate(GO_PACKAGES[id]!));
    }
    if (BREW_FORMULAS[id]) candidates.push(brewCandidate(BREW_FORMULAS[id]!));
    if (id === "whatweb") candidates.push(gemCandidate("whatweb"));
    if (id === "sqlmap" || id === "semgrep" || id === "bandit") candidates.unshift(...pipCandidates(id));
    if (id === "gitleaks" && candidates.length === 0 && GO_PACKAGES.gitleaks) candidates.push(goCandidate(GO_PACKAGES.gitleaks));
    if (id === "trivy" && candidates.length === 0 && GO_PACKAGES.trivy) candidates.push(goCandidate(GO_PACKAGES.trivy));
    return candidates;
  }

  const candidates: Candidate[] = [];
  if (GO_PACKAGES[id] && (id === "subfinder" || id === "naabu" || id === "nuclei" || id === "ffuf" || id === "osv-scanner" || id === "gitleaks" || id === "trivy")) {
    candidates.push(goCandidate(GO_PACKAGES[id]!));
  }
  if (id === "whatweb") candidates.push(gemCandidate("whatweb"));
  if (id === "sqlmap" || id === "semgrep" || id === "bandit") candidates.unshift(...pipCandidates(id));
  if (APT_PACKAGES[id]) candidates.push(aptCandidate(APT_PACKAGES[id]!));
  if (DNF_PACKAGES[id]) candidates.push(dnfCandidate(DNF_PACKAGES[id]!));
  if (PACMAN_PACKAGES[id]) candidates.push(pacmanCandidate(PACMAN_PACKAGES[id]!));
  if (candidates.length === 0 && BREW_FORMULAS[id]) candidates.push(brewCandidate(BREW_FORMULAS[id]!));
  return candidates;
}

function manualPlan(tool: ToolAvailability): InstallPlan {
  return {
    id: tool.id,
    name: tool.name,
    manager: "manual",
    command: null,
    display: tool.install,
    available: false,
    requiresAdmin: false,
    note: "manual command from the adapter definition",
  };
}

function choosePlan(tool: ToolAvailability, platform: InstallPlatform, which: (binary: string) => string | null): InstallPlan {
  const candidates = candidatesFor(tool.id, platform);
  if (candidates.length === 0) return manualPlan(tool);
  for (const candidate of candidates) {
    if (which(candidate.command[0]!)) {
      return {
        id: tool.id,
        name: tool.name,
        manager: candidate.manager,
        command: candidate.command,
        display: candidate.display,
        available: true,
        requiresAdmin: candidate.requiresAdmin,
        note: candidate.note,
      };
    }
  }
  const first = candidates[0]!;
  return {
    id: tool.id,
    name: tool.name,
    manager: first.manager,
    command: first.command,
    display: first.display,
    available: false,
    requiresAdmin: first.requiresAdmin,
    note: `${first.manager} was not found on PATH${first.note ? `; ${first.note}` : ""}`,
  };
}

/** Builds a platform-aware install plan for every missing adapter. */
export function buildInstallPlans(
  tools: ToolAvailability[],
  options: {
    platform?: NodeJS.Platform;
    which?: (binary: string) => string | null;
  } = {},
): InstallPlan[] {
  const requested = options.platform ?? process.platform;
  const platform: InstallPlatform = requested === "win32" || requested === "darwin" ? requested : "linux";
  const which = options.which ?? ((binary: string) => Bun.which(binary) ?? null);
  return tools
    .filter((tool) => !tool.installed)
    .map((tool) => choosePlan(tool, platform, which))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Executes only a user-level plan. Admin plans are returned as a refusal so the
 * operator can run the printed command in an elevated shell themselves.
 */
export async function runInstallPlan(
  plan: InstallPlan,
  options: { signal?: AbortSignal; timeoutMs?: number; cwd?: string } = {},
): Promise<InstallRunResult> {
  if (!plan.command || !plan.available) {
    return { id: plan.id, name: plan.name, ok: false, code: -1, output: "no runnable installer found on PATH" };
  }
  if (plan.requiresAdmin) {
    return {
      id: plan.id,
      name: plan.name,
      ok: false,
      code: -1,
      output: `requires an elevated shell - run: ${plan.display}`,
    };
  }
  let proc: ReturnType<typeof Bun.spawn> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const onAbort = () => {
    try {
      proc?.kill();
    } catch {
      // already exited
    }
  };
  options.signal?.addEventListener("abort", onAbort, { once: true });
  try {
    proc = Bun.spawn(plan.command, {
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
      cwd: options.cwd,
    });
    timer = setTimeout(() => {
      try {
        proc?.kill();
      } catch {
        // already exited
      }
    }, options.timeoutMs ?? 300_000);
    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout as ReadableStream<Uint8Array>).text(),
      new Response(proc.stderr as ReadableStream<Uint8Array>).text(),
    ]);
    const code = await proc.exited;
    const output = [stderr.trim(), stdout.trim()].filter(Boolean).join("\n");
    return {
      id: plan.id,
      name: plan.name,
      ok: code === 0,
      code,
      output: truncate(output || (code === 0 ? "installed" : `exit code ${code}`), 4_000),
    };
  } catch (error) {
    return {
      id: plan.id,
      name: plan.name,
      ok: false,
      code: -1,
      output: error instanceof Error ? error.message : String(error),
    };
  } finally {
    if (timer) clearTimeout(timer);
    options.signal?.removeEventListener("abort", onAbort);
  }
}
