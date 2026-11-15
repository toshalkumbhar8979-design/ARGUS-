import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  ExternalToolResult,
  FindingDraft,
  PhaseTask,
  ProfileId,
  ProbeContext,
  Severity,
  TargetKind,
  ToolAvailability,
} from "./types";
import { isCidr, parseCidr } from "./scope";
import { TAKEOVER_FINGERPRINTS, WORDLIST } from "./signatures";
import { truncate } from "./util";

type ToolPhase = "recon" | "surface" | "audit" | "supply";
type Runtime = (ctx: ProbeContext, binary: string) => Promise<ExternalToolResult>;

interface ToolDefinition {
  id: string;
  name: string;
  binary: string;
  category: string;
  phase: ToolPhase;
  profiles: ProfileId[];
  kinds: TargetKind[];
  requiresActive: boolean;
  intrusive: boolean;
  external: boolean;
  description: string;
  install: string;
  versionArgs?: string[];
  execute: Runtime;
}

const ALL_WEB: ProfileId[] = ["quick", "recon", "web", "api", "deep"];
const ACTIVE_WEB: ProfileId[] = ["web", "api", "deep"];
const ALL_KINDS: TargetKind[] = ["web", "api", "network", "repo"];

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    id: "subfinder",
    name: "subfinder",
    binary: "subfinder",
    category: "dns",
    phase: "recon",
    profiles: ["recon", "web", "deep"],
    kinds: ["web", "api"],
    requiresActive: false,
    intrusive: false,
    external: true,
    description: "Passive subdomain enumeration from public sources.",
    install: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    versionArgs: ["-version"],
    execute: runSubfinder,
  },
  {
    id: "whatweb",
    name: "WhatWeb",
    binary: "whatweb",
    category: "web",
    phase: "recon",
    profiles: ["web", "deep"],
    kinds: ["web", "api"],
    requiresActive: true,
    intrusive: false,
    external: false,
    description: "Web technology and CMS fingerprinting.",
    install: "gem install whatweb",
    versionArgs: ["--version"],
    execute: runWhatweb,
  },
  {
    id: "nmap",
    name: "Nmap",
    binary: "nmap",
    category: "network",
    phase: "surface",
    profiles: ["network", "deep"],
    kinds: ["web", "api", "network"],
    requiresActive: true,
    intrusive: false,
    external: false,
    description: "Service and version detection with Nmap XML output.",
    install: "winget install Insecure.Nmap",
    versionArgs: ["--version"],
    execute: runNmap,
  },
  {
    id: "naabu",
    name: "naabu",
    binary: "naabu",
    category: "network",
    phase: "surface",
    profiles: ["deep"],
    kinds: ["web", "api", "network"],
    requiresActive: true,
    intrusive: false,
    external: false,
    description: "Fast port discovery with naabu.",
    install: "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    versionArgs: ["-version"],
    execute: runNaabu,
  },
  {
    id: "nuclei",
    name: "Nuclei",
    binary: "nuclei",
    category: "vulnerability",
    phase: "audit",
    profiles: ["web", "api", "deep"],
    kinds: ["web", "api"],
    requiresActive: true,
    intrusive: false,
    external: true,
    description: "Template-driven web vulnerability checks.",
    install: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    versionArgs: ["-version"],
    execute: runNuclei,
  },
  {
    id: "ffuf",
    name: "ffuf",
    binary: "ffuf",
    category: "discovery",
    phase: "audit",
    profiles: ["web", "api", "deep"],
    kinds: ["web", "api"],
    requiresActive: true,
    intrusive: false,
    external: false,
    description: "Content discovery against a built-in authorized wordlist.",
    install: "go install github.com/ffuf/ffuf/v2@latest",
    versionArgs: ["-V"],
    execute: runFfuf,
  },
  {
    id: "nikto",
    name: "Nikto",
    binary: "nikto",
    category: "vulnerability",
    phase: "audit",
    profiles: ["web", "deep"],
    kinds: ["web", "api"],
    requiresActive: true,
    intrusive: false,
    external: false,
    description: "Legacy web server misconfiguration checks.",
    install: "winget install Nikto",
    versionArgs: ["-Version"],
    execute: runNikto,
  },
  {
    id: "sqlmap",
    name: "sqlmap",
    binary: "sqlmap",
    category: "injection",
    phase: "audit",
    profiles: ["deep"],
    kinds: ["web", "api"],
    requiresActive: true,
    intrusive: true,
    external: false,
    description: "Low-risk, parameter-focused SQL injection confirmation.",
    install: "pip install sqlmap",
    versionArgs: ["--version"],
    execute: runSqlmap,
  },
  {
    id: "semgrep",
    name: "Semgrep",
    binary: "semgrep",
    category: "sast",
    phase: "supply",
    profiles: ["repo", "deep"],
    kinds: ["repo"],
    requiresActive: false,
    intrusive: false,
    external: true,
    description: "Static analysis using the Semgrep registry ruleset.",
    install: "pip install semgrep",
    versionArgs: ["--version"],
    execute: runSemgrep,
  },
  {
    id: "gitleaks",
    name: "Gitleaks",
    binary: "gitleaks",
    category: "secrets",
    phase: "supply",
    profiles: ["repo", "deep"],
    kinds: ["repo"],
    requiresActive: false,
    intrusive: false,
    external: false,
    description: "Secret detection across repository files.",
    install: "winget install gitleaks",
    versionArgs: ["version"],
    execute: runGitleaks,
  },
  {
    id: "trivy",
    name: "Trivy",
    binary: "trivy",
    category: "supply-chain",
    phase: "supply",
    profiles: ["repo", "deep"],
    kinds: ["repo"],
    requiresActive: false,
    intrusive: false,
    external: true,
    description: "Dependency, secret and misconfiguration scanning.",
    install: "winget install AquaSecurity.Trivy",
    versionArgs: ["--version"],
    execute: runTrivy,
  },
  {
    id: "osv-scanner",
    name: "OSV-Scanner",
    binary: "osv-scanner",
    category: "supply-chain",
    phase: "supply",
    profiles: ["repo", "deep"],
    kinds: ["repo"],
    requiresActive: false,
    intrusive: false,
    external: true,
    description: "Dependency vulnerability matching through OSV.",
    install: "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
    versionArgs: ["--version"],
    execute: runOsvScanner,
  },
  {
    id: "bandit",
    name: "Bandit",
    binary: "bandit",
    category: "sast",
    phase: "supply",
    profiles: ["repo", "deep"],
    kinds: ["repo"],
    requiresActive: false,
    intrusive: false,
    external: false,
    description: "Python security static analysis.",
    install: "pip install bandit",
    versionArgs: ["--version"],
    execute: runBandit,
  },
];

export async function discoverTools(): Promise<ToolAvailability[]> {
  const results = await Promise.all(
    TOOL_DEFINITIONS.map(async (definition) => {
      const path = Bun.which(definition.binary) ?? undefined;
      if (!path) {
        return {
          id: definition.id,
          name: definition.name,
          category: definition.category,
          binary: definition.binary,
          installed: false,
          install: definition.install,
          intrusive: definition.intrusive,
          description: definition.description,
        } satisfies ToolAvailability;
      }
      const probe = await runBinary(path, definition.versionArgs ?? ["--version"], { timeoutMs: 5_000, maxBytes: 20_000 });
      const version = firstLine(probe.stdout || probe.stderr);
      return {
        id: definition.id,
        name: definition.name,
        category: definition.category,
        binary: definition.binary,
        installed: true,
        path,
        version: version || undefined,
        install: definition.install,
        intrusive: definition.intrusive,
        description: definition.description,
      } satisfies ToolAvailability;
    }),
  );
  return results;
}

export function buildToolTasks(tools: ToolAvailability[], profile: ProfileId, kind: TargetKind): PhaseTask[] {
  const installed = new Map(tools.filter((tool) => tool.installed && tool.path).map((tool) => [tool.id, tool]));
  const tasks: PhaseTask[] = [];
  for (const definition of TOOL_DEFINITIONS) {
    if (!definition.profiles.includes(profile)) continue;
    if (!definition.kinds.includes(kind) && !(definition.kinds.includes("web") && kind === "api")) continue;
    const tool = installed.get(definition.id);
    if (!tool?.path) continue;
    tasks.push({
      id: `ext-${definition.id}`,
      label: definition.name,
      phase: definition.phase,
      requiresActive: definition.requiresActive,
      requiresIntrusive: definition.intrusive,
      run: async (ctx) => {
        if (definition.external && (!ctx.options.allowExternal || !ctx.scope.allowExternal)) {
          ctx.emit({ type: "tool:status", runId: ctx.runId, tool: definition.name, status: "skipped", message: "External access disabled by scope." });
          return [];
        }
        ctx.emit({ type: "tool:status", runId: ctx.runId, tool: definition.name, status: "running", message: tool.version });
        ctx.log("info", `Running ${definition.name}${tool.version ? ` (${tool.version})` : ""}`, definition.id);
        let result: ExternalToolResult;
        try {
          result = await definition.execute(ctx, tool.path!);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          ctx.emit({ type: "tool:status", runId: ctx.runId, tool: definition.name, status: "failed", message });
          ctx.log("warn", `${definition.name} failed: ${message}`, definition.id);
          return [];
        }
        await saveToolOutput(ctx, definition.id, result);
        if (result.skipped) {
          ctx.emit({ type: "tool:status", runId: ctx.runId, tool: definition.name, status: "skipped", message: result.skipped });
          ctx.log("info", `${definition.name} skipped: ${result.skipped}`, definition.id);
          return [];
        }
        if (result.exitCode !== 0 && result.findings.length === 0) {
          const message = truncate(firstLine(result.stderr) || `exit code ${result.exitCode}`, 300);
          ctx.emit({ type: "tool:status", runId: ctx.runId, tool: definition.name, status: "failed", message });
          ctx.log("warn", `${definition.name}: ${message}`, definition.id);
        } else {
          ctx.emit({ type: "tool:status", runId: ctx.runId, tool: definition.name, status: "done", message: `${result.findings.length} findings` });
        }
        return result.findings;
      },
    });
  }
  return tasks;
}

export function availableToolIds(tools: ToolAvailability[]): string[] {
  return tools.filter((tool) => tool.installed).map((tool) => tool.id);
}

export function toolSummary(tools: ToolAvailability[]): string {
  const installed = tools.filter((tool) => tool.installed).length;
  return `${installed}/${tools.length} external tools detected`;
}

async function runNmap(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const host = ctx.target.host ?? ctx.target.ip;
  if (!host) return skipped("Target has no host.");
  if (isCidr(host)) {
    const parsed = parseCidr(host);
    if (!parsed || parsed.version !== 4 || parsed.bits < 24) return skipped("Nmap is limited to /24 or narrower ranges; use the native scanner for broad ranges.");
  }
  const args = ["-Pn", "-sV", "--version-light", "-T3", "--max-retries", "1", "--host-timeout", "45s", "-oX", "-"];
  if (ctx.scope.allowedPorts?.length) args.push("-p", ctx.scope.allowedPorts.join(","));
  args.push(host);
  const run = await runBinary(binary, args, { timeoutMs: 180_000, signal: ctx.signal, maxBytes: 8_000_000 });
  const findings: FindingDraft[] = [];
  for (const hostBlock of run.stdout.matchAll(/<host\b[\s\S]*?<\/host>/g)) {
    const block = hostBlock[0];
    const address = /<address addr="([^"]+)" addrtype="(?:ipv4|ipv6)"/.exec(block)?.[1] ?? host;
    const hostname = /<hostname name="([^"]+)"/.exec(block)?.[1];
    for (const portMatch of block.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/g)) {
      const attrs = portMatch[1] ?? "";
      const body = portMatch[2] ?? "";
      const port = Number(/portid="(\d+)"/.exec(attrs)?.[1]);
      if (!port) continue;
      if (!/<state state="open"/.test(body)) continue;
      const service = /<service\b([^>]*)\/?>/.exec(body)?.[1] ?? "";
      const name = /\bname="([^"]+)"/.exec(service)?.[1];
      const product = /\bproduct="([^"]+)"/.exec(service)?.[1];
      const version = /\bversion="([^"]+)"/.exec(service)?.[1];
      const tunnel = /\btunnel="([^"]+)"/.exec(service)?.[1];
      findings.push({
        title: `Open port ${port}${name ? ` (${name})` : ""} on ${address}`,
        severity: serviceRisk(port, name),
        category: "network",
        confidence: "confirmed",
        tool: "nmap",
        target: hostname ?? address,
        evidence: `${address}:${port}${name ? ` ${name}` : ""}${product ? ` ${product}` : ""}${version ? ` ${version}` : ""}${tunnel ? ` via ${tunnel}` : ""}`,
        description: "Nmap confirmed the port is open and fingerprinted the service.",
        remediation: "Restrict exposed services with firewall rules and require authentication.",
        references: [],
        dedupeKey: `port-${address}-${port}`,
        metadata: { port, service: name, product, version, tunnel },
      });
      if (findings.length >= 500) break;
    }
  }
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runNaabu(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const host = ctx.target.host ?? ctx.target.ip;
  if (!host) return skipped("Target has no host.");
  if (isCidr(host)) {
    const parsed = parseCidr(host);
    if (!parsed || parsed.version !== 4 || parsed.bits < 24) return skipped("naabu is limited to /24 or narrower ranges.");
  }
  const args = ["-host", host, "-top-ports", "100", "-silent", "-rate", String(Math.min(500, Math.max(20, (ctx.scope.maxRps ?? 20) * 10)))];
  if (ctx.scope.allowedPorts?.length) args.push("-p", ctx.scope.allowedPorts.join(","));
  const run = await runBinary(binary, args, { timeoutMs: 120_000, signal: ctx.signal, maxBytes: 2_000_000 });
  const findings: FindingDraft[] = [];
  for (const line of run.stdout.split(/\r?\n/)) {
    const match = /^(\[[^\]]+\]|[^:\s]+):(\d+)\s*$/.exec(line.trim());
    if (!match) continue;
    const address = match[1]!.replace(/^\[|\]$/g, "");
    const port = Number(match[2]);
    findings.push({
      title: `Open port ${port} on ${address}`,
      severity: "info",
      category: "network",
      confidence: "confirmed",
      tool: "naabu",
      target: address,
      evidence: `${address}:${port}`,
      description: "naabu reported the TCP port as open.",
      remediation: "Restrict unnecessary exposed ports.",
      references: [],
      dedupeKey: `port-${address}-${port}`,
    });
    if (findings.length >= 500) break;
  }
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runSubfinder(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const host = ctx.target.host;
  if (!host || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) return skipped("Subfinder requires a domain target.");
  const run = await runBinary(binary, ["-d", host, "-silent", "-timeout", "10"], { timeoutMs: 120_000, signal: ctx.signal, maxBytes: 2_000_000 });
  const findings: FindingDraft[] = [];
  const seen = new Set<string>();
  for (const line of run.stdout.split(/\r?\n/)) {
    const sub = line.trim().toLowerCase();
    if (!sub || seen.has(sub) || sub === host) continue;
    if (!sub.endsWith(`.${host}`) || !/^[a-z0-9][a-z0-9.-]*$/.test(sub)) continue;
    seen.add(sub);
    findings.push({
      title: `Subdomain discovered: ${sub}`,
      severity: "info",
      category: "recon",
      confidence: "likely",
      tool: "subfinder",
      target: sub,
      evidence: sub,
      description: "Passive DNS intelligence discovered this subdomain.",
      remediation: "Inventory the asset, confirm ownership, and include it in scope before testing.",
      references: [],
      dedupeKey: `subfinder-${sub}`,
      metadata: { parent: host },
    });
    if (findings.length >= 300) break;
  }
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runWhatweb(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const url = webTarget(ctx);
  if (!url) return skipped("WhatWeb requires an HTTP target.");
  const run = await runBinary(binary, ["--color=never", "--no-errors", "-a", "1", "--user-agent", "Argus/0.1", url], {
    timeoutMs: 90_000,
    signal: ctx.signal,
    maxBytes: 2_000_000,
  });
  const findings: FindingDraft[] = [];
  const seen = new Set<string>();
  for (const line of run.stdout.split(/\r?\n/)) {
    const plugins = line.matchAll(/([A-Za-z0-9_.-]+)(?:\[([^\]]+)\])/g);
    for (const plugin of plugins) {
      const name = plugin[1]!;
      if (["URL", "Status", "Title", "IP", "Country"].includes(name)) continue;
      const version = plugin[2];
      const key = `${name}:${version ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        title: `Technology detected: ${name}${version ? ` ${version}` : ""}`,
        severity: "info",
        category: "recon",
        confidence: "likely",
        tool: "whatweb",
        url,
        evidence: truncate(line.trim(), 400),
        description: "WhatWeb identified a web technology or server component.",
        remediation: "Remove version banners and keep the component patched.",
        references: [],
        dedupeKey: `whatweb-${name}-${version ?? ""}`,
        metadata: { technology: name, version },
      });
      if (findings.length >= 100) break;
    }
  }
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runNuclei(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const url = webTarget(ctx);
  if (!url) return skipped("Nuclei requires an HTTP target.");
  const artifacts = await artifactDir(ctx);
  const args = [
    "-u", url,
    "-jsonl", "-silent", "-nc", "-duc", "-no-interactsh",
    "-severity", "low,medium,high,critical",
    "-rl", String(Math.min(50, Math.max(5, ctx.scope.maxRps ?? 20))),
    "-timeout", "10", "-retries", "1",
    "-etags", "intrusive,brute-force,fuzz,dos",
  ];
  const run = await runBinary(binary, args, { timeoutMs: 240_000, signal: ctx.signal, maxBytes: 8_000_000, cwd: artifacts });
  const findings: FindingDraft[] = [];
  const seen = new Set<string>();
  for (const line of run.stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    let parsed: NucleiResult;
    try {
      parsed = JSON.parse(trimmed) as NucleiResult;
    } catch {
      continue;
    }
    const info = parsed.info ?? {};
    const matchedAt = parsed["matched-at"] ?? parsed.host ?? url;
    const key = `${parsed["template-id"] ?? info.name}:${matchedAt}:${parsed["matcher-name"] ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const references = Array.isArray(info.reference) ? info.reference : info.reference ? [info.reference] : [];
    const classification = info.classification ?? {};
    const cweArray = Array.isArray(classification["cwe-id"]) ? classification["cwe-id"] : classification["cwe-id"] ? [classification["cwe-id"]] : [];
    const extracted = Array.isArray(parsed["extracted-results"]) ? parsed["extracted-results"].join("\n") : "";
    findings.push({
      title: info.name ?? parsed["template-id"] ?? "Nuclei finding",
      severity: normalizeSeverity(info.severity),
      category: "web",
      confidence: "confirmed",
      tool: "nuclei",
      url: matchedAt,
      evidence: `${matchedAt}\ntemplate: ${parsed["template-id"] ?? "unknown"}${parsed["matcher-name"] ? `\nmatcher: ${parsed["matcher-name"]}` : ""}${extracted ? `\nextracted: ${truncate(extracted, 1000)}` : ""}`,
      description: info.description ?? "Nuclei matched a vulnerability or exposure template.",
      remediation: info.remediation ?? "Review the template evidence and apply the vendor mitigation.",
      references,
      cwe: cweArray[0],
      dedupeKey: `nuclei-${key}`,
      metadata: { template: parsed["template-id"], matcher: parsed["matcher-name"], tags: info.tags },
    });
    if (findings.length >= 300) break;
  }
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runFfuf(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const target = webTarget(ctx);
  if (!target) return skipped("ffuf requires an HTTP target.");
  const artifacts = await artifactDir(ctx);
  const wordlist = join(artifacts, "ffuf-wordlist.txt");
  const output = join(artifacts, "ffuf.json");
  await writeFile(wordlist, `${WORDLIST.join("\n")}\n`, "utf8");
  const base = target.endsWith("/") ? target.slice(0, -1) : target;
  const fuzzUrl = `${base}/FUZZ`;
  const scopeCheck = ctx.guard.checkUrl(fuzzUrl);
  if (!scopeCheck.allowed) return skipped(`FUZZ URL is outside scope: ${scopeCheck.reason}`);
  const args = [
    "-u", fuzzUrl,
    "-w", wordlist,
    "-mc", "200,201,202,204,301,302,307,308,401,403,405,500",
    "-t", "20",
    "-rate", String(Math.min(100, Math.max(5, ctx.scope.maxRps ?? 20))),
    "-timeout", "10",
    "-ac",
    "-s",
    "-of", "json",
    "-o", output,
    "-H", "User-Agent: Argus/0.1",
  ];
  const run = await runBinary(binary, args, { timeoutMs: 180_000, signal: ctx.signal, maxBytes: 1_000_000, cwd: artifacts });
  let raw = "";
  try {
    raw = await readFile(output, "utf8");
  } catch {
    return { findings: [], stdout: run.stdout, stderr: run.stderr || "ffuf did not produce JSON output.", exitCode: run.code };
  }
  let data: { results?: FfufResult[] };
  try {
    data = JSON.parse(raw) as { results?: FfufResult[] };
  } catch {
    return { findings: [], stdout: run.stdout, stderr: "ffuf JSON output could not be parsed.", exitCode: run.code };
  }
  const findings: FindingDraft[] = [];
  for (const result of data.results ?? []) {
    const path = `/${String(result.input?.FUZZ ?? "").replace(/^\/+/, "")}`;
    if (!path || path === "/") continue;
    const severity: Severity = result.status === 500 ? "low" : result.status === 401 || result.status === 403 ? "low" : "info";
    findings.push({
      title: `Discovered path ${path} (HTTP ${result.status})`,
      severity,
      category: "discovery",
      confidence: "confirmed",
      tool: "ffuf",
      url: result.url,
      evidence: `${result.url}\nstatus: ${result.status}\nlength: ${result.length ?? "?"} words: ${result.words ?? "?"} lines: ${result.lines ?? "?"}${result.redirectlocation ? `\nredirect: ${result.redirectlocation}` : ""}`,
      description: "A hidden or unlinked path responded to content discovery.",
      remediation: "Review the endpoint for intended exposure and enforce authentication or removal.",
      references: [],
      dedupeKey: `ffuf-${path}-${result.status}`,
      metadata: { path, status: result.status, length: result.length, contentType: result["content-type"] },
    });
    if (findings.length >= 100) break;
  }
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runNikto(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const url = webTarget(ctx);
  if (!url) return skipped("Nikto requires an HTTP target.");
  const artifacts = await artifactDir(ctx);
  const args = ["-h", url, "-nointeractive", "-Display", "V", "-maxtime", "90s", "-timeout", "10", "-useragent", "Argus/0.1"];
  const run = await runBinary(binary, args, { timeoutMs: 150_000, signal: ctx.signal, maxBytes: 4_000_000, cwd: artifacts });
  const findings: FindingDraft[] = [];
  const seen = new Set<string>();
  for (const line of run.stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("+ ") || /^\+ (Target|Server|Start Time|End Time|requests:)/i.test(trimmed)) continue;
    const text = trimmed.slice(2).trim();
    if (!text) continue;
    if (seen.has(text)) continue;
    seen.add(text);
    const lower = text.toLowerCase();
    const severe = /(sql injection|remote code|command execution|file inclusion|xxe|deserialization|authentication bypass)/.test(lower);
    const medium = /(xss|cross site scripting|directory traversal|upload|backup|config|phpinfo|exposed|default (file|password)|directory indexing)/.test(lower);
    findings.push({
      title: truncate(text.split(":")[0] ?? text, 160),
      severity: severe ? "high" : medium ? "medium" : "low",
      category: "misconfiguration",
      confidence: "possible",
      tool: "nikto",
      url,
      evidence: text,
      description: "Nikto reported a server misconfiguration or known exposure.",
      remediation: "Validate the finding manually and remove exposed files or harden the server configuration.",
      references: [],
      dedupeKey: `nikto-${truncate(text, 180)}`,
    });
    if (findings.length >= 150) break;
  }
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runSqlmap(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const url = webTarget(ctx);
  if (!url) return skipped("sqlmap requires an HTTP target.");
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return skipped("Invalid target URL.");
  }
  const params = [...parsed.searchParams.keys()];
  if (params.length === 0) return skipped("Target URL has no query parameters.");
  const artifacts = await artifactDir(ctx);
  const args = [
    "-u", url,
    "--batch", "--smart", "--level=1", "--risk=1", "--threads=2",
    "--timeout=10", "--retries=1", "--technique=BEUSTQ",
    "--output-dir", join(artifacts, "sqlmap"),
    "--flush-session", "--disable-coloring",
  ];
  const run = await runBinary(binary, args, { timeoutMs: 240_000, signal: ctx.signal, maxBytes: 6_000_000, cwd: artifacts });
  const output = `${run.stdout}\n${run.stderr}`;
  const findings: FindingDraft[] = [];
  const blocks = output.split(/\r?\n(?=Parameter: )/);
  for (const block of blocks) {
    const parameter = /Parameter: ([^\n]+)/.exec(block)?.[1]?.trim();
    if (!parameter) continue;
    const types = [...block.matchAll(/Type: ([^\n]+)/g)].map((match) => match[1]!.trim());
    if (types.length === 0) continue;
    const payload = /Payload: ([^\n]+)/.exec(block)?.[1]?.trim();
    const dbms = /back-end DBMS: ([^\n]+)/.exec(block)?.[1]?.trim();
    findings.push({
      title: `SQL injection confirmed in parameter ${parameter}`,
      severity: "high",
      category: "injection",
      confidence: "confirmed",
      tool: "sqlmap",
      url,
      evidence: `parameter: ${parameter}\ntypes: ${types.join(", ")}${payload ? `\npayload: ${payload}` : ""}${dbms ? `\nDBMS: ${dbms}` : ""}`,
      description: "sqlmap confirmed that the parameter is injectable.",
      remediation: "Use parameterized queries, validate input types, and apply least-privilege database accounts.",
      references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
      cwe: "CWE-89",
      dedupeKey: `sqlmap-${parameter}-${types[0] ?? "sqli"}`,
      metadata: { parameter, types, dbms },
    });
  }
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runSemgrep(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const path = ctx.target.path;
  if (!path) return skipped("Semgrep requires a repository path.");
  const artifacts = await artifactDir(ctx);
  const args = [
    "--config", "auto",
    "--json", "--quiet", "--metrics", "off",
    "--timeout", "30", "--max-target-bytes", "2000000",
    "--exclude", "node_modules", "--exclude", ".git", "--exclude", "dist", "--exclude", "vendor",
    path,
  ];
  const run = await runBinary(binary, args, { timeoutMs: 300_000, signal: ctx.signal, maxBytes: 8_000_000, cwd: artifacts });
  let data: { results?: SemgrepResult[] };
  try {
    data = JSON.parse(run.stdout) as { results?: SemgrepResult[] };
  } catch {
    return { findings: [], stdout: run.stdout, stderr: run.stderr || "Semgrep output was not valid JSON.", exitCode: run.code };
  }
  const findings: FindingDraft[] = [];
  for (const result of data.results ?? []) {
    const extra = result.extra ?? {};
    const metadata = extra.metadata ?? {};
    const mapped = semgrepSeverity(extra.severity, metadata.impact);
    const cweArray = Array.isArray(metadata.cwe) ? metadata.cwe : metadata.cwe ? [metadata.cwe] : [];
    const cwe = String(cweArray[0] ?? "").match(/CWE-\d+/)?.[0];
    findings.push({
      title: extra.message ?? result.check_id ?? "Semgrep finding",
      severity: mapped,
      category: "code",
      confidence: "likely",
      tool: "semgrep",
      target: result.path,
      evidence: `${result.path}:${result.start?.line ?? "?"}\n${truncate(extra.lines ?? extra.message ?? "", 800)}`,
      description: extra.message ?? "Semgrep matched a static analysis rule.",
      remediation: typeof metadata.remediation === "string" ? metadata.remediation : "Review the rule guidance and remediate the unsafe pattern.",
      references: Array.isArray(metadata.references) ? metadata.references.map(String) : [],
      cwe,
      dedupeKey: `semgrep-${result.check_id}-${result.path}-${result.start?.line ?? 0}`,
      metadata: { checkId: result.check_id, impact: metadata.impact, confidence: metadata.confidence },
    });
    if (findings.length >= 200) break;
  }
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runGitleaks(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const path = ctx.target.path;
  if (!path) return skipped("Gitleaks requires a repository path.");
  const artifacts = await artifactDir(ctx);
  const report = join(artifacts, "gitleaks.json");
  const args = [
    "detect", "--source", path, "--no-git",
    "--report-format", "json", "--report-path", report,
    "--redact", "--exit-code", "0",
    "--max-target-megabytes", "2",
  ];
  const run = await runBinary(binary, args, { timeoutMs: 180_000, signal: ctx.signal, maxBytes: 1_000_000, cwd: artifacts });
  let raw = "";
  try {
    raw = await readFile(report, "utf8");
  } catch {
    return { findings: [], stdout: run.stdout, stderr: run.stderr || "Gitleaks did not produce a report.", exitCode: run.code };
  }
  let data: GitleaksResult[];
  try {
    data = JSON.parse(raw) as GitleaksResult[];
  } catch {
    return { findings: [], stdout: run.stdout, stderr: "Gitleaks report could not be parsed.", exitCode: run.code };
  }
  const findings = data.slice(0, 200).map((item) => ({
    title: `${item.Description || item.RuleID || "Secret"} in ${item.File ?? "unknown file"}`,
    severity: "high" as Severity,
    category: "secrets",
    confidence: /test|example|sample|dummy/i.test(`${item.File ?? ""} ${item.Match ?? ""}`) ? ("possible" as const) : ("likely" as const),
    tool: "gitleaks",
    target: item.File,
    evidence: `${item.File ?? "unknown"}:${item.StartLine ?? "?"}\nrule: ${item.RuleID ?? "unknown"}\nentropy: ${item.Entropy ?? "?"}\nmatch: ${item.Match ?? "[redacted]"}`,
    description: item.Description ?? "A credential pattern was detected in the repository.",
    remediation: "Rotate the credential, remove it from history, and use a secret manager.",
    references: ["https://cwe.mitre.org/data/definitions/798.html"],
    cwe: "CWE-798",
    dedupeKey: `gitleaks-${item.RuleID}-${item.File}-${item.StartLine}`,
  }));
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runTrivy(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const path = ctx.target.path;
  if (!path) return skipped("Trivy requires a repository path.");
  const artifacts = await artifactDir(ctx);
  const output = join(artifacts, "trivy.json");
  const args = [
    "fs", "--quiet", "--format", "json",
    "--scanners", "vuln,secret,misconfig",
    "--skip-dirs", "node_modules", "--skip-dirs", ".git", "--skip-dirs", "vendor",
    "--timeout", "10m",
    "--output", output,
    path,
  ];
  const run = await runBinary(binary, args, { timeoutMs: 600_000, signal: ctx.signal, maxBytes: 2_000_000, cwd: artifacts });
  let data: TrivyReport;
  try {
    data = JSON.parse(await readFile(output, "utf8")) as TrivyReport;
  } catch {
    return { findings: [], stdout: run.stdout, stderr: run.stderr || "Trivy did not produce parseable JSON.", exitCode: run.code };
  }
  const findings: FindingDraft[] = [];
  for (const result of data.Results ?? []) {
    for (const vuln of result.Vulnerabilities ?? []) {
      findings.push({
        title: `${vuln.VulnerabilityID ?? "Vulnerability"} in ${vuln.PkgName ?? result.Target ?? "dependency"}`,
        severity: normalizeSeverity(vuln.Severity),
        category: "supply-chain",
        confidence: "likely",
        tool: "trivy",
        target: result.Target,
        evidence: `${result.Target ?? ""}\n${vuln.PkgName ?? ""} ${vuln.InstalledVersion ?? ""}${vuln.FixedVersion ? ` -> ${vuln.FixedVersion}` : ""}\n${vuln.Title ?? vuln.Description ?? ""}`,
        description: vuln.Description ?? "A known vulnerability affects an installed dependency.",
        remediation: vuln.FixedVersion ? `Upgrade to ${vuln.FixedVersion} or later.` : "Upgrade, remove, or mitigate the affected dependency.",
        references: vuln.PrimaryURL ? [vuln.PrimaryURL] : [],
        cwe: "CWE-1104",
        dedupeKey: `trivy-vuln-${vuln.VulnerabilityID}-${vuln.PkgName}-${result.Target}`,
        metadata: { package: vuln.PkgName, installed: vuln.InstalledVersion, fixed: vuln.FixedVersion, score: vuln.CVSS },
      });
      if (findings.length >= 250) break;
    }
    for (const secret of result.Secrets ?? []) {
      findings.push({
        title: `${secret.Title ?? secret.RuleID ?? "Secret"} in ${result.Target ?? "repository"}`,
        severity: normalizeSeverity(secret.Severity),
        category: "secrets",
        confidence: "likely",
        tool: "trivy",
        target: result.Target,
        evidence: `${result.Target ?? ""}:${secret.StartLine ?? "?"}\n${secret.Match ?? "[redacted]"}`,
        description: "Trivy detected a credential or secret in the scanned files.",
        remediation: "Rotate the credential and move it to a secret manager.",
        references: ["https://cwe.mitre.org/data/definitions/798.html"],
        cwe: "CWE-798",
        dedupeKey: `trivy-secret-${secret.RuleID}-${result.Target}-${secret.StartLine}`,
      });
    }
    for (const misconfig of result.Misconfigurations ?? []) {
      findings.push({
        title: `${misconfig.Title ?? misconfig.ID ?? "Misconfiguration"} in ${result.Target ?? "configuration"}`,
        severity: normalizeSeverity(misconfig.Severity),
        category: "iac",
        confidence: "likely",
        tool: "trivy",
        target: result.Target,
        evidence: `${result.Target ?? ""}:${misconfig.CauseMetadata?.StartLine ?? "?"}\n${misconfig.Description ?? ""}`,
        description: misconfig.Description ?? "Infrastructure configuration violates a security policy.",
        remediation: misconfig.Resolution ?? "Apply the recommended configuration.",
        references: misconfig.References ?? [],
        dedupeKey: `trivy-misconfig-${misconfig.ID}-${result.Target}-${misconfig.CauseMetadata?.StartLine}`,
      });
      if (findings.length >= 350) break;
    }
  }
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

async function runOsvScanner(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const path = ctx.target.path;
  if (!path) return skipped("OSV-Scanner requires a repository path.");
  const artifacts = await artifactDir(ctx);
  const runV2 = await runBinary(binary, ["scan", "--format", "json", "--recursive", path], {
    timeoutMs: 240_000,
    signal: ctx.signal,
    maxBytes: 8_000_000,
    cwd: artifacts,
  });
  let raw = runV2.stdout;
  let code = runV2.code;
  let stderr = runV2.stderr;
  if (!raw.trim().startsWith("{") && /unknown command|unrecognized/i.test(stderr)) {
    const runV1 = await runBinary(binary, ["--format", "json", "-r", path], {
      timeoutMs: 240_000,
      signal: ctx.signal,
      maxBytes: 8_000_000,
      cwd: artifacts,
    });
    raw = runV1.stdout;
    code = runV1.code;
    stderr = runV1.stderr;
  }
  let data: { results?: OsvCliResult[] };
  try {
    data = JSON.parse(raw) as { results?: OsvCliResult[] };
  } catch {
    return { findings: [], stdout: raw, stderr: stderr || "OSV-Scanner output was not valid JSON.", exitCode: code };
  }
  const findings: FindingDraft[] = [];
  for (const result of data.results ?? []) {
    for (const pkg of result.packages ?? []) {
      for (const vuln of pkg.vulnerabilities ?? []) {
        findings.push({
          title: `${vuln.id ?? "OSV advisory"} in ${pkg.package?.name ?? "dependency"}`,
          severity: osvCliSeverity(vuln),
          category: "supply-chain",
          confidence: "likely",
          tool: "osv-scanner",
          target: result.source?.path ?? path,
          evidence: `${pkg.package?.name ?? ""} ${pkg.package?.version ?? ""} (${pkg.package?.ecosystem ?? ""})\n${vuln.id ?? ""}${vuln.summary ? `\n${vuln.summary}` : ""}`,
          description: vuln.summary ?? "A known vulnerability affects this dependency.",
          remediation: "Upgrade to a fixed version or remove the dependency.",
          references: vuln.id ? [`https://osv.dev/vulnerability/${vuln.id}`] : [],
          cwe: "CWE-1104",
          dedupeKey: `osv-cli-${pkg.package?.name}-${vuln.id}`,
        });
        if (findings.length >= 250) break;
      }
    }
  }
  return { findings, stdout: raw, stderr, exitCode: code };
}

async function runBandit(ctx: ProbeContext, binary: string): Promise<ExternalToolResult> {
  const path = ctx.target.path;
  if (!path) return skipped("Bandit requires a repository path.");
  const artifacts = await artifactDir(ctx);
  const args = ["-r", path, "-f", "json", "-q", "-x", "node_modules,.git,venv,.venv,tests"];
  const run = await runBinary(binary, args, { timeoutMs: 240_000, signal: ctx.signal, maxBytes: 8_000_000, cwd: artifacts });
  let data: { results?: BanditResult[] };
  try {
    data = JSON.parse(run.stdout) as { results?: BanditResult[] };
  } catch {
    return { findings: [], stdout: run.stdout, stderr: run.stderr || "Bandit output was not valid JSON.", exitCode: run.code };
  }
  const findings = (data.results ?? []).slice(0, 200).map((item) => ({
    title: `${item.test_name ?? item.test_id ?? "Bandit issue"} in ${item.filename ?? "source"}`,
    severity: item.issue_severity === "HIGH" ? ("high" as Severity) : item.issue_severity === "MEDIUM" ? ("medium" as Severity) : ("low" as Severity),
    category: "code",
    confidence: item.issue_confidence === "HIGH" ? ("likely" as const) : ("possible" as const),
    tool: "bandit",
    target: item.filename,
    evidence: `${item.filename ?? ""}:${item.line_number ?? "?"}\n${item.test_id ?? ""} ${item.test_name ?? ""}\n${item.issue_text ?? ""}`,
    description: item.issue_text ?? "Bandit matched a Python security issue.",
    remediation: "Review the Bandit rule and remediate the unsafe code pattern.",
    references: item.more_info ? [item.more_info] : [],
    dedupeKey: `bandit-${item.test_id}-${item.filename}-${item.line_number}`,
  }));
  return { findings, stdout: run.stdout, stderr: run.stderr, exitCode: run.code };
}

interface NucleiResult {
  "template-id"?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    remediation?: string;
    reference?: string[] | string;
    classification?: { "cwe-id"?: string[] | string; "owasp"?: string[] };
    tags?: string[] | string;
  };
  host?: string;
  "matched-at"?: string;
  "matcher-name"?: string;
  "extracted-results"?: string[];
}

interface FfufResult {
  input?: { FUZZ?: string };
  url?: string;
  status?: number;
  length?: number;
  words?: number;
  lines?: number;
  redirectlocation?: string;
  "content-type"?: string;
}

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number; col?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: {
      cwe?: string[] | string;
      impact?: string;
      confidence?: string;
      references?: unknown[];
      remediation?: string;
    };
  };
}

interface GitleaksResult {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Secret?: string;
  Match?: string;
  Entropy?: number;
}

interface TrivyReport {
  Results?: Array<{
    Target?: string;
    Vulnerabilities?: Array<{
      VulnerabilityID?: string;
      PkgName?: string;
      InstalledVersion?: string;
      FixedVersion?: string;
      Severity?: string;
      Title?: string;
      Description?: string;
      PrimaryURL?: string;
      CVSS?: Record<string, unknown>;
    }>;
    Secrets?: Array<{ RuleID?: string; Title?: string; Severity?: string; StartLine?: number; Match?: string }>;
    Misconfigurations?: Array<{
      ID?: string;
      Title?: string;
      Description?: string;
      Severity?: string;
      Resolution?: string;
      References?: string[];
      CauseMetadata?: { StartLine?: number };
    }>;
  }>;
}

interface OsvCliResult {
  source?: { path?: string };
  packages?: Array<{
    package?: { name?: string; version?: string; ecosystem?: string };
    vulnerabilities?: Array<{ id?: string; summary?: string; database_specific?: { severity?: string }; severity?: Array<{ score?: string }> }>;
  }>;
}

interface BanditResult {
  filename?: string;
  line_number?: number;
  issue_severity?: string;
  issue_confidence?: string;
  issue_text?: string;
  test_id?: string;
  test_name?: string;
  more_info?: string;
}

interface RunResult {
  stdout: string;
  stderr: string;
  code: number;
}

async function runBinary(
  command: string,
  args: string[],
  options: { timeoutMs: number; signal?: AbortSignal; cwd?: string; maxBytes?: number },
): Promise<RunResult> {
  let proc;
  try {
    proc = Bun.spawn([command, ...args], {
      cwd: options.cwd,
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env },
    });
  } catch (error) {
    return { stdout: "", stderr: error instanceof Error ? error.message : String(error), code: 127 };
  }
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try {
      proc.kill();
    } catch {
      // process already exited
    }
  }, options.timeoutMs);
  const abort = () => {
    try {
      proc.kill();
    } catch {
      // process already exited
    }
  };
  options.signal?.addEventListener("abort", abort, { once: true });
  try {
    const [stdout, stderr, code] = await Promise.all([
      readLimited(proc.stdout, options.maxBytes ?? 8_000_000),
      readLimited(proc.stderr, 1_000_000),
      proc.exited,
    ]);
    return {
      stdout,
      stderr: timedOut ? `${stderr}\nTimed out after ${options.timeoutMs}ms` : stderr,
      code: timedOut ? 124 : code,
    };
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
  }
}

async function readLimited(stream: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<string> {
  if (!stream) return "";
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const remaining = maxBytes - total;
      const chunk = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      chunks.push(chunk);
      total += chunk.byteLength;
      if (chunk.byteLength < value.byteLength) break;
    }
  } catch {
    // stream ended abruptly
  } finally {
    try {
      await reader.cancel();
    } catch {
      // ignore
    }
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function artifactDir(ctx: ProbeContext): Promise<string> {
  const dir = join(ctx.runDir, "artifacts");
  await mkdir(dir, { recursive: true });
  return dir;
}

async function saveToolOutput(ctx: ProbeContext, id: string, result: ExternalToolResult): Promise<void> {
  try {
    const dir = await artifactDir(ctx);
    const body = `exit=${result.exitCode}\n--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}\n`;
    await writeFile(join(dir, `${id}.log`), body.slice(0, 4_000_000), "utf8");
  } catch {
    // artifact persistence must not fail the scan
  }
}

function skipped(reason: string): ExternalToolResult {
  return { findings: [], stdout: "", stderr: "", exitCode: 0, skipped: reason };
}

function webTarget(ctx: ProbeContext): string | undefined {
  return ctx.target.url ?? ctx.target.baseUrl;
}

function firstLine(value: string): string {
  return value.split(/\r?\n/).map((line) => line.trim()).find(Boolean)?.slice(0, 160) ?? "";
}

function normalizeSeverity(value?: string): Severity {
  const normalized = String(value ?? "").toLowerCase();
  if (normalized.includes("critical")) return "critical";
  if (normalized.includes("high")) return "high";
  if (normalized.includes("medium") || normalized.includes("moderate") || normalized === "warning") return "medium";
  if (normalized.includes("low") || normalized === "info" || normalized === "informational") return "low";
  return "medium";
}

function semgrepSeverity(severity?: string, impact?: string): Severity {
  const impactValue = String(impact ?? "").toUpperCase();
  if (impactValue === "HIGH" || impactValue === "CRITICAL") return "high";
  if (impactValue === "MEDIUM") return "medium";
  if (impactValue === "LOW") return "low";
  const value = String(severity ?? "").toUpperCase();
  if (value === "ERROR") return "high";
  if (value === "WARNING") return "medium";
  if (value === "INFO") return "low";
  return "medium";
}

function serviceRisk(port: number, service?: string): Severity {
  const critical = new Set([2375, 2379, 10250, 9200, 11211, 6379, 27017, 5601, 15672]);
  const high = new Set([21, 23, 445, 1433, 3306, 5432, 5900, 5985, 5986, 6443]);
  if (critical.has(port) || /redis|memcached|docker|kubelet|elasticsearch/i.test(service ?? "")) return "medium";
  if (high.has(port)) return "low";
  return "info";
}

function osvCliSeverity(vuln: { database_specific?: { severity?: string }; severity?: Array<{ score?: string }> }): Severity {
  const db = vuln.database_specific?.severity?.toUpperCase();
  if (db === "CRITICAL") return "critical";
  if (db === "HIGH") return "high";
  if (db === "MODERATE" || db === "MEDIUM") return "medium";
  if (db === "LOW") return "low";
  for (const entry of vuln.severity ?? []) {
    const score = entry.score ?? "";
    const impacts = score.match(/\/[CIA]:H/gi)?.length ?? 0;
    if (impacts >= 2) return "high";
    if (impacts === 1) return "medium";
  }
  return "medium";
}
