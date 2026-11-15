#!/usr/bin/env bun
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { defaultConfig, findConfigPath, loadConfig, saveScopeFile, scopeExample, saveConfig, ensureDataDirs, loadScopeFile } from "./core/config";
import { ArgusEngine } from "./core/engine";
import { ensurePromptScope } from "./core/prompt-scope";
import { ScopeGuard, validateScope } from "./core/scope";
import { SessionMemory } from "./core/session";
import { RunStore } from "./core/store";
import { acceptTerms, readConsent, revokeConsent, termsText } from "./core/authorization";
import { McpManager, runMcpServer } from "./core/mcp";
import { hasNetworkTarget } from "./core/prompt-scope";
import { runConnectors } from "./core/connectors";
import { writeReports } from "./core/report";
import { discoverTools } from "./core/tools";
import { eventLine } from "./core/events";
import { formatDuration, oneLine, severityAtLeast, truncate } from "./core/util";
import { runAgentPrompt } from "./tui/agent-runner";
import type { ProfileId, ReportFormat, RunOptions } from "./core/types";

const HELP = `ARGUS - authorized security assessment harness

Usage:
  argus init [--force]
  argus authorize [--accept <name> | --revoke | --status]
  argus scope init [path]
  argus scope validate <scope.json> [target] [--profile web]
  argus scan <target> [--scope <scope.json>] [options]
  argus resume -session <id>
  argus tools [--json]
  argus runs [--json]
  argus report <runId> [--format md|json|sarif|csv|html|research] [--stdout]
  argus mcp serve
  argus mcp tools
  argus mcp call <server> <tool> [jsonArgs]
  argus connectors list
  argus connectors send <runId>
  argus config show

Scan options:
  --profile quick|recon|web|api|network|deep|repo
  --intrusive            Enable deep confirmation adapters if scope allows
  --passive              Skip active checks
  --no-external          Skip registry, OSV and subdomain intelligence
  --formats md,json,sarif
  --retries <0-5>        Retry a failed probe (default 0; the TUI uses 2)
  --no-tools             Use native probes only
  --quiet                Only print warnings, errors and final summary

Authorization:
  Scan authorization is derived from the target you name. A manual --scope file
  is still honored and is never overwritten. Generated scopes are self-updating.
`;

const PROFILES: ProfileId[] = ["quick", "recon", "web", "api", "network", "deep", "repo"];
const REPORTS: ReportFormat[] = ["markdown", "json", "sarif", "csv", "html", "research"];
const ANSI = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
};

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const { positionals, flags } = parseArgs(argv);
  const command = positionals[0];
  if (flags.get("version")) {
    let version = "0.0.0";
    try {
      const pkg = JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8")) as {
        version?: string;
      };
      version = pkg.version ?? version;
    } catch {
      // a packaged or relocated entrypoint keeps a safe default
    }
    process.stdout.write(`argus ${version}\n`);
    return;
  }
  if (!command || flags.get("help")) {
    process.stdout.write(HELP);
    return;
  }
  switch (command) {
    case "init":
      return init(Boolean(flags.get("force")));
    case "authorize":
    case "authorise":
      return authorizeCommand(positionals.slice(1), flags);
    case "scan":
      return scan(positionals.slice(1), flags);
    case "resume":
      return resume(positionals.slice(1), flags);
    case "tools":
      return tools(Boolean(flags.get("json")));
    case "runs":
      return runs(Boolean(flags.get("json")));
    case "report":
      return report(positionals.slice(1), flags);
    case "scope":
      return scopeCommand(positionals.slice(1), flags);
    case "mcp":
      return mcpCommand(positionals.slice(1), flags);
    case "connectors":
      return connectorsCommand(positionals.slice(1));
    case "config":
      return configCommand(positionals.slice(1));
    default:
      fail(`Unknown command: ${command}\n\n${HELP}`);
  }
}

async function init(force: boolean): Promise<void> {
  const config = defaultConfig();
  const configPath = resolve("argus.config.json");
  const scopePath = resolve("scope.json");
  if (existsSync(configPath) && !force) {
    process.stdout.write(`Config already exists: ${configPath}\nUse --force to overwrite.\n`);
  } else {
    await saveConfig(config, configPath);
    process.stdout.write(`Wrote ${configPath}\n`);
  }
  if (existsSync(scopePath) && !force) {
    process.stdout.write(`Scope already exists: ${scopePath}\nUse --force to overwrite.\n`);
  } else {
    await saveScopeFile(scopeExample(), scopePath);
    process.stdout.write(`Wrote example ${scopePath}\n`);
  }
  await ensureDataDirs(config.dataDir);
  process.stdout.write(`Data directory: ${config.dataDir}\n`);
  process.stdout.write(
    "The example scope.json is optional: a target named in the prompt (or on `argus scan <target>`) is authorized automatically. Edit it only when you want a durable, operator-authored authorization record.\n",
  );
}

async function authorizeCommand(args: string[], flags: FlagMap): Promise<void> {
  const config = await loadConfig();
  const sub = args[0]?.toLowerCase();
  if (flags.get("revoke") || sub === "revoke") {
    await revokeConsent(config.dataDir);
    process.stdout.write("Authorized-use acceptance revoked.\n");
    return;
  }
  if (flags.get("accept") || sub === "accept") {
    const flagName = typeof flags.get("accept") === "string" ? String(flags.get("accept")) : "";
    const positional = (sub === "accept" ? args.slice(1) : args).join(" ").trim();
    const record = await acceptTerms(config.dataDir, flagName || positional || undefined);
    process.stdout.write(`Authorized-use agreement accepted at ${record.acceptedAt}.\n`);
    process.stdout.write("Operator mode is on: in-scope assessments run without confirmation prompts.\n");
    process.stdout.write("Scope and the deny list still bound every target.\n");
    return;
  }
  const consent = await readConsent(config.dataDir);
  process.stdout.write(
    consent
      ? `Accepted ${consent.acceptedAt}${consent.acceptedBy ? ` by ${consent.acceptedBy}` : ""}.\n\n`
      : "Not accepted. Network assessments are blocked until you accept.\n\n",
  );
  process.stdout.write(`${termsText()}\n`);
  process.stdout.write("\nAccept with: argus authorize --accept <your name>\nRevoke with: argus authorize --revoke\n");
}

async function scan(args: string[], flags: FlagMap): Promise<void> {
  const target = args[0];
  if (!target) fail("Usage: argus scan <target> [--scope <scope.json>]");
  const config = await loadConfig();
  if (!flags.get("scope") && hasNetworkTarget([target]) && !(await readConsent(config.dataDir))) {
    fail(`${termsText()}\n\nAccept once with: argus authorize --accept <your name>`);
  }
  const explicitScope = stringFlag(flags, "scope");
  const profile = parseProfile(stringFlag(flags, "profile") ?? config.defaultProfile);
  const passive = Boolean(flags.get("passive"));
  const intrusive = Boolean(flags.get("intrusive"));
  let scopePath = explicitScope ?? "scope.json";
  if (explicitScope) {
    if (!existsSync(resolve(scopePath))) fail(`Scope file not found: ${resolve(scopePath)}`);
  } else {
    const ensured = await ensurePromptScope(scopePath, target, {
      workspace: process.cwd(),
      targets: [target],
      profile,
      passive,
      intrusive,
      external: !flags.get("no-external"),
      override: true,
      maxRps: config.maxRps,
    });
    scopePath = ensured.path;
  }
  const scope = await loadScopeFile(scopePath);
  const validation = validateScope(scope);
  if (!validation.ok) fail(`Scope rejected: ${validation.errors.join(" ")}`);
  new ScopeGuard(scope).resolveTarget(target, profile);
  const formats = parseFormats(stringFlag(flags, "formats"));
  const options: RunOptions = {
    profile,
    passiveOnly: passive,
    intrusive,
    allowExternal: flags.get("no-external") ? false : true,
    exportFormats: formats,
  };
  if (flags.get("no-tools")) options.detectTools = false;
  const retries = stringFlag(flags, "retries");
  if (retries !== undefined) {
    const parsed = Number.parseInt(retries, 10);
    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 5) fail("--retries must be a number from 0 to 5");
    options.retryFailedTasks = parsed;
  }
  const quiet = Boolean(flags.get("quiet"));
  const engine = new ArgusEngine(config);
  const controller = new AbortController();
  const onSigint = () => controller.abort();
  process.once("SIGINT", onSigint);
  const unsubscribe = engine.bus.subscribe((event) => {
    if (event.type === "task:end" && event.status === "failed" && event.message) {
      process.stderr.write(`${ANSI.yellow}task failed${ANSI.reset} ${event.label}: ${oneLine(event.message)}\n`);
      return;
    }
    if (event.type === "finding") {
      const finding = event.finding;
      if (quiet && !severityAtLeast(finding.severity, "medium")) return;
      process.stdout.write(`${severityColor(finding.severity)}[${finding.severity.toUpperCase()}]${ANSI.reset} ${finding.title} ${ANSI.dim}(${finding.target})${ANSI.reset}\n`);
      return;
    }
    if (event.type === "log" && (event.level === "warn" || event.level === "error")) {
      process.stderr.write(`${event.level === "error" ? ANSI.red : ANSI.yellow}${event.level}${ANSI.reset} ${event.message}\n`);
      return;
    }
    if (event.type === "tool:status" && !quiet && (event.status === "running" || event.status === "done" || event.status === "failed")) {
      process.stdout.write(`${ANSI.dim}tool ${event.tool} ${event.status}${event.message ? ` - ${oneLine(event.message)}` : ""}${ANSI.reset}\n`);
      return;
    }
    if (!quiet) process.stdout.write(`${ANSI.dim}${eventLine(event)}${ANSI.reset}\n`);
  });
  try {
    process.stdout.write(`${ANSI.bold}ARGUS${ANSI.reset} ${profile} -> ${target} ${ANSI.dim}(${scopePath})${ANSI.reset}\n`);
    const handle = await engine.run({ target, scopePath, options }, { signal: controller.signal });
    const duration = handle.record.startedAt && handle.record.finishedAt
      ? formatDuration(Date.parse(handle.record.finishedAt) - Date.parse(handle.record.startedAt))
      : "?";
    process.stdout.write(`\n${ANSI.bold}${handle.record.status.toUpperCase()}${ANSI.reset} ${handle.record.id} in ${duration}\n`);
    process.stdout.write(
      `Critical ${handle.record.counts.critical} | High ${handle.record.counts.high} | Medium ${handle.record.counts.medium} | Low ${handle.record.counts.low} | Info ${handle.record.counts.info}\n`,
    );
    const artifacts = await engine.store.listArtifacts(handle.record.id);
    const reports = artifacts.filter((artifact) => artifact.name.startsWith("report."));
    for (const artifact of reports) process.stdout.write(`report: ${join(engine.store.runDir(handle.record.id), artifact.name)}\n`);
    process.stdout.write(`run dir: ${engine.store.runDir(handle.record.id)}\n`);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  } finally {
    unsubscribe();
    process.removeListener("SIGINT", onSigint);
  }
}

async function resume(args: string[], flags: FlagMap): Promise<void> {
  const id = stringFlag(flags, "session") ?? args[0];
  if (!id) fail("Usage: argus resume -session <id>");
  const config = await loadConfig();
  const found = await SessionMemory.byId(config.dataDir, id);
  if (!found) fail(`Session not found: ${id}`);
  const turns = await found.session.load();
  if (turns.length === 0) fail(`Session has no turns: ${id}`);
  if (!existsSync(found.workspace)) fail(`Session workspace is missing: ${found.workspace}`);
  const last = turns[turns.length - 1]!;
  process.stdout.write(
    `${ANSI.bold}ARGUS resume${ANSI.reset} ${found.session.id} ${ANSI.dim}${found.workspace}${ANSI.reset}\n`,
  );
  process.stdout.write(`${ANSI.dim}last: ${truncate(oneLine(last.prompt), 180)}${ANSI.reset}\n`);
  const engine = new ArgusEngine(config);
  const scopePath = resolve(found.workspace, "scope.json");
  try {
    const result = await runAgentPrompt({
      config,
      engine,
      scopePath,
      prompt: "continue",
      workspace: found.workspace,
      callbacks: {
        onStep: (step, note) => process.stdout.write(`${ANSI.dim}step ${step} | ${oneLine(note)}${ANSI.reset}\n`),
        onTool: (tool, status, detail) => {
          if (status === "start") {
            process.stdout.write(`${ANSI.dim}> ${tool}${detail ? ` | ${oneLine(detail)}` : ""}${ANSI.reset}\n`);
            return;
          }
          if (status === "error") {
            process.stdout.write(`${ANSI.red}! ${tool} | ${oneLine(detail ?? "failed")}${ANSI.reset}\n`);
          }
        },
      },
    });
    process.stdout.write(`\n${ANSI.bold}RESULT${ANSI.reset}\n${result.summary}\n`);
    for (const finding of result.verified) {
      process.stdout.write(
        `${severityColor(finding.severity)}[${finding.severity.toUpperCase()}]${ANSI.reset} ${finding.title} ${ANSI.dim}(${finding.url ?? finding.target})${ANSI.reset}\n`,
      );
    }
    if (result.gaps.length > 0) {
      process.stdout.write(`${ANSI.dim}gaps: ${result.gaps.map((gap) => truncate(gap, 160)).join("; ")}${ANSI.reset}\n`);
    }
    process.stdout.write(`\nresume: argus resume -session ${result.sessionId ?? found.session.id}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.stdout.write(`resume: argus resume -session ${found.session.id}\n`);
    process.exitCode = 1;
  }
}

async function tools(json: boolean): Promise<void> {
  const config = await loadConfig();
  const found = await discoverTools();
  if (json) {
    process.stdout.write(`${JSON.stringify(found, null, 2)}\n`);
    return;
  }
  process.stdout.write(`${ANSI.bold}External tools${ANSI.reset} ${ANSI.dim}(${config.dataDir})${ANSI.reset}\n`);
  for (const tool of found) {
    const status = tool.installed ? `${ANSI.green}installed${ANSI.reset}` : `${ANSI.dim}missing${ANSI.reset}`;
    process.stdout.write(`${tool.installed ? "[x]" : "[ ]"} ${tool.name.padEnd(14)} ${status}${tool.version ? ` ${ANSI.dim}${truncate(oneLine(tool.version), 60)}${ANSI.reset}` : ""}\n`);
    if (!tool.installed) process.stdout.write(`  ${ANSI.dim}${tool.install}${ANSI.reset}\n`);
  }
  const installed = found.filter((tool) => tool.installed).length;
  process.stdout.write(`\n${installed}/${found.length} adapters available. Native probes always run.\n`);
}

async function runs(json: boolean): Promise<void> {
  const config = await loadConfig();
  const store = new RunStore(config.dataDir);
  const records = await store.list();
  if (json) {
    process.stdout.write(`${JSON.stringify(records, null, 2)}\n`);
    return;
  }
  if (records.length === 0) {
    process.stdout.write("No runs recorded.\n");
    return;
  }
  for (const record of records) {
    process.stdout.write(
      `${record.id} ${record.status.padEnd(9)} ${record.profile.padEnd(8)} C:${record.counts.critical} H:${record.counts.high} M:${record.counts.medium} L:${record.counts.low} ${record.target.display}\n`,
    );
  }
}

async function report(args: string[], flags: FlagMap): Promise<void> {
  const runId = args[0];
  if (!runId) fail("Usage: argus report <runId> [--format md|json|sarif|csv|html]");
  const config = await loadConfig();
  const store = new RunStore(config.dataDir);
  const handle = await store.load(runId);
  if (!handle) fail(`Run not found: ${runId}`);
  const format = parseFormats(stringFlag(flags, "format"))[0]!;
  if (flags.get("stdout")) {
    const { generateReport } = await import("./core/report");
    process.stdout.write(generateReport(handle, format));
    return;
  }
  const paths = await writeReports(store, handle, [format]);
  for (const path of paths) process.stdout.write(`${path}\n`);
}

async function scopeCommand(args: string[], flags: FlagMap): Promise<void> {
  const sub = args[0];
  if (sub === "init") {
    const path = args[1] ?? "scope.json";
    const saved = await saveScopeFile(scopeExample(), path);
    process.stdout.write(`Wrote example ${saved}\n`);
    return;
  }
  if (sub === "validate" || sub === "check") {
    const path = args[1] ?? "scope.json";
    const scope = await loadScopeFile(path);
    const validation = validateScope(scope);
    process.stdout.write(`${JSON.stringify(validation, null, 2)}\n`);
    if (!validation.ok) process.exitCode = 1;
    const target = args[2];
    if (target && validation.ok) {
      const guard = new ScopeGuard(scope);
      const resolved = guard.resolveTarget(target, parseProfile(stringFlag(flags, "profile") ?? "web"));
      process.stdout.write(`Authorized target: ${JSON.stringify(resolved, null, 2)}\n`);
    }
    return;
  }
  fail("Usage: argus scope <init|validate> ...");
}

async function mcpCommand(args: string[], flags: FlagMap): Promise<void> {
  const sub = args[0];
  const config = await loadConfig();
  if (sub === "serve") {
    process.stderr.write(`ARGUS MCP server starting (${config.dataDir})\n`);
    await runMcpServer(config);
    return;
  }
  const manager = new McpManager();
  try {
    const tools = await manager.connectAll(config.mcpServers);
    if (sub === "tools") {
      if (flags.get("json")) {
        process.stdout.write(`${JSON.stringify(tools, null, 2)}\n`);
      } else if (tools.length === 0) {
        process.stdout.write("No MCP tools available. Configure mcpServers in argus.config.json.\n");
      } else {
        for (const tool of tools) process.stdout.write(`${tool.server} :: ${tool.name} ${tool.description ? `- ${oneLine(tool.description)}` : ""}\n`);
      }
      return;
    }
    if (sub === "call") {
      const server = args[1];
      const tool = args[2];
      if (!server || !tool) fail("Usage: argus mcp call <server> <tool> [jsonArgs]");
      const json = args[3] ?? "{}";
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(json) as Record<string, unknown>;
      } catch {
        fail("MCP arguments must be valid JSON.");
      }
      const result = await manager.call(server, tool, parsed);
      process.stdout.write(`${typeof result === "string" ? result : JSON.stringify(result, null, 2)}\n`);
      return;
    }
    fail("Usage: argus mcp <serve|tools|call> ...");
  } finally {
    await manager.disconnect();
  }
}

async function connectorsCommand(args: string[]): Promise<void> {
  const sub = args[0];
  const config = await loadConfig();
  if (sub === "list") {
    if (config.connectors.length === 0) {
      process.stdout.write("No connectors configured.\n");
      return;
    }
    for (const connector of config.connectors) {
      process.stdout.write(`${connector.id} ${connector.type} ${connector.enabled ? "enabled" : "disabled"} min:${connector.minSeverity ?? "info"}\n`);
    }
    return;
  }
  if (sub === "send") {
    const runId = args[1];
    if (!runId) fail("Usage: argus connectors send <runId>");
    const store = new RunStore(config.dataDir);
    const handle = await store.load(runId);
    if (!handle) fail(`Run not found: ${runId}`);
    const results = await runConnectors(config.connectors, handle);
    if (results.length === 0) {
      process.stdout.write("No enabled connectors.\n");
      return;
    }
    for (const result of results) process.stdout.write(`${result.id} ${result.status}${result.message ? ` - ${oneLine(result.message)}` : ""}\n`);
    return;
  }
  fail("Usage: argus connectors <list|send> ...");
}

async function configCommand(args: string[]): Promise<void> {
  const sub = args[0];
  const config = await loadConfig();
  if (sub === "show") {
    process.stdout.write(`${JSON.stringify(config, null, 2)}\n`);
    return;
  }
  if (sub === "path") {
    process.stdout.write(`${findConfigPath() ?? "(defaults; no config file)"}\n`);
    return;
  }
  fail("Usage: argus config <show|path>");
}

type FlagValue = string | boolean;
type FlagMap = Map<string, FlagValue>;

const BOOLEAN_FLAGS = new Set([
  "help",
  "version",
  "force",
  "yes-authorized",
  "intrusive",
  "passive",
  "external",
  "no-external",
  "no-tools",
  "quiet",
  "json",
  "stdout",
]);

function parseArgs(argv: string[]): { positionals: string[]; flags: FlagMap } {
  const flags: FlagMap = new Map();
  const positionals: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const raw = argv[index]!;
    // Accept both --session and the shorter -session form printed by older docs.
    const arg = /^-[A-Za-z][A-Za-z0-9-]*$/.test(raw) ? `-${raw}` : raw;
    if (!arg.startsWith("--") || arg === "--") {
      positionals.push(arg);
      continue;
    }
    const body = arg.slice(2);
    if (body.includes("=")) {
      const [key, ...rest] = body.split("=");
      flags.set(key!, rest.join("="));
      continue;
    }
    if (BOOLEAN_FLAGS.has(body)) {
      flags.set(body, true);
      continue;
    }
    const next = argv[index + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags.set(body, next);
      index += 1;
    } else {
      flags.set(body, true);
    }
  }
  return { positionals, flags };
}

function stringFlag(flags: FlagMap, key: string): string | undefined {
  const value = flags.get(key);
  return typeof value === "string" ? value : undefined;
}

function parseProfile(value: string): ProfileId {
  if (!PROFILES.includes(value as ProfileId)) fail(`Unknown profile: ${value}. Use ${PROFILES.join(", ")}.`);
  return value as ProfileId;
}

function parseFormats(value: string | undefined): ReportFormat[] {
  if (!value) return ["markdown", "json", "sarif"];
  const alias: Record<string, ReportFormat> = { md: "markdown", markdown: "markdown", json: "json", sarif: "sarif", csv: "csv", html: "html", research: "research", r: "research" };
  const formats: ReportFormat[] = [];
  for (const part of value.split(/[\s,]+/).map((item) => item.trim().toLowerCase()).filter(Boolean)) {
    const format = alias[part];
    if (!format || !REPORTS.includes(format)) fail(`Unknown report format: ${part}`);
    if (!formats.includes(format)) formats.push(format);
  }
  return formats;
}

function severityColor(severity: string): string {
  if (severity === "critical") return ANSI.magenta;
  if (severity === "high") return ANSI.red;
  if (severity === "medium") return ANSI.yellow;
  if (severity === "low") return ANSI.blue;
  return ANSI.dim;
}

function fail(message: string, code = 1): never {
  process.stderr.write(`${message}\n`);
  process.exit(code);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
