import { readFile, stat } from "node:fs/promises";
import { acceptTerms, readConsent, revokeConsent, termsLines } from "../core/authorization";
import { isAbsolute, relative, resolve } from "node:path";
import { loadScopeFile, saveScopeFile, scopeExample } from "../core/config";
import type { ArgusEngine } from "../core/engine";
import { HttpClient } from "../core/http";
import { analyzeJwt } from "../core/jwt";
import { ensureProjectMemory, memoryPath, readProjectMemory } from "../core/memory";
import { McpManager } from "../core/mcp";
import { ensurePromptScope, isGeneratedScope, localRootsForScope } from "../core/prompt-scope";
import { buildPipeline } from "../core/pipeline";
import { buildFixPlan } from "../core/remediation";
import { runDoctor } from "./doctor";
import { writeReports } from "../core/report";
import { ScopeGuard, validateScope } from "../core/scope";
import { discoverTools } from "../core/tools";
import { detectWsl } from "../core/wsl";
import { buildTerminalSpec, buildVimSpec, type TerminalSpec } from "./terminal-spec";
import { readWebPage, searchWeb } from "../core/web";
import { buildInstallPlans, runInstallPlan } from "../core/installer";
import { GLYPH, MARK } from "./theme";
import type {
  ArgusConfig,
  ProfileId,
  ReportFormat,
  RunHandle,
  ScopePolicy,
  Severity,
  SeverityCounts,
} from "../core/types";
import { expandHome, findingRiskScore, formatDuration, oneLine, rankFindings, truncate } from "../core/util";
import { previewNote, textPreview, type PreviewPayload } from "./preview";
import {
  apiKeyPresent,
  keyStatus,
  listProviderModels,
  llmSettings,
  PROVIDERS,
  resolveProvider,
  saveLlmSettings,
} from "./providers";
import type { TranscriptKind } from "./state";
import type { DoctorStatus } from "./doctor";

const PROFILES: ProfileId[] = ["quick", "recon", "web", "api", "network", "deep", "repo"];
const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const JWT_SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function parseHeaderArgument(raw: string): { name: string; value: string } {
  const colon = raw.indexOf(":");
  if (colon <= 0) throw new Error('header must look like "Name: value"');
  const name = raw.slice(0, colon).trim();
  const value = raw.slice(colon + 1).trim();
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) throw new Error(`invalid header name: ${name}`);
  if (/[\r\n]/.test(value)) throw new Error("header values cannot contain newlines");
  return { name, value };
}

const FORMATS: Record<string, ReportFormat> = {
  md: "markdown",
  markdown: "markdown",
  json: "json",
  sarif: "sarif",
  csv: "csv",
  html: "html",
  research: "research",
  narrative: "research",
};

export interface CommandSpec {
  name: string;
  usage: string;
  summary: string;
}

export const COMMANDS: CommandSpec[] = [
  { name: "/help", usage: "/help", summary: "list commands" },
  { name: "/doctor", usage: "/doctor [--chat]", summary: "preflight provider, key, model, scope, memory and adapters" },
  { name: "/scan", usage: "/scan <target> [--profile deep] [--scope file]", summary: "run an assessment; scope follows the target" },
  { name: "/dashboard", usage: "/dashboard", summary: "charts for findings and coverage" },
  { name: "/providers", usage: "/providers [use <id> | url <baseUrl> | key <ENV_VAR>]", summary: "switch AI provider" },
  { name: "/models", usage: "/models [<model>] [--refresh]", summary: "list or select a model" },
  { name: "/connect", usage: "/connect [mcp-server]", summary: "providers, keys and MCP servers" },
  { name: "/key", usage: "/key [provider]", summary: "add or replace an API key in one step" },
  { name: "/copy", usage: "/copy [last|all]", summary: "copy the last answer or transcript" },
  { name: "/memory", usage: "/memory", summary: "show the AGENTS.md memory file" },
  { name: "/preview", usage: "/preview <path> [--start N] [--end N]", summary: "read-only file and diff preview panel" },
  { name: "/runs", usage: "/runs [limit]", summary: "recent assessments" },
  { name: "/pipeline", usage: "/pipeline [runId] [--all]", summary: "discovery -> validation -> exploitability -> patches -> review" },
  { name: "/findings", usage: "/findings [runId] [--all]", summary: "review findings" },
  { name: "/report", usage: "/report [runId] [md|json|sarif|csv|html]", summary: "write reports" },
  { name: "/tools", usage: "/tools", summary: "external adapter inventory" },
  { name: "/install", usage: "/install [tool...] [--all] [--yes]", summary: "plan or run adapter installers (never elevates)" },
  { name: "/web", usage: "/web <query> | /web read <url>", summary: "keyless web research and public page reading" },
  { name: "/http", usage: "/http <url> [--method GET] [--header \"k: v\"] [--json body]", summary: "send one HTTP request; scope follows the URL" },
  { name: "/jwt", usage: "/jwt <token> [--json]", summary: "decode a JWT and flag session risks" },
  { name: "/scope", usage: "/scope [path | init | target]", summary: "show, derive or validate the active scope" },
  { name: "/config", usage: "/config", summary: "effective configuration" },
  { name: "/authorize", usage: "/authorize [accept <name> | revoke | status]", summary: "one-time authorized-use agreement; enables operator mode" },
  { name: "/vim", usage: "/vim [file]", summary: "open a file (or the project) in vim inside the embedded terminal" },
  { name: "/terminal", usage: "/terminal [command]", summary: "open an interactive shell or run a command in the embedded terminal" },
  { name: "/clear", usage: "/clear", summary: "clear the transcript" },
  { name: "/quit", usage: "/quit", summary: "exit" },
];

export interface ParsedCommand {
  name: string;
  args: string[];
  flags: Map<string, string | boolean>;
}

export function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  for (const char of input.trim()) {
    if (quote) {
      if (char === quote) quote = null;
      else current += char;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }
  if (current) tokens.push(current);
  return tokens;
}

export function parseCommandLine(line: string): ParsedCommand | null {
  const tokens = tokenize(line);
  const head = tokens[0];
  if (!head || !head.startsWith("/")) return null;
  const flags = new Map<string, string | boolean>();
  const args: string[] = [];
  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token.startsWith("--") && token.length > 2) {
      const [key, ...rest] = token.slice(2).split("=");
      if (rest.length > 0) {
        flags.set(key!.toLowerCase(), rest.join("="));
        continue;
      }
      const next = tokens[index + 1];
      if (next !== undefined && !next.startsWith("-")) {
        flags.set(key!.toLowerCase(), next);
        index += 1;
      } else {
        flags.set(key!.toLowerCase(), true);
      }
      continue;
    }
    if (/^-[a-z]$/i.test(token)) {
      const key = token.slice(1).toLowerCase();
      const next = tokens[index + 1];
      if (next !== undefined && !next.startsWith("-")) {
        flags.set(key, next);
        index += 1;
      } else {
        flags.set(key, true);
      }
      continue;
    }
    args.push(token);
  }
  return { name: head.toLowerCase(), args, flags };
}

export function matchCommands(input: string): CommandSpec[] {
  const trimmed = input.trimStart();
  if (!trimmed.startsWith("/") || /\s/.test(trimmed)) return [];
  const token = trimmed.toLowerCase();
  if (token === "/") return COMMANDS;
  return COMMANDS.filter((command) => command.name.startsWith(token));
}

export interface ScanRequest {
  target: string;
  profile: ProfileId;
  scopePath: string;
  passiveOnly: boolean;
  intrusive: boolean;
  allowExternal: boolean;
  formats: ReportFormat[];
  retries: number;
}

function flagString(flags: Map<string, string | boolean>, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = flags.get(key);
    if (typeof value === "string") return value;
  }
  return undefined;
}

function flagBool(flags: Map<string, string | boolean>, ...keys: string[]): boolean {
  return keys.some((key) => flags.has(key));
}

function flagNumber(
  flags: Map<string, string | boolean>,
  key: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = flags.get(key);
  const parsed = typeof raw === "string" ? Number.parseInt(raw, 10) : Number.NaN;
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

export function parseFormats(value: string | undefined): ReportFormat[] {
  if (!value) return ["markdown", "json", "sarif"];
  const formats: ReportFormat[] = [];
  for (const part of value.split(/[\s,]+/).filter(Boolean)) {
    const format = FORMATS[part.toLowerCase()];
    if (!format) throw new Error(`unknown report format: ${part}`);
    if (!formats.includes(format)) formats.push(format);
  }
  return formats;
}

/** Parses `/scan` arguments. Defaults are deliberately thorough. */
export function buildScanRequest(
  parsed: ParsedCommand,
  fallbackProfile: ProfileId = "deep",
): { request?: ScanRequest; error?: string } {
  const target = parsed.args[0];
  if (!target) return { error: "usage: /scan <target> [--profile deep] [--scope scope.json]" };
  const profile = (flagString(parsed.flags, "profile", "p") ?? fallbackProfile) as ProfileId;
  if (!PROFILES.includes(profile)) return { error: `unknown profile ${profile}. use ${PROFILES.join(", ")}` };
  let formats: ReportFormat[];
  try {
    formats = parseFormats(flagString(parsed.flags, "formats"));
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
  return {
    request: {
      target,
      profile,
      scopePath: flagString(parsed.flags, "scope", "s") ?? "scope.json",
      passiveOnly: flagBool(parsed.flags, "passive"),
      intrusive: flagBool(parsed.flags, "intrusive"),
      allowExternal: !flagBool(parsed.flags, "no-external"),
      formats,
      retries: flagBool(parsed.flags, "no-retry") ? 0 : flagNumber(parsed.flags, "retries", 2, 0, 5),
    },
  };
}

export interface CommandIO {
  write(kind: TranscriptKind, text: string, severity?: Severity): void;
  clear(): void;
  quit(): void;
}

export interface CommandDeps {
  config: ArgusConfig;
  scopePath: string;
  engine: ArgusEngine;
  io: CommandIO;
  running: boolean;
  lastRunId?: string;
  setConfig(config: ArgusConfig): void;
  setScopePath(path: string): void;
  setLastRunId(id: string): void;
  startScan(request: ScanRequest): Promise<void>;
  /** Opens the read-only preview panel; without it the lines print to the transcript. */
  openPreview?(payload: PreviewPayload): void;
  /** Opens the embedded interactive terminal (PTY). */
  openTerminal?(spec: TerminalSpec): void;
}

export function countLine(counts: SeverityCounts): string {
  return `CRIT=${counts.critical} | HIGH=${counts.high} | MED=${counts.medium} | LOW=${counts.low} | INFO=${counts.info}`;
}

function stamp(iso: string | undefined): string {
  if (!iso) return " - ";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return " - ";
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function describeScope(scope: ScopePolicy): string[] {
  const lines: string[] = [];
  lines.push(`name        ${scope.name}`);
  lines.push(`authorized  ${scope.authorizedBy}`);
  lines.push(`reference   ${scope.authorizationRef}`);
  lines.push(`expires     ${scope.expiresAt}`);
  lines.push(`source      ${isGeneratedScope(scope) ? "prompt-derived (self-updating)" : "operator-authored"}`);
  const flags = [
    `active ${scope.allowActive ? "on" : "off"}`,
    `intrusive ${scope.allowIntrusive ? "allowed" : "locked"}`,
    `external ${scope.allowExternal ? "allowed" : "locked"}`,
  ];
  lines.push(`mode        ${flags.join(" | ")}`);
  lines.push(`allow       ${(scope.allow ?? []).slice(0, 10).join(", ") || "(none)"}`);
  if ((scope.allow?.length ?? 0) > 10) lines.push(`            +${(scope.allow?.length ?? 0) - 10} more`);
  if (scope.deny?.length) lines.push(`deny        ${scope.deny.slice(0, 6).join(", ")}`);
  return lines;
}

async function printProviders(deps: CommandDeps, config: ArgusConfig): Promise<void> {
  const settings = llmSettings(config);
  const active = resolveProvider(settings);
  deps.io.write("system", `providers | ${PROVIDERS.length} endpoints | OpenAI-compatible`);
  for (const provider of PROVIDERS) {
    if (provider.id === "custom") continue;
    const marker = provider.id === active.id ? GLYPH.bar : " ";
    const key = provider.apiKeyEnv ? (process.env[provider.apiKeyEnv] ? "key set" : `no ${provider.apiKeyEnv}`) : "no key needed";
    const models = provider.models.length > 0 ? `${provider.models.length} models` : "live only";
    deps.io.write(
      provider.id === active.id ? "ok" : "dim",
      `${marker} ${provider.id.padEnd(11)} ${provider.label.padEnd(17)} ${truncate(provider.baseUrl, 30).padEnd(30)} ${models.padEnd(10)} ${key}`,
    );
  }
  if (active.id === "custom") {
    deps.io.write("ok", `${GLYPH.bar} custom      Custom endpoint   ${truncate(active.baseUrl, 38)}`);
  }
  deps.io.write("info", `active      ${active.label} | ${settings.model}`);
  deps.io.write("info", `base url    ${settings.baseUrl}`);
  deps.io.write("info", `api key     ${keyStatus(settings)}`);
  deps.io.write("dim", "known models are listed by /models | live discovery runs when a key is available");
  deps.io.write("dim", "switch with /providers use <id> | custom with /providers url <baseUrl>");
}

export async function runCommand(line: string, deps: CommandDeps): Promise<void> {
  const parsed = parseCommandLine(line);
  if (!parsed) {
    deps.io.write("warn", "commands start with / - type /help for the command list");
    return;
  }
  let config = deps.config;
  const io = deps.io;

  switch (parsed.name) {
    case "/help": {
      io.write("system", "commands");
      for (const command of COMMANDS) {
        io.write("info", `${command.name.padEnd(13)} ${command.summary}`);
        if (command.usage !== command.name) io.write("dim", `             ${command.usage}`);
      }
      io.write("dim", "scan flags: --profile quick|recon|web|api|network|deep|repo | --scope <file> | --passive | --intrusive");
      io.write("dim", "            --no-external | --retries 0-5 | --formats md,json,sarif");
      io.write("dim", "scope is derived from the target you name; a manual --scope file is still honored");
      io.write("dim", "/scan defaults to the deep profile and two retries per failed probe.");
      io.write("dim", "plain text goes to the agent - it can scan, read source, and search the workspace.");
      return;
    }

    case "/vim": {
      if (!deps.openTerminal) {
        io.write("warn", "this session has no terminal surface");
        return;
      }
      const wanted = parsed.args.join(" ").trim();
      const wsl = await detectWsl().catch(() => undefined);
      deps.openTerminal(buildVimSpec(wanted || undefined, process.cwd(), wsl?.kali ? { distro: wsl.kali } : {}));
      return;
    }

    case "/terminal": {
      if (!deps.openTerminal) {
        io.write("warn", "this session has no terminal surface");
        return;
      }
      const command = parsed.args.join(" ").trim();
      deps.openTerminal(buildTerminalSpec(command || undefined, process.cwd()));
      return;
    }

    case "/authorize": {
      const action = parsed.args[0]?.toLowerCase();
      if (action === "accept" || action === "agree") {
        const record = await acceptTerms(deps.config.dataDir, parsed.args.slice(1).join(" "));
        io.write("ok", `authorized-use agreement accepted at ${record.acceptedAt}`);
        io.write("dim", "operator mode is on: in-scope assessments run without confirmation prompts; the prompt scope still bounds every target");
        return;
      }
      if (action === "revoke" || action === "reset") {
        await revokeConsent(deps.config.dataDir);
        io.write("ok", "authorized-use acceptance revoked");
        io.write("dim", "network assessments will ask for the agreement again");
        return;
      }
      const consent = await readConsent(deps.config.dataDir);
      io.write("system", "authorized use");
      io.write(
        consent ? "ok" : "warn",
        consent
          ? `accepted ${consent.acceptedAt}${consent.acceptedBy ? ` by ${consent.acceptedBy}` : ""} · operator mode on`
          : "not accepted · network assessments are blocked until you accept",
      );
      for (const line of termsLines()) io.write("info", line);
      io.write("dim", "accept: /authorize accept <your name>   revoke: /authorize revoke");
      return;
    }

    case "/doctor": {
      io.write("system", "doctor");
      io.write("dim", "checking provider, key, model, scope, memory, store and adapters...");
      const chatTest = parsed.flags.has("chat");
      if (chatTest) {
        io.write("dim", "chat test requested: sending one tiny completion (small credit use)");
      }
      const report = await runDoctor({
        config,
        scopePath: deps.scopePath,
        engine: deps.engine,
        chatTest,
      });
      const tone: Record<DoctorStatus, TranscriptKind> = { ok: "ok", warn: "warn", error: "error", info: "dim" };
      for (const check of report.checks) {
        io.write(tone[check.status], `${check.label.padEnd(10)} ${check.detail}`);
      }
      const summary = `doctor  ok=${report.ok}  warnings=${report.warnings}  errors=${report.errors}`;
      if (report.errors > 0) {
        io.write("error", summary);
        io.write("dim", "fix the errors above, then run /doctor again");
      } else if (report.warnings > 0) {
        io.write("warn", summary);
        io.write("dim", "warnings are optional; a valid scope is still required before any scan");
      } else {
        io.write("ok", summary);
      }
      return;
    }

    case "/memory": {
      const path = await ensureProjectMemory();
      const content = await readProjectMemory();
      io.write("system", `memory | ${path}`);
      io.write("dim", "edit AGENTS.md to give the agent durable context | never store secrets in it");
      if (!content.trim()) {
        io.write("dim", "empty - the agent appends verified outcomes here after a scan");
        return;
      }
      const lines = content.trim().split(/\r?\n/);
      io.write("dim", `${lines.length} lines | ${content.length} chars | target ${memoryPath()}`);
      for (const line of lines.slice(-18)) io.write("info", truncate(line, 140));
      io.write("dim", `memory | AGENTS.md | ${lines.length} lines | ${content.length} chars`);
      return;
    }

    case "/providers": {
      const sub = parsed.args[0]?.toLowerCase();
      if (!sub) {
        await printProviders(deps, config);
        return;
      }
      if (sub === "use") {
        const id = parsed.args[1]?.toLowerCase();
        if (!id) {
          io.write("error", "usage: /providers use <id> | ids: " + PROVIDERS.map((provider) => provider.id).join(", "));
          return;
        }
        const provider = PROVIDERS.find((entry) => entry.id === id);
        if (!provider) {
          io.write("error", `unknown provider ${id}. available: ${PROVIDERS.map((entry) => entry.id).join(", ")}`);
          return;
        }
        if (provider.id === "custom") {
          io.write("error", "custom endpoints need a URL: /providers url https://host/v1");
          return;
        }
        const next = await saveLlmSettings(config, {
          providerId: provider.id,
          baseUrl: provider.baseUrl,
          apiKeyEnv: provider.apiKeyEnv ?? "",
        });
        deps.setConfig(next);
        config = next;
        io.write("ok", `${MARK.done} provider | ${provider.label} | ${provider.baseUrl}`);
        io.write("dim", `api key ${keyStatus(llmSettings(next))} | run /connect to verify, /models to pick a model`);
        return;
      }
      if (sub === "url") {
        const value = parsed.args[1];
        if (!value) {
          io.write("error", "usage: /providers url https://host/v1");
          return;
        }
        let url: URL;
        try {
          url = new URL(value);
        } catch {
          io.write("error", `not a valid URL: ${value}`);
          return;
        }
        if (url.protocol !== "http:" && url.protocol !== "https:") {
          io.write("error", "provider base URL must be http or https");
          return;
        }
        const next = await saveLlmSettings(config, {
          providerId: "custom",
          baseUrl: value.replace(/\/+$/, ""),
        });
        deps.setConfig(next);
        config = next;
        io.write("ok", `${MARK.done} provider | custom | ${llmSettings(next).baseUrl}`);
        io.write("dim", "run /connect to verify the endpoint");
        return;
      }
      if (sub === "key") {
        const envName = parsed.args[1];
        if (!envName) {
          io.write("info", `api key is read from ${llmSettings(config).apiKeyEnv ?? "(no variable)"} - secrets never enter the transcript`);
          io.write("dim", "usage: /providers key GROQ_API_KEY");
          return;
        }
        if (!/^[A-Z][A-Z0-9_]*$/.test(envName)) {
          io.write("error", "env var names must look like PROVIDER_API_KEY");
          return;
        }
        const next = await saveLlmSettings(config, { apiKeyEnv: envName });
        deps.setConfig(next);
        config = next;
        io.write("ok", `api key source -> ${envName}`);
        io.write(next.llm?.apiKeyEnv && apiKeyPresent(llmSettings(next)) ? "ok" : "warn", keyStatus(llmSettings(next)));
        return;
      }
      io.write("error", "usage: /providers [use <id> | url <baseUrl> | key <ENV_VAR>]");
      return;
    }

    case "/models": {
      const requested = parsed.args[0];
      const settings = llmSettings(config);
      if (requested) {
        const next = await saveLlmSettings(config, { model: requested });
        deps.setConfig(next);
        config = next;
        io.write("ok", `${MARK.done} model | ${requested}`);
        io.write("dim", `${MARK.note} provider | ${resolveProvider(llmSettings(next)).label} | ${llmSettings(next).baseUrl}`);
        return;
      }
      const provider = resolveProvider(settings);
      io.write("info", `listing models from ${provider.label} | ${settings.baseUrl}`);
      if (provider.requiresKey && !apiKeyPresent(settings)) {
        io.write("warn", `no key in ${settings.apiKeyEnv ?? "the environment"} - remote providers will reject the request`);
      }
      try {
        const models = await listProviderModels(settings);
        io.write("ok", `${models.length} models available | active ${settings.model}`);
        const shown = models.slice(0, 40);
        for (const model of shown) {
          io.write(model === settings.model ? "ok" : "dim", `${model === settings.model ? "*" : " "} ${model}`);
        }
        if (models.length > shown.length) io.write("dim", `+${models.length - shown.length} more | /models <name> to select`);
        io.write("dim", `select with /models <name>`);
      } catch (error) {
        io.write("error", error instanceof Error ? error.message : String(error));
        const known = provider.models;
        if (known.length > 0) {
          io.write("dim", `known ${provider.label} models | live discovery unavailable`);
          for (const model of known) {
            io.write(model === settings.model ? "ok" : "dim", `${model === settings.model ? "*" : " "} ${model}`);
          }
          io.write("dim", "select with /models <name>");
        } else {
          io.write("dim", "type a model id: /models <name>");
        }
        io.write("dim", "check the base URL with /providers, or run /connect to verify reachability");
      }
      return;
    }

    case "/connect": {
      const settings = llmSettings(config);
      const provider = resolveProvider(settings);
      const serverArg = parsed.args[0];
      if (!serverArg) {
        io.write("info", `providers | ${PROVIDERS.filter((entry) => entry.id !== "custom").length} OpenAI-compatible endpoints`);
        for (const entry of PROVIDERS) {
          if (entry.id === "custom") continue;
          const current = entry.id === provider.id;
          const count = entry.models.length > 0 ? `${entry.models.length} models` : "discover live";
          io.write(
            current ? "ok" : "dim",
            `${current ? "*" : " "} ${entry.id.padEnd(11)} ${entry.label.padEnd(17)} ${count.padEnd(14)} ${truncate(entry.baseUrl, 34)}`,
          );
        }
        io.write("dim", "models per provider are listed by /models | verify the active one with /connect");
        io.write("info", `active provider | ${provider.label} | ${settings.baseUrl}`);
        try {
          const models = await listProviderModels(settings);
          io.write("ok", `provider reachable | ${models.length} models | active ${settings.model}`);
        } catch (error) {
          io.write("error", `provider check failed - ${error instanceof Error ? error.message : String(error)}`);
          if (provider.requiresKey && !apiKeyPresent(settings)) {
            io.write("dim", `export ${settings.apiKeyEnv ?? "PROVIDER_API_KEY"} before launching argus, then retry`);
          }
          if (provider.models.length > 0) {
            io.write("dim", `known ${provider.label} models: ${provider.models.join(", ")}`);
          }
        }
      }
      const servers = Object.entries(config.mcpServers ?? {});
      if (serverArg && !config.mcpServers?.[serverArg]) {
        io.write("error", `unknown MCP server ${serverArg}. configured: ${servers.map(([name]) => name).join(", ") || "(none)"}`);
        return;
      }
      if (servers.length === 0) {
        io.write("dim", "no MCP servers configured - add mcpServers to argus.config.json");
        return;
      }
      const manager = new McpManager();
      try {
        for (const [name, server] of servers) {
          if (serverArg && name !== serverArg) continue;
          if (server.enabled === false) {
            io.write("dim", `${name} | disabled`);
            continue;
          }
          try {
            const connection = await manager.connect(name, server);
            io.write("ok", `${name} | connected | ${connection.tools.length} tools`);
            for (const tool of connection.tools.slice(0, 6)) {
              io.write("dim", `  ${tool.name}${tool.description ? ` - ${oneLine(tool.description, 80)}` : ""}`);
            }
          } catch (error) {
            io.write("error", `${name} | failed - ${error instanceof Error ? error.message : String(error)}`);
          }
        }
      } finally {
        await manager.disconnect();
      }
      return;
    }

    case "/dashboard": {
      io.write("info", "the dashboard is a terminal chart view - type /dashboard with no arguments to open it");
      return;
    }

    case "/scan": {
      const { request, error } = buildScanRequest(parsed, "deep");
      if (!request) {
        io.write("error", error ?? "invalid scan arguments");
        return;
      }
      const explicitScope = parsed.flags.has("scope") || parsed.flags.has("s");
      if (!explicitScope) request.scopePath = deps.scopePath;
      let scope: ScopePolicy;
      if (!explicitScope) {
        try {
          const ensured = await ensurePromptScope(request.scopePath, request.target, {
            workspace: process.cwd(),
            targets: [request.target],
            profile: request.profile,
            passive: request.passiveOnly,
            intrusive: request.intrusive,
            external: request.allowExternal,
            override: true,
            maxRps: config.maxRps,
          });
          scope = ensured.scope;
          request.scopePath = ensured.path;
          deps.setScopePath(ensured.path);
          io.write(
            "ok",
            `${MARK.done} scope | ${ensured.source === "prompt" ? "authorization derived from the target" : ensured.source === "local" ? "workspace-only review scope created" : "operator scope loaded"} | ${ensured.path}`,
          );
          if (ensured.updated) io.write("dim", `${MARK.note} scope | generated scope updated; manual scope files are never overwritten`);
        } catch (scopeError) {
          io.write("error", `${MARK.fail} scope | could not derive authorization | ${scopeError instanceof Error ? scopeError.message : String(scopeError)}`);
          return;
        }
      } else {
        try {
          scope = await loadScopeFile(request.scopePath);
        } catch (loadError) {
          const message = loadError instanceof Error ? loadError.message : String(loadError);
          if (!/not found/i.test(message)) {
            io.write("error", message);
            return;
          }
          try {
            const ensured = await ensurePromptScope(request.scopePath, request.target, {
              workspace: process.cwd(),
              targets: [request.target],
              profile: request.profile,
              passive: request.passiveOnly,
              intrusive: request.intrusive,
              external: request.allowExternal,
              override: true,
              maxRps: config.maxRps,
            });
            scope = ensured.scope;
            request.scopePath = ensured.path;
            deps.setScopePath(ensured.path);
            io.write("ok", `${MARK.done} scope | new prompt scope created | ${ensured.path}`);
          } catch (scopeError) {
            io.write("error", `${MARK.fail} scope | could not create a prompt scope | ${scopeError instanceof Error ? scopeError.message : String(scopeError)}`);
            return;
          }
        }
      }
      const validation = validateScope(scope);
      if (!validation.ok) {
        io.write("error", `scope rejected: ${validation.errors.join(" ")}`);
        return;
      }
      try {
        const target = new ScopeGuard(scope).resolveTarget(request.target, request.profile);
        io.write("info", `target in scope | ${target.kind} | ${target.display}`);
      } catch (targetError) {
        io.write("error", targetError instanceof Error ? targetError.message : String(targetError));
        return;
      }
      deps.setScopePath(request.scopePath);
      io.write("info", `ruthless mode | profile ${request.profile} | ${request.retries} retries per probe`);
      io.write("dim", `${MARK.note} scope | active ${scope.allowActive ? "on" : "off"} | intrusive ${scope.allowIntrusive ? "on" : "off"} | external ${scope.allowExternal ? "on" : "off"}`);
      if (validation.warnings.length > 0) io.write("warn", validation.warnings.join(" "));
      await deps.startScan(request);
      return;
    }

    case "/runs": {
      const limit = flagNumber(parsed.flags, "limit", Number(parsed.args[0]) || 15, 1, 200);
      const runs = await deps.engine.store.list(limit);
      if (runs.length === 0) {
        io.write("info", "no assessments recorded yet - /scan <target>");
        return;
      }
      io.write("system", `recent runs | ${runs.length}`);
      for (const run of runs) {
        io.write(
          run.status === "completed" ? "info" : run.status === "failed" ? "error" : "warn",
          `${run.status === "completed" ? MARK.done : run.status === "failed" ? MARK.fail : "~"} ${run.status.padEnd(9)} ${run.profile.padEnd(7)} ${truncate(run.target.display, 44)}`,
        );
        io.write("dim", `  ${stamp(run.createdAt)} | ${countLine(run.counts)} | ${run.id}`);
      }
      const first = runs[0];
      if (first) deps.setLastRunId(first.id);
      return;
    }

    case "/findings": {
      const runId = parsed.args[0] ?? deps.lastRunId ?? (await deps.engine.store.list(1))[0]?.id;
      if (!runId) {
        io.write("info", "no run selected - run a scan or use /runs");
        return;
      }
      const handle = await deps.engine.store.load(runId);
      if (!handle) {
        io.write("error", `run not found: ${runId}`);
        return;
      }
      deps.setLastRunId(handle.record.id);
      io.write("system", "findings");
      io.write("info", `${handle.record.target.display}  ·  ${handle.record.status}  ·  ${handle.findings.length} finding(s)`);
      io.write("dim", `${countLine(handle.record.counts)}  ·  ${handle.record.id}`);
      if (handle.findings.length === 0) {
        io.write("ok", "clean run - no findings recorded");
        return;
      }
      const ranked = rankFindings(handle.findings);
      const cap = flagBool(parsed.flags, "all") ? ranked.length : Math.min(ranked.length, 12);
      for (const finding of ranked.slice(0, cap)) {
        io.write("finding", `risk ${findingRiskScore(finding)}  ·  ${finding.title}`, finding.severity);
        const meta = [finding.category, finding.confidence, finding.cwe, finding.owasp].filter(Boolean).join("  ·  ");
        io.write("dim", `  ${meta}  ·  ${finding.url ?? finding.target}`);
        if (finding.evidence) io.write("dim", `  evidence  ${oneLine(finding.evidence, 160)}`);
        io.write("dim", `  fix       ${oneLine(finding.remediation, 160)}`);
      }
      if (cap < ranked.length) io.write("dim", `+${ranked.length - cap} more | /findings ${handle.record.id} --all`);
      const plan = buildFixPlan(handle.findings, 5);
      if (plan.length > 0) {
        io.write("system", "FIX PLAN");
        for (const action of plan) {
          io.write("finding", `${action.priority} | ${action.remediation}`, action.severity);
          if (action.count > 1) io.write("dim", `     ${action.count} finding(s) share this fix`);
        }
      }
      return;
    }

    case "/pipeline": {
      const runId = parsed.args[0] ?? deps.lastRunId ?? (await deps.engine.store.list(1))[0]?.id;
      if (!runId) {
        io.write("info", "no run selected - run a scan or use /runs");
        return;
      }
      const handle = await deps.engine.store.load(runId);
      if (!handle) {
        io.write("error", `run not found: ${runId}`);
        return;
      }
      deps.setLastRunId(handle.record.id);
      const pipeline = buildPipeline(handle.findings);
      io.write("system", "assessment pipeline");
      io.write("info", `${handle.record.target.display}  ·  ${handle.record.status}  ·  ${handle.record.id}`);
      for (const stage of pipeline.stages) {
        const tone =
          stage.status === "blocked"
            ? "warn"
            : stage.status === "done"
              ? "ok"
              : stage.status === "awaiting"
                ? "info"
                : "dim";
        io.write(tone, `${stage.label.padEnd(26)} ${stage.status.padEnd(9)} ${stage.count}`);
        for (const note of stage.notes) io.write("dim", `  ${oneLine(note, 150)}`);
        if (flagBool(parsed.flags, "all")) {
          for (const entry of stage.items) io.write("dim", `  · [${entry.severity}] ${oneLine(entry.title, 110)}`);
        }
      }
      io.write("dim", "discovery -> validation -> exploitability -> candidate patches -> human review");
      io.write("dim", "nothing is applied or disclosed by ARGUS; the last gate is a human");
      return;
    }

    case "/report": {
      const requested = parsed.args[0];
      const runId = requested && !FORMATS[requested.toLowerCase()] ? requested : deps.lastRunId ?? (await deps.engine.store.list(1))[0]?.id;
      if (!runId) {
        io.write("info", "no run selected - run a scan or use /runs");
        return;
      }
      const handle = await deps.engine.store.load(runId);
      if (!handle) {
        io.write("error", `run not found: ${runId}`);
        return;
      }
      let formats: ReportFormat[];
      try {
        formats = parseFormats(requested && FORMATS[requested.toLowerCase()] ? requested : flagString(parsed.flags, "format"));
      } catch (formatError) {
        io.write("error", formatError instanceof Error ? formatError.message : String(formatError));
        return;
      }
      const paths = await writeReports(deps.engine.store, handle, formats);
      io.write("ok", `wrote ${paths.length} report(s) for ${handle.record.id}`);
      for (const path of paths) io.write("dim", path);
      return;
    }

    case "/preview": {
      const target = parsed.args[0];
      if (!target) {
        io.write("warn", "usage: /preview <path> [--start N] [--end N]");
        io.write("dim", "read-only: the panel shows numbered lines; the agent opens the same panel before a write");
        return;
      }
      const abs = resolve(expandHome(target));
      const roots = [resolve(process.cwd())];
      try {
        roots.push(...localRootsForScope(await loadScopeFile(deps.scopePath)));
      } catch {
        // no scope file is fine: the workspace stays the only read root
      }
      const inside = roots.some((root) => {
        const rel = relative(root, abs);
        return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
      });
      if (!inside) {
        io.write("error", `${MARK.fail} preview | refused | ${abs} is outside the workspace and the authorized local roots`);
        return;
      }
      let content: string;
      try {
        const info = await stat(abs);
        if (!info.isFile()) {
          io.write("error", `${MARK.fail} preview | ${abs} is not a file`);
          return;
        }
        if (info.size > 8 * 1024 * 1024) {
          io.write("error", `${MARK.fail} preview | ${abs} is ${Math.round(info.size / (1024 * 1024))} MB | too large to preview`);
          return;
        }
        content = await readFile(abs, "utf8");
      } catch (error) {
        io.write("error", `${MARK.fail} preview | ${error instanceof Error ? error.message : String(error)}`);
        return;
      }
      const start = Number(parsed.flags.get("start") ?? 1) || 1;
      const end = parsed.flags.get("end");
      const payload = textPreview(abs, content, {
        start,
        ...(typeof end === "string" || typeof end === "number" ? { end: Number(end) } : {}),
      });
      if (deps.openPreview) {
        deps.openPreview(payload);
        io.write("dim", `${MARK.note} preview | ${previewNote(payload)}`);
      } else {
        io.write("system", `preview | ${abs} | lines ${payload.start}-${payload.end} of ${payload.totalLines}`);
        for (const line of (payload.preview ?? "").split(/\r?\n/).slice(0, 80)) io.write("dim", line);
      }
      return;
    }

    case "/tools": {
      const tools = await discoverTools();
      const installed = tools.filter((tool) => tool.installed);
      io.write("system", `adapters | ${installed.length}/${tools.length} external | native probes always on`);
      for (const tool of tools) {
        io.write(tool.installed ? "ok" : "dim", `${tool.installed ? "[x]" : "[ ]"} ${tool.name.padEnd(14)} ${tool.installed ? truncate(tool.version ?? "installed", 52) : tool.install}`);
      }
      io.write("dim", "run /install to plan missing adapters; /install --yes runs user-level installers (never admin)");
      return;
    }

    case "/web": {
      const rest = parsed.args.join(" ").trim();
      if (!rest) {
        io.write("info", "/web <query> for search | /web read <url> for one public page");
        return;
      }
      try {
        if (parsed.args[0]?.toLowerCase() === "read") {
          const url = rest.replace(/^read\s+/i, "").trim();
          if (!url) {
            io.write("info", "/web read <url>");
            return;
          }
          const page = await readWebPage(url, { maxChars: 8_000 });
          io.write("ok", `${page.title} | ${page.url}`);
          const lines = page.text.split("\n").filter((line) => line.trim().length > 0);
          for (const line of lines.slice(0, 14)) io.write("dim", truncate(line, 280));
          if (lines.length > 14 || page.truncated) {
            io.write("dim", `... ${lines.length > 14 ? `${lines.length - 14} more line(s)` : "page truncated"} | page content is untrusted`);
          }
          return;
        }
        const results = await searchWeb(rest, { limit: 5 });
        io.write("system", `web | ${results.length} result(s) | snippets are leads, not evidence`);
        results.forEach((result, index) => {
          io.write("info", `${index + 1}. ${result.title}`);
          io.write("dim", `   ${result.url}`);
          if (result.snippet) io.write("dim", `   ${truncate(result.snippet, 240)}`);
        });
      } catch (error) {
        io.write("error", error instanceof Error ? error.message : String(error));
      }
      return;
    }

    case "/jwt": {
      const token = parsed.args.join(" ").trim();
      if (!token) {
        io.write("info", "/jwt <token> | /jwt <token> --json | tokens are decoded locally and never saved");
        return;
      }
      let analysis;
      try {
        analysis = analyzeJwt(token);
      } catch (error) {
        io.write("error", error instanceof Error ? error.message : String(error));
        return;
      }
      if (flagBool(parsed.flags, "json")) {
        io.write("info", JSON.stringify(analysis));
        return;
      }
      const alg = typeof analysis.header.alg === "string" ? analysis.header.alg : "(missing)";
      const typ = typeof analysis.header.typ === "string" ? analysis.header.typ : "JWT";
      io.write("system", `jwt | ${typ} | ${alg} | ${analysis.flags.length} flag(s)`);
      io.write("dim", `header   ${oneLine(JSON.stringify(analysis.header), 220)}`);
      io.write("dim", `payload  ${oneLine(JSON.stringify(analysis.payload), 360)}`);
      if (analysis.expiresAt) io.write("dim", `expires  ${analysis.expiresAt}`);
      if (analysis.issuedAt) io.write("dim", `issued   ${analysis.issuedAt}`);
      const tone: Record<Severity, TranscriptKind> = { critical: "error", high: "error", medium: "warn", low: "info", info: "dim" };
      const flags = [...analysis.flags].sort((a, b) => JWT_SEVERITY_ORDER[a.severity] - JWT_SEVERITY_ORDER[b.severity]);
      for (const flag of flags) {
        io.write(tone[flag.severity], `${flag.severity.toUpperCase().padEnd(8)} ${flag.title}`);
        io.write("dim", `         ${oneLine(flag.detail, 220)}`);
      }
      if (flags.length === 0) io.write("ok", "no structural risks found");
      io.write("dim", "signature is not verified | confirm every flag against the live verifier");
      return;
    }

    case "/http": {
      const url = parsed.args[0];
      if (!url) {
        io.write("info", "/http <url> [--method GET] [--header \"Authorization: Bearer ...\"] [--json body] [--scope scope.json]");
        io.write("dim", "requests are scope-checked and redirect-checked; the URL you name is the authorization");
        return;
      }
      const method = (flagString(parsed.flags, "method", "X") ?? "GET").toUpperCase();
      if (!HTTP_METHODS.has(method)) {
        io.write("error", `unsupported method ${method} | use ${[...HTTP_METHODS].join(", ")}`);
        return;
      }
      let headers: Record<string, string> = { accept: "*/*", "user-agent": config.userAgent };
      try {
        const extra = flagString(parsed.flags, "header", "H");
        if (extra) {
          const header = parseHeaderArgument(extra);
          headers[header.name.toLowerCase()] = header.value;
        }
      } catch (error) {
        io.write("error", error instanceof Error ? error.message : String(error));
        return;
      }
      const bearer = flagString(parsed.flags, "bearer");
      if (bearer) headers.authorization = `Bearer ${bearer}`;
      let body = flagString(parsed.flags, "body", "d");
      const jsonBody = flagString(parsed.flags, "json");
      const formBody = flagString(parsed.flags, "form");
      if (jsonBody !== undefined) {
        body = jsonBody;
        headers["content-type"] = "application/json";
      } else if (formBody !== undefined) {
        body = formBody;
        headers["content-type"] = "application/x-www-form-urlencoded";
      }
      if (body && (method === "GET" || method === "HEAD")) {
        io.write("error", `${method} requests cannot carry a body here | use --method POST/PUT/PATCH`);
        return;
      }
      if (body && body.length > 32_000) {
        io.write("error", "request body exceeds 32000 characters");
        return;
      }
      const explicitScope = flagString(parsed.flags, "scope", "s");
      let scopePath = explicitScope ?? deps.scopePath;
      let scope: ScopePolicy;
      if (!explicitScope) {
        try {
          const stateChanging = ["PUT", "PATCH", "DELETE"].includes(method);
          const ensured = await ensurePromptScope(scopePath, `${method} ${url}`, {
            workspace: process.cwd(),
            targets: [url],
            profile: "api",
            passive: false,
            intrusive: stateChanging,
            external: false,
            override: true,
            maxRps: config.maxRps,
          });
          scope = ensured.scope;
          scopePath = ensured.path;
          deps.setScopePath(scopePath);
          io.write("ok", `${MARK.done} scope | authorization derived from the URL | ${scopePath}`);
        } catch (error) {
          io.write("error", `${MARK.fail} scope | could not derive authorization | ${error instanceof Error ? error.message : String(error)}`);
          return;
        }
      } else {
        try {
          scope = await loadScopeFile(scopePath);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          if (!/not found/i.test(message)) {
            io.write("error", message);
            return;
          }
          try {
            const ensured = await ensurePromptScope(scopePath, `${method} ${url}`, {
              workspace: process.cwd(),
              targets: [url],
              profile: "api",
              passive: false,
              intrusive: ["PUT", "PATCH", "DELETE"].includes(method),
              external: false,
              override: true,
              maxRps: config.maxRps,
            });
            scope = ensured.scope;
            scopePath = ensured.path;
            deps.setScopePath(scopePath);
            io.write("ok", `${MARK.done} scope | new prompt scope created | ${scopePath}`);
          } catch (scopeError) {
            io.write("error", `${MARK.fail} scope | could not create a prompt scope | ${scopeError instanceof Error ? scopeError.message : String(scopeError)}`);
            return;
          }
        }
      }
      const validation = validateScope(scope);
      if (!validation.ok) {
        io.write("error", `scope rejected: ${validation.errors.join(" ")}`);
        return;
      }
      const guard = new ScopeGuard(scope);
      const check = guard.checkUrl(url);
      if (!check.allowed) {
        io.write("error", `scope violation: ${check.reason}`);
        return;
      }
      let port: number;
      try {
        const parsedUrl = new URL(url);
        port = parsedUrl.port ? Number(parsedUrl.port) : parsedUrl.protocol === "https:" ? 443 : 80;
      } catch {
        io.write("error", `invalid URL: ${url}`);
        return;
      }
      const portCheck = guard.checkPort(port);
      if (!portCheck.allowed) {
        io.write("error", `scope violation: ${portCheck.reason}`);
        return;
      }
      if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && !scope.allowActive) {
        io.write("error", `${method} needs allowActive=true in the scope`);
        return;
      }
      if (["PUT", "PATCH", "DELETE"].includes(method) && !scope.allowIntrusive) {
        io.write("error", `${method} needs allowIntrusive=true in the scope`);
        return;
      }
      io.write("dim", `sending ${method} ${url} | scope ${scopePath}`);
      try {
        const client = new HttpClient(guard, {
          timeoutMs: config.timeoutMs,
          maxRps: scope.maxRps ?? config.maxRps,
          userAgent: config.userAgent,
          maxRedirects: 5,
          maxBodyBytes: 500_000,
          keepAlive: false,
        });
        const response = await client.request(url, { method, headers, body, allowCrossOriginRedirects: false });
        const tone: TranscriptKind = response.status >= 500 ? "error" : response.status >= 400 ? "warn" : response.status >= 300 ? "info" : "ok";
        io.write(tone, `${response.status} ${response.statusText} | ${response.elapsedMs}ms | ${response.bodyBytes} bytes`);
        if (response.finalUrl !== url) io.write("dim", `final    ${response.finalUrl}`);
        if (response.redirects.length > 0) io.write("dim", `redirects ${response.redirects.join(" -> ")}`);
        for (const [name, value] of Object.entries(response.headers).sort(([a], [b]) => a.localeCompare(b)).slice(0, 18)) {
          if (name.toLowerCase() === "set-cookie") continue;
          io.write("dim", `${name.padEnd(24)} ${truncate(oneLine(value, 180), 180)}`);
        }
        if (response.headers["set-cookie"]) io.write("dim", "set-cookie               present | value hidden");
        if (response.tls) {
          const tls = response.tls;
          const tlsTone = tls.selfSigned || !tls.hostnameMatch || tls.daysRemaining <= 0 ? "warn" : "dim";
          io.write(tlsTone, `tls                      ${tls.protocol} | ${tls.issuer} | ${tls.daysRemaining}d remaining${tls.selfSigned ? " | self-signed" : ""}${tls.hostnameMatch ? "" : " | hostname mismatch"}`);
        }
        const bodyText = response.body;
        if (!bodyText.trim()) {
          io.write("dim", "(empty body)");
        } else {
          io.write("dim", "body");
          for (const line of bodyText.split(/\r?\n/).slice(0, 12)) {
            io.write("dim", `  ${truncate(line, 260)}`);
          }
          const lineCount = bodyText.split(/\r?\n/).length;
          if (lineCount > 12) io.write("dim", `  ... ${lineCount - 12} more line(s) | ${bodyText.length} chars total`);
        }
      } catch (error) {
        io.write("error", error instanceof Error ? error.message : String(error));
      }
      return;
    }

    case "/install": {
      const tools = await discoverTools();
      const plans = buildInstallPlans(tools);
      const wanted = new Set(parsed.args.map((arg) => arg.toLowerCase()));
      // Tolerate "/install --yes subfinder" by recovering the consumed value.
      for (const key of ["yes", "all"]) {
        const value = parsed.flags.get(key);
        if (typeof value === "string" && value.trim()) wanted.add(value.trim().toLowerCase());
      }
      const all = parsed.flags.has("all");
      const selected = plans.filter(
        (plan) => all || wanted.size === 0 || wanted.has(plan.id.toLowerCase()) || wanted.has(plan.name.toLowerCase()),
      );
      if (selected.length === 0) {
        io.write("info", plans.length === 0 ? "all external adapters are already installed" : "no missing adapter matches that name - /tools lists them");
        return;
      }
      io.write("system", `install | ${selected.length} missing adapter(s) | ${parsed.flags.has("yes") ? "execute" : "dry-run"}`);
      for (const plan of selected) {
        io.write(plan.available ? "dim" : "warn", `  ${plan.name.padEnd(14)} ${plan.display}`);
        if (plan.requiresAdmin) {
          io.write("warn", "    requires admin - run the printed command in an elevated shell");
        } else if (!plan.available) {
          io.write("warn", `    ${plan.note ?? "installer not found on PATH"}`);
        } else if (plan.note) {
          io.write("dim", `    ${plan.note}`);
        }
      }
      if (!parsed.flags.has("yes")) {
        io.write("dim", "dry-run only | /install <tool...> --yes runs user-level installers; admin plans are never executed");
        return;
      }
      if (!all && wanted.size === 0) {
        io.write("warn", "choose tools (/install subfinder nuclei --yes) or add --all to install every missing adapter");
        return;
      }
      const runnable = selected.filter((plan) => plan.available && !plan.requiresAdmin && plan.command);
      if (runnable.length === 0) {
        io.write("warn", "nothing can be installed without elevation - run the printed admin commands yourself");
        return;
      }
      io.write("system", `install | executing ${runnable.length} user-level plan(s)`);
      for (const plan of runnable) {
        io.write("dim", `  installing ${plan.name} | ${plan.manager}...`);
        const result = await runInstallPlan(plan);
        if (result.ok) {
          io.write("ok", `  ${MARK.done} ${plan.name} installed`);
          if (plan.note) io.write("dim", `    ${plan.note}`);
        } else {
          io.write("error", `  ${MARK.fail} ${plan.name} | ${truncate(result.output.split("\n")[0] ?? "failed", 220)}`);
          const rest = result.output.split("\n").slice(1).join("\n").trim();
          if (rest) io.write("dim", `    ${truncate(rest, 300)}`);
        }
      }
      io.write("dim", "run /tools to confirm; restart the shell if PATH changed");
      return;
    }

    case "/scope": {
      if (parsed.args[0] === "init") {
        const path = parsed.args[1] ?? "scope.json";
        const saved = await saveScopeFile(scopeExample(), path);
        deps.setScopePath(saved);
        io.write("ok", `wrote example scope -> ${saved}`);
        io.write("dim", "you can also type /scope <target> to derive a scope from the request");
        return;
      }
      const requested = parsed.args[0];
      const looksLikeFile = requested !== undefined && (/\.(?:json|ya?ml)$/i.test(requested) || /[\\/]/.test(requested));
      let activePath = deps.scopePath;
      if (requested && !looksLikeFile) {
        try {
          const ensured = await ensurePromptScope(activePath, requested, {
            workspace: process.cwd(),
            targets: [requested],
            override: true,
            maxRps: config.maxRps,
          });
          activePath = ensured.path;
          deps.setScopePath(activePath);
          io.write("ok", `${MARK.done} scope | derived from request | authorized by ${ensured.scope.authorizedBy} | ${activePath}`);
        } catch (error) {
          io.write("error", `${MARK.fail} scope | could not derive authorization | ${error instanceof Error ? error.message : String(error)}`);
          return;
        }
      }
      const path = requested && looksLikeFile ? requested : activePath;
      if (requested && looksLikeFile) deps.setScopePath(path);
      let scope: ScopePolicy;
      try {
        scope = await loadScopeFile(path);
      } catch (error) {
        io.write("error", error instanceof Error ? error.message : String(error));
        io.write("dim", "use /scope <target> to derive one from the request");
        return;
      }
      const validation = validateScope(scope);
      io.write(validation.ok ? "ok" : "error", `${path} | ${validation.ok ? "valid" : "invalid"} | ${validation.expired ? "expired" : "in date"}`);
      for (const item of describeScope(scope)) io.write("dim", item);
      for (const issue of validation.errors) io.write("error", issue);
      for (const warning of validation.warnings) io.write("warn", warning);
      const targetArg = parsed.args[1];
      if (targetArg) {
        try {
          const target = new ScopeGuard(scope).resolveTarget(targetArg, "deep");
          io.write("ok", `authorized | ${target.kind} | ${target.display}`);
        } catch (error) {
          io.write("error", error instanceof Error ? error.message : String(error));
        }
      }
      return;
    }

    case "/config": {
      const settings = llmSettings(config);
      const provider = resolveProvider(settings);
      io.write("system", "effective configuration");
      const rows: Array<[string, string]> = [
        ["data dir", config.dataDir],
        ["scope", deps.scopePath],
        ["profile", config.defaultProfile],
        ["max rps", String(config.maxRps)],
        ["timeout", `${config.timeoutMs}ms`],
        ["concurrency", String(config.concurrency)],
        ["provider", `${provider.label} (${provider.id})`],
        ["base url", settings.baseUrl],
        ["model", settings.model],
        ["api key", keyStatus(settings)],
        ["tools off", config.disabledTools.join(", ") || "(none)"],
        ["mcp", Object.keys(config.mcpServers ?? {}).join(", ") || "(none)"],
        ["connectors", config.connectors.map((connector) => connector.id).join(", ") || "(none)"],
      ];
      for (const [label, value] of rows) io.write("dim", `${label.padEnd(12)} ${value}`);
      return;
    }

    case "/clear":
      io.clear();
      return;

    case "/quit":
      io.quit();
      return;

    default:
      io.write("error", `unknown command ${parsed.name} - /help lists everything`);
      return;
  }
}

export function runSummary(handle: RunHandle, failed: string[], reportNames: string[]): Array<[TranscriptKind, string]> {
  const lines: Array<[TranscriptKind, string]> = [];
  const duration =
    handle.record.startedAt && handle.record.finishedAt
      ? formatDuration(Date.parse(handle.record.finishedAt) - Date.parse(handle.record.startedAt))
      : "?";
  const ok = handle.record.status === "completed" && failed.length === 0;
  lines.push([
    ok ? "ok" : "warn",
    `${handle.record.status}${ok ? "" : " with failures"} in ${duration} | ${handle.findings.length} findings`,
  ]);
  lines.push(["dim", countLine(handle.record.counts)]);
  if (failed.length > 0) {
    lines.push(["warn", `${failed.length} probe(s) failed after retries: ${failed.slice(0, 6).join(", ")}`]);
  }
  if (reportNames.length > 0) lines.push(["dim", `reports  ${reportNames.join(" | ")}`]);
  lines.push(["dim", `run      ${handle.record.id}`]);
  return lines;
}
