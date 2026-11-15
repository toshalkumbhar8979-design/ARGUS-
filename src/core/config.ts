import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { ArgusConfig, ProfileId, ScopePolicy } from "./types";
import { expandHome } from "./util";

export const CONFIG_FILENAME = "argus.config.json";

export function userDataDir(): string {
  return resolve(process.env.ARGUS_DATA_DIR || join(homedir(), ".argus"));
}

export function defaultConfig(): ArgusConfig {
  return {
    dataDir: userDataDir(),
    defaultProfile: "web",
    maxRps: 40,
    timeoutMs: 10_000,
    concurrency: 50,
    userAgent: "Argus/0.1 (authorized security testing; +https://github.com/anomalyco/opencode)",
    allowExternalIntel: false,
    maxFileScanBytes: 2_000_000,
    mcpServers: {},
    connectors: [],
    disabledTools: [],
    llm: {
      enabled: false,
      providerId: "openai",
      baseUrl: "https://api.openai.com/v1",
      model: "gpt-4.1-mini",
      apiKeyEnv: "OPENAI_API_KEY",
    },
  };
}

export function configSearchPaths(cwd = process.cwd()): string[] {
  const paths: string[] = [];
  if (process.env.ARGUS_CONFIG) paths.push(resolve(process.env.ARGUS_CONFIG));
  paths.push(resolve(cwd, CONFIG_FILENAME));
  paths.push(join(userDataDir(), CONFIG_FILENAME));
  return [...new Set(paths)];
}

export function findConfigPath(cwd = process.cwd()): string | undefined {
  return configSearchPaths(cwd).find((path) => existsSync(path));
}

export async function loadConfig(cwd = process.cwd()): Promise<ArgusConfig> {
  const base = defaultConfig();
  const path = findConfigPath(cwd);
  if (!path) return base;
  let parsed: Partial<ArgusConfig>;
  try {
    parsed = JSON.parse(await readFile(path, "utf8")) as Partial<ArgusConfig>;
  } catch (error) {
    throw new Error(`Cannot read config at ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return normalizeConfig({ ...base, ...parsed, dataDir: parsed.dataDir ? expandHome(parsed.dataDir) : base.dataDir });
}

export function normalizeConfig(config: ArgusConfig): ArgusConfig {
  const dataDir = resolve(expandHome(config.dataDir || userDataDir()));
  return {
    ...config,
    dataDir,
    defaultProfile: isProfile(config.defaultProfile) ? config.defaultProfile : "web",
    maxRps: clampNumber(config.maxRps, 1, 1000, 40),
    timeoutMs: clampNumber(config.timeoutMs, 500, 120_000, 10_000),
    concurrency: clampNumber(config.concurrency, 1, 500, 50),
    maxFileScanBytes: clampNumber(config.maxFileScanBytes, 10_000, 50_000_000, 2_000_000),
    mcpServers: config.mcpServers ?? {},
    connectors: config.connectors ?? [],
    disabledTools: config.disabledTools ?? [],
    userAgent: config.userAgent || defaultConfig().userAgent,
  };
}

export async function saveConfig(config: ArgusConfig, path?: string): Promise<string> {
  const target = path ? resolve(expandHome(path)) : configSearchPaths()[0]!;
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  return target;
}

export async function loadScopeFile(path: string): Promise<ScopePolicy> {
  const resolved = resolve(expandHome(path));
  let raw: string;
  try {
    raw = await readFile(resolved, "utf8");
  } catch {
    throw new Error(`Scope file not found: ${resolved}`);
  }
  let parsed: ScopePolicy;
  try {
    parsed = JSON.parse(raw) as ScopePolicy;
  } catch (error) {
    throw new Error(`Scope file is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  return parsed;
}

export async function saveScopeFile(scope: ScopePolicy, path: string): Promise<string> {
  const resolved = resolve(expandHome(path));
  await mkdir(dirname(resolved), { recursive: true });
  await writeFile(resolved, `${JSON.stringify(scope, null, 2)}\n`, "utf8");
  return resolved;
}

export async function ensureDataDirs(dataDir: string): Promise<{ runsDir: string; configDir: string }> {
  const resolved = resolve(expandHome(dataDir));
  const runsDir = join(resolved, "runs");
  await mkdir(runsDir, { recursive: true });
  await mkdir(join(resolved, "exports"), { recursive: true });
  return { runsDir, configDir: resolved };
}

export function scopeExample(): ScopePolicy {
  return {
    version: 1,
    name: "Example authorized assessment",
    authorizedBy: "Security Team",
    authorizationRef: "TICKET-SEC-0001 / signed rules of engagement",
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    allow: ["https://example.com", "*.example.com", "127.0.0.1"],
    deny: ["https://example.com/account/delete"],
    maxRps: 20,
    allowedPorts: [80, 443, 8080, 8443],
    allowActive: true,
    allowIntrusive: false,
    allowExternal: false,
  };
}

function isProfile(value: string): value is ProfileId {
  return ["quick", "recon", "web", "api", "network", "deep", "repo"].includes(value);
}

function clampNumber(value: number, min: number, max: number, fallback: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.round(value)));
}
