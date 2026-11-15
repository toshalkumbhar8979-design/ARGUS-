import { createChatClient } from "../core/agent";
import { ensureDataDirs, findConfigPath, loadScopeFile } from "../core/config";
import type { ArgusEngine } from "../core/engine";
import { ensureProjectMemory, readProjectMemory } from "../core/memory";
import { validateScope } from "../core/scope";
import type { ArgusConfig } from "../core/types";
import { truncate } from "../core/util";
import { apiKeyPresent, listProviderModels, llmSettings, resolveProvider } from "./providers";

export type DoctorStatus = "ok" | "warn" | "error" | "info";

export interface DoctorCheck {
  id: string;
  label: string;
  status: DoctorStatus;
  detail: string;
}

export interface DoctorReport {
  checks: DoctorCheck[];
  ok: number;
  warnings: number;
  errors: number;
}

export interface DoctorOptions {
  config: ArgusConfig;
  scopePath: string;
  engine: ArgusEngine;
  fetchImpl?: typeof fetch;
  /** Opt-in: send one tiny completion to prove the chat endpoint works. */
  chatTest?: boolean;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Preflight without spending model credits. Reachability is checked through the
 * provider's /models endpoint; the chat endpoint itself is only exercised by a
 * real prompt, which is called out explicitly in the report.
 */
export async function runDoctor(options: DoctorOptions): Promise<DoctorReport> {
  const checks: DoctorCheck[] = [];
  const settings = llmSettings(options.config);
  const provider = resolveProvider(settings);

  checks.push({
    id: "config",
    label: "config",
    status: "info",
    detail: process.env.ARGUS_CONFIG || findConfigPath() || "defaults (no config file)",
  });
  checks.push({
    id: "provider",
    label: "provider",
    status: settings.baseUrl.trim() ? "ok" : "error",
    detail: `${provider.label} | ${truncate(settings.baseUrl || "(no base URL - /providers url <url>)", 80)}`,
  });
  checks.push({
    id: "model",
    label: "model",
    status: settings.model.trim() ? "ok" : "error",
    detail: settings.model.trim() || "no model selected - /models",
  });

  const keyName = settings.apiKeyEnv;
  const keyPresent = apiKeyPresent(settings);
  if (provider.requiresKey && !keyPresent) {
    checks.push({
      id: "key",
      label: "api key",
      status: "error",
      detail: `missing ${keyName ?? "API key"} - run /key ${provider.id}`,
    });
  } else {
    checks.push({
      id: "key",
      label: "api key",
      status: "ok",
      detail: keyName ? (keyPresent ? `${keyName} set` : `${keyName} not set (optional)`) : "not required",
    });

    if (settings.baseUrl.trim()) {
      try {
        const models = await listProviderModels(settings, options.fetchImpl);
        checks.push({
          id: "endpoint",
          label: "endpoint",
          status: "ok",
          detail: `reachable | ${models.length} model(s) listed`,
        });
        if (settings.model.trim() && models.length > 0 && !models.includes(settings.model)) {
          checks.push({
            id: "catalog",
            label: "catalog",
            status: "warn",
            detail: `${settings.model} is not in the live list (the provider may still accept it)`,
          });
        }
      } catch (error) {
        const detail = messageOf(error);
        const local =
          provider.id === "ollama" ||
          provider.id === "lmstudio" ||
          /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])/i.test(settings.baseUrl);
        const auth = /HTTP 401|HTTP 403/.test(detail);
        const noListing = /HTTP 404/.test(detail);
        checks.push({
          id: "endpoint",
          label: "endpoint",
          status: auth ? "error" : local || noListing ? "warn" : "error",
          detail: auth
            ? "the key was rejected - run /key and paste a fresh key"
            : local
              ? `not reachable - start ${provider.label} (${truncate(detail, 100)})`
              : noListing
                ? "does not expose /models; chat may still work"
                : truncate(detail, 180),
        });
      }
    }
  }

  if (options.chatTest) {
    if (!settings.baseUrl.trim() || !settings.model.trim() || (provider.requiresKey && !keyPresent)) {
      checks.push({
        id: "chat",
        label: "chat call",
        status: "warn",
        detail: "skipped - a base URL, model and usable key are required",
      });
    } else {
      try {
        const client = createChatClient(settings);
        const started = Date.now();
        const reply = await client.complete([{ role: "user", content: "Reply with the single word OK." }], {
          signal: AbortSignal.timeout(20_000),
        });
        const elapsed = Date.now() - started;
        checks.push({
          id: "chat",
          label: "chat call",
          status: "ok",
          detail: `endpoint replied | ${truncate(reply.replace(/\s+/g, " ").trim(), 80) || "(empty)"} | ${elapsed}ms`,
        });
      } catch (error) {
        checks.push({
          id: "chat",
          label: "chat call",
          status: "error",
          detail: truncate(messageOf(error), 220),
        });
      }
    }
  } else {
    checks.push({
      id: "chat",
      label: "chat call",
      status: "info",
      detail: "not sent - avoids spending credits; add --chat to test the endpoint",
    });
  }

  try {
    const scope = await loadScopeFile(options.scopePath);
    const validation = validateScope(scope);
    if (!validation.ok) {
      checks.push({
        id: "scope",
        label: "scope",
        status: "error",
        detail: validation.errors.join("; ") || "invalid scope",
      });
    } else {
      checks.push({
        id: "scope",
        label: "scope",
        status: validation.warnings.length > 0 ? "warn" : "ok",
        detail: `${scope.name} | ${scope.authorizationRef} | ${(scope.allow ?? []).length} allow rule(s)${
          validation.warnings.length > 0 ? ` | ${validation.warnings.join("; ")}` : ""
        }`,
      });
    }
  } catch {
    checks.push({
      id: "scope",
      label: "scope",
      status: "warn",
      detail: `no usable scope at ${truncate(options.scopePath, 70)} - scanning disabled; /scope init`,
    });
  }

  if (process.env.ARGUS_MEMORY === "off") {
    checks.push({ id: "memory", label: "memory", status: "info", detail: "disabled by ARGUS_MEMORY=off" });
  } else {
    try {
      const path = await ensureProjectMemory();
      const content = await readProjectMemory();
      const entries = (content.match(/^### /gm) ?? []).length;
      checks.push({
        id: "memory",
        label: "memory",
        status: "ok",
        detail: `${truncate(path, 80)} | ${entries} entr${entries === 1 ? "y" : "ies"} | ${content.length} bytes`,
      });
    } catch (error) {
      checks.push({
        id: "memory",
        label: "memory",
        status: "warn",
        detail: `unavailable | ${truncate(messageOf(error), 120)}`,
      });
    }
  }

  try {
    const dirs = await ensureDataDirs(options.config.dataDir);
    checks.push({ id: "store", label: "store", status: "ok", detail: dirs.configDir });
  } catch (error) {
    checks.push({
      id: "store",
      label: "store",
      status: "error",
      detail: `cannot use ${options.config.dataDir} | ${truncate(messageOf(error), 120)}`,
    });
  }

  try {
    const tools = await options.engine.tools();
    const installed = tools.filter((tool) => tool.installed);
    const missing = tools
      .filter((tool) => !tool.installed)
      .slice(0, 4)
      .map((tool) => tool.name);
    checks.push({
      id: "tools",
      label: "adapters",
      status: tools.length === 0 ? "warn" : installed.length > 0 ? "ok" : "warn",
      detail:
        tools.length === 0
          ? "no external adapters discovered"
          : `${installed.length}/${tools.length} installed${missing.length > 0 ? ` | missing ${missing.join(", ")}` : ""}`,
    });
  } catch (error) {
    checks.push({
      id: "tools",
      label: "adapters",
      status: "warn",
      detail: truncate(messageOf(error), 140),
    });
  }

  checks.push({
    id: "web",
    label: "web research",
    status: process.env.ARGUS_SEARCH_URL ? "ok" : "info",
    detail: process.env.ARGUS_SEARCH_URL
      ? `custom search | ${truncate(process.env.ARGUS_SEARCH_URL, 70)}`
      : "DuckDuckGo (no key) | /web <query> or agent web_search; set ARGUS_SEARCH_URL for SearXNG",
  });

  const servers = Object.keys(options.config.mcpServers ?? {});
  checks.push({
    id: "mcp",
    label: "mcp",
    status: "info",
    detail: servers.length > 0 ? `${servers.length} configured | ${servers.join(", ")}` : "none configured",
  });

  return {
    checks,
    ok: checks.filter((check) => check.status === "ok").length,
    warnings: checks.filter((check) => check.status === "warn").length,
    errors: checks.filter((check) => check.status === "error").length,
  };
}
