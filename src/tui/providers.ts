import { join, resolve } from "node:path";
import { findConfigPath, saveConfig } from "../core/config";
import type { ArgusConfig } from "../core/types";

export type LlmSettings = NonNullable<ArgusConfig["llm"]>;

export interface ProviderProfile {
  id: string;
  label: string;
  baseUrl: string;
  apiKeyEnv?: string;
  /** Where to create a key, shown during key entry. */
  keysUrl?: string;
  requiresKey: boolean;
  /** Known real model ids for this provider, used until live discovery answers. */
  models: string[];
}

const DEFAULT_LLM: LlmSettings = {
  enabled: false,
  providerId: "openai",
  baseUrl: "https://api.openai.com/v1",
  model: "gpt-4.1-mini",
  apiKeyEnv: "OPENAI_API_KEY",
};

export const PROVIDERS: ProviderProfile[] = [
  {
    id: "openai",
    label: "OpenAI",
    baseUrl: "https://api.openai.com/v1",
    apiKeyEnv: "OPENAI_API_KEY",
    keysUrl: "https://platform.openai.com/api-keys",
    requiresKey: true,
    models: ["gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano", "o4-mini", "o3", "gpt-4o", "gpt-4o-mini"],
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    baseUrl: "https://openrouter.ai/api/v1",
    apiKeyEnv: "OPENROUTER_API_KEY",
    keysUrl: "https://openrouter.ai/keys",
    requiresKey: true,
    models: [
      "openai/gpt-4.1",
      "openai/gpt-4.1-mini",
      "anthropic/claude-sonnet-4",
      "anthropic/claude-opus-4",
      "google/gemini-2.5-pro",
      "deepseek/deepseek-chat",
      "meta-llama/llama-3.3-70b-instruct",
    ],
  },
  {
    id: "groq",
    label: "Groq",
    baseUrl: "https://api.groq.com/openai/v1",
    apiKeyEnv: "GROQ_API_KEY",
    keysUrl: "https://console.groq.com/keys",
    requiresKey: true,
    models: ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "openai/gpt-oss-120b", "qwen/qwen3-32b"],
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    baseUrl: "https://api.deepseek.com/v1",
    apiKeyEnv: "DEEPSEEK_API_KEY",
    keysUrl: "https://platform.deepseek.com/api_keys",
    requiresKey: true,
    models: ["deepseek-chat", "deepseek-reasoner"],
  },
  {
    id: "together",
    label: "Together AI",
    baseUrl: "https://api.together.xyz/v1",
    apiKeyEnv: "TOGETHER_API_KEY",
    keysUrl: "https://api.together.xyz/settings/api-keys",
    requiresKey: true,
    models: [
      "meta-llama/Llama-3.3-70B-Instruct-Turbo",
      "Qwen/Qwen2.5-72B-Instruct-Turbo",
      "deepseek-ai/DeepSeek-R1",
      "mistralai/Mixtral-8x7B-Instruct-v0.1",
    ],
  },
  {
    id: "mistral",
    label: "Mistral",
    baseUrl: "https://api.mistral.ai/v1",
    apiKeyEnv: "MISTRAL_API_KEY",
    keysUrl: "https://console.mistral.ai/api-keys",
    requiresKey: true,
    models: ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest", "codestral-latest"],
  },
  {
    id: "xai",
    label: "xAI",
    baseUrl: "https://api.x.ai/v1",
    apiKeyEnv: "XAI_API_KEY",
    keysUrl: "https://console.x.ai",
    requiresKey: true,
    models: ["grok-4", "grok-3", "grok-3-mini"],
  },
  {
    id: "nvidia",
    label: "NVIDIA NIM",
    baseUrl: "https://integrate.api.nvidia.com/v1",
    apiKeyEnv: "NVIDIA_API_KEY",
    keysUrl: "https://build.nvidia.com/settings/api-keys",
    requiresKey: true,
    // Verified against https://integrate.api.nvidia.com/v1/models; the live
    // catalog is fetched when this provider is active, so this is only a fallback.
    models: [
      "nvidia/nemotron-3-ultra-550b-a55b",
      "nvidia/nemotron-3-super-120b-a12b",
      "nvidia/nemotron-3.5-lightning-30b-a3b",
      "nvidia/nemotron-3.5-bolt-e4b",
      "nvidia/nemotron-3.5-super-vl-120b-a12b",
      "nvidia/nemotron-nano-3-30b-a3b",
      "nvidia/llama-3.1-nemotron-ultra-253b-v1",
      "nvidia/llama-3.1-nemotron-70b-instruct",
      "nvidia/nemotron-4-340b-instruct",
      "deepseek-ai/deepseek-v4.1-flash",
      "openai/gpt-oss-20b",
      "moonshotai/kimi-k2.6",
      "z-ai/glm-5.3",
      "z-ai/glm-5.3-flash",
      "minimaxai/minimax-m3.1-flash",
      "meta/muse-glimmer-30b",
      "mistralai/mistral-large-2-instruct",
      "google/gemma-3-12b-it",
    ],
  },
  {
    id: "ollama",
    label: "Ollama (local)",
    baseUrl: "http://127.0.0.1:11434/v1",
    requiresKey: false,
    models: ["llama3.2", "llama3.1", "qwen2.5-coder", "deepseek-r1", "gemma3", "mistral"],
  },
  {
    id: "lmstudio",
    label: "LM Studio (local)",
    baseUrl: "http://127.0.0.1:1234/v1",
    requiresKey: false,
    // LM Studio exposes whatever the user has downloaded; only live discovery is meaningful.
    models: [],
  },
  {
    id: "custom",
    label: "Custom endpoint",
    baseUrl: "",
    requiresKey: false,
    models: [],
  },
];

function normalizeUrl(value: string): string {
  return value.trim().replace(/\/+$/, "").toLowerCase();
}

export function llmSettings(config: ArgusConfig): LlmSettings {
  return config.llm ?? DEFAULT_LLM;
}

export function resolveProvider(llm?: LlmSettings): ProviderProfile {
  const settings = llm ?? DEFAULT_LLM;
  const byId = PROVIDERS.find((provider) => provider.id === settings.providerId);
  if (byId && byId.id !== "custom") {
    return { ...byId, baseUrl: settings.baseUrl || byId.baseUrl, apiKeyEnv: settings.apiKeyEnv || byId.apiKeyEnv };
  }
  const byUrl = PROVIDERS.find(
    (provider) => provider.id !== "custom" && provider.baseUrl.length > 0 && normalizeUrl(provider.baseUrl) === normalizeUrl(settings.baseUrl),
  );
  if (byUrl) return byUrl;
  return {
    id: "custom",
    label: "Custom endpoint",
    baseUrl: settings.baseUrl,
    apiKeyEnv: settings.apiKeyEnv,
    requiresKey: false,
    models: [],
  };
}

export function apiKeyPresent(llm?: LlmSettings): boolean {
  if (!llm?.apiKeyEnv) return false;
  return Boolean(process.env[llm.apiKeyEnv]);
}

export function keyStatus(llm?: LlmSettings): string {
  if (!llm?.apiKeyEnv) return "no key required";
  return apiKeyPresent(llm) ? `key from ${llm.apiKeyEnv}` : `missing ${llm.apiKeyEnv}`;
}

export function extractModelIds(payload: unknown): string[] {
  const record = payload && typeof payload === "object" && !Array.isArray(payload) ? (payload as Record<string, unknown>) : undefined;
  const items = Array.isArray(payload) ? payload : (record?.data ?? record?.models);
  if (!Array.isArray(items)) return [];
  const ids = new Set<string>();
  for (const item of items) {
    if (typeof item === "string") {
      if (item.trim()) ids.add(item.trim());
      continue;
    }
    if (item && typeof item === "object") {
      const entry = item as Record<string, unknown>;
      const id = entry.id ?? entry.name ?? entry.model;
      if (typeof id === "string" && id.trim()) ids.add(id.trim());
    }
  }
  return [...ids].sort((a, b) => a.localeCompare(b));
}

/** Lists models through the provider's OpenAI-compatible /models endpoint. */
export async function listProviderModels(
  llm: LlmSettings,
  fetchImpl: typeof fetch = fetch,
): Promise<string[]> {
  const base = llm.baseUrl.trim().replace(/\/+$/, "");
  if (!base) throw new Error("Provider base URL is empty. Set one with /providers url <baseUrl>.");
  const headers: Record<string, string> = { accept: "application/json" };
  const key = llm.apiKeyEnv ? process.env[llm.apiKeyEnv] : undefined;
  if (key) headers.authorization = `Bearer ${key}`;
  const response = await fetchImpl(`${base}/models`, { headers, signal: AbortSignal.timeout(6_000) });
  if (!response.ok) {
    throw new Error(`model listing failed: HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}`);
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("model listing returned invalid JSON");
  }
  const ids = extractModelIds(payload);
  if (ids.length === 0) throw new Error("provider returned no models");
  return ids;
}

export function configPathFor(config: ArgusConfig): string {
  if (process.env.ARGUS_CONFIG) return resolve(process.env.ARGUS_CONFIG);
  return findConfigPath() ?? join(config.dataDir, "argus.config.json");
}

export async function saveLlmSettings(config: ArgusConfig, patch: Partial<LlmSettings>): Promise<ArgusConfig> {
  const llm: LlmSettings = { ...llmSettings(config), ...patch };
  const next: ArgusConfig = { ...config, llm };
  await saveConfig(next, configPathFor(config));
  return next;
}
