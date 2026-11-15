import type { ArgusConfig } from "../core/types";
import {
  apiKeyPresent,
  llmSettings,
  PROVIDERS,
  resolveProvider,
  type LlmSettings,
  type ProviderProfile,
} from "./providers";

export interface LiveModels {
  models?: string[];
  status?: "loading" | "live" | "error";
  note?: string;
}

export interface ProviderGroup {
  provider: ProviderProfile;
  models: string[];
  liveCount: number;
  status: "known" | "loading" | "live" | "error";
  note?: string;
  active: boolean;
  activeModel?: string;
  hasKey: boolean;
  keyLabel: string;
}

export interface CatalogRow {
  kind: "provider" | "model" | "note";
  key: string;
  providerId: string;
  label: string;
  active?: boolean;
  model?: string;
  tone?: "ok" | "faint" | "warn";
}

function orderedProviders(activeId: string): ProviderProfile[] {
  const catalog = PROVIDERS.filter((provider) => provider.id !== "custom" || provider.id === activeId);
  const active = catalog.find((provider) => provider.id === activeId);
  const rest = catalog.filter((provider) => provider.id !== activeId);
  return active ? [active, ...rest] : catalog;
}

export function providerSettings(provider: ProviderProfile, active: LlmSettings): LlmSettings {
  const isActive = provider.id === resolveProvider(active).id;
  return {
    ...active,
    providerId: provider.id,
    baseUrl: isActive ? active.baseUrl || provider.baseUrl : provider.baseUrl,
    apiKeyEnv: provider.apiKeyEnv ?? (isActive ? active.apiKeyEnv : ""),
    model: isActive ? active.model : (provider.models[0] ?? active.model),
  };
}

export function keyLabel(provider: ProviderProfile, active: LlmSettings): string {
  if (!provider.requiresKey) return "no key";
  const envName = provider.id === resolveProvider(active).id ? active.apiKeyEnv || provider.apiKeyEnv : provider.apiKeyEnv;
  if (!envName) return "no key";
  return process.env[envName] ? "key set" : `no ${envName}`;
}

export function buildProviderGroups(
  config: ArgusConfig,
  live: Record<string, LiveModels> = {},
): ProviderGroup[] {
  const settings = llmSettings(config);
  const active = resolveProvider(settings);
  return orderedProviders(active.id).map((provider) => {
    const state = live[provider.id];
    const discovered = state?.models ?? [];
    const curated = [...new Set(provider.models)];
    const curatedSet = new Set(curated);
    const extras = discovered.filter((model) => !curatedSet.has(model)).sort((a, b) => a.localeCompare(b));
    const merged = [...curated, ...extras];
    const isActive = provider.id === active.id;
    if (isActive && settings.model && !merged.includes(settings.model)) merged.unshift(settings.model);
    const mergedProvider: ProviderProfile = isActive
      ? { ...provider, baseUrl: active.baseUrl || provider.baseUrl, apiKeyEnv: active.apiKeyEnv || provider.apiKeyEnv }
      : provider;
    return {
      provider: mergedProvider,
      models: merged,
      liveCount: discovered.length,
      status: state?.status ?? (discovered.length > 0 ? "live" : "known"),
      note: state?.note,
      active: isActive,
      activeModel: isActive ? settings.model : undefined,
      hasKey: provider.requiresKey ? Boolean(process.env[provider.apiKeyEnv ?? ""]) : true,
      keyLabel: keyLabel(provider, settings),
    };
  });
}

export function searchProviders(providers: ProviderProfile[], query: string): ProviderProfile[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return providers;
  const score = (provider: ProviderProfile): number => {
    if (provider.label.toLowerCase() === needle || provider.id.toLowerCase() === needle) return 0;
    if (provider.label.toLowerCase().startsWith(needle) || provider.id.toLowerCase().startsWith(needle)) return 1;
    if (provider.label.toLowerCase().includes(needle) || provider.id.toLowerCase().includes(needle)) return 2;
    if (provider.baseUrl.toLowerCase().includes(needle)) return 3;
    if (provider.models.some((model) => model.toLowerCase().includes(needle))) return 4;
    return Number.POSITIVE_INFINITY;
  };
  return providers
    .map((provider) => ({ provider, score: score(provider) }))
    .filter((entry) => Number.isFinite(entry.score))
    .sort((a, b) => a.score - b.score)
    .map((entry) => entry.provider);
}

/**
 * Flattens provider groups into rows with headers, so the model picker can
 * show "Provider -> its models". Search matches providers and models.
 */
export function buildModelRows(groups: ProviderGroup[], query: string, maxPerGroup = 24): CatalogRow[] {
  const needle = query.trim().toLowerCase();
  const rows: CatalogRow[] = [];
  for (const group of groups) {
    const providerMatches =
      !needle ||
      group.provider.label.toLowerCase().includes(needle) ||
      group.provider.id.toLowerCase().includes(needle);
    const matchingModels = needle ? group.models.filter((model) => model.toLowerCase().includes(needle)) : group.models;
    const models = providerMatches ? group.models : matchingModels;
    if (needle && !providerMatches && models.length === 0) continue;
    rows.push({
      kind: "provider",
      key: `provider:${group.provider.id}`,
      providerId: group.provider.id,
      label: group.provider.label,
      active: group.active,
      tone: group.active ? "ok" : "faint",
    });
    if (models.length === 0) {
      rows.push({
        kind: "note",
        key: `empty:${group.provider.id}`,
        providerId: group.provider.id,
        label: group.status === "loading" ? "discovering live models..." : "no known models - discovery runs live",
        tone: "faint",
      });
      continue;
    }
    for (const model of models.slice(0, maxPerGroup)) {
      rows.push({
        kind: "model",
        key: `model:${group.provider.id}:${model}`,
        providerId: group.provider.id,
        label: model,
        model,
        active: group.active && model === group.activeModel,
        tone: group.active && model === group.activeModel ? "ok" : undefined,
      });
    }
    if (models.length > maxPerGroup) {
      rows.push({
        kind: "note",
        key: `more:${group.provider.id}`,
        providerId: group.provider.id,
        label: `+${models.length - maxPerGroup} more | type to filter`,
        tone: "faint",
      });
    }
  }
  return rows;
}

export function selectableModelRows(rows: CatalogRow[]): CatalogRow[] {
  return rows.filter((row) => row.kind === "model");
}

export function apiKeyForProvider(provider: ProviderProfile, active: LlmSettings): boolean {
  if (!provider.requiresKey) return true;
  const settings = providerSettings(provider, active);
  return apiKeyPresent(settings);
}
