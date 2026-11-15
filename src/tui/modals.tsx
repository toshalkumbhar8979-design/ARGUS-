import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useKeyboard, usePaste, useTerminalDimensions } from "@opentui/react";
import { McpManager } from "../core/mcp";
import type { AgentApprovalRequest } from "../core/agent";
import type { RunStore } from "../core/store";
import type { ArgusConfig, DependencyGraphSnapshot, Finding } from "../core/types";
import { truncate } from "../core/util";
import {
  buildModelRows,
  buildProviderGroups,
  providerSettings,
  searchProviders,
  selectableModelRows,
  type LiveModels,
} from "./catalog";
import { readClipboardText } from "./clipboard";
import { saveCredential } from "./credentials";
import { buildDashboard, type DashTone, type DashboardPhase } from "./dashboard";
import {
  apiKeyPresent,
  listProviderModels,
  llmSettings,
  PROVIDERS,
  resolveProvider,
  type ProviderProfile,
} from "./providers";
import { previewRows, previewSubtitle, previewTitle, type PreviewPayload, type PreviewTone } from "./preview";
import { windowed } from "./state";
import { GLYPH, palette, ruleLine, severityColor, severityTag, spinnerFrame } from "./theme";

/**
 * One panel chrome for every modal: title row, hairline, body, hairline, key
 * hints. Consistent enough that every dialog reads as the same surface.
 */
function ModalFrame({
  title,
  subtitle,
  footer,
  children,
  wide,
  onClose,
  onScroll,
}: {
  title: string;
  subtitle?: string;
  footer: string;
  children: ReactNode;
  wide?: boolean;
  onClose?: () => void;
  onScroll?: (direction: "up" | "down") => void;
}) {
  const { width } = useTerminalDimensions();
  const inner = Math.max(24, Math.floor(width * (wide ? 0.92 : 0.84)) - 6);
  // The title takes only what it needs; the subtitle gets the rest of the row.
  const shownTitle = truncate(title, Math.max(12, Math.floor(inner * 0.45)));
  const subtitleRoom = Math.max(10, inner - shownTitle.length - (onClose ? 19 : 4));
  return (
    <box
      position="absolute"
      left={wide ? "4%" : "8%"}
      right={wide ? "4%" : "8%"}
      top={wide ? "6%" : "12%"}
      bottom={wide ? "6%" : "14%"}
    >
      <box
        flexDirection="column"
        flexGrow={1}
        border
        borderStyle="rounded"
        borderColor={palette.border}
        backgroundColor={palette.panel}
        paddingLeft={1}
        paddingRight={1}
      >
        <box flexDirection="row" height={1} flexShrink={0}>
          <text wrapMode="none">
            <span fg={palette.accent}>
              <strong>{GLYPH.brand} {shownTitle}</strong>
            </span>
            {subtitle ? <span fg={palette.faint}>{`  ${truncate(subtitle, subtitleRoom)}`}</span> : null}
          </text>
          <box flexGrow={1} />
          {onClose ? (
            <text fg={palette.faint} onMouseDown={onClose} wrapMode="none">
              esc to close
            </text>
          ) : null}
        </box>
        <box height={1} flexShrink={0}>
          <text fg={palette.rule} wrapMode="none">{ruleLine(inner)}</text>
        </box>
        <box
          flexDirection="column"
          flexGrow={1}
          paddingTop={1}
          overflow="hidden"
          onMouseScroll={(event) => {
            const direction = event.scroll?.direction;
            if (!onScroll || (direction !== "up" && direction !== "down")) return;
            event.stopPropagation();
            onScroll(direction);
          }}
        >
          {children}
        </box>
        <box height={1} flexShrink={0}>
          <text fg={palette.rule} wrapMode="none">{ruleLine(inner)}</text>
        </box>
        <box height={1} flexShrink={0}>
          <text fg={palette.faint} wrapMode="none">{truncate(footer, inner)}</text>
        </box>
      </box>
    </box>
  );
}

export function ApprovalModal({
  request,
  onAllow,
  onAlways,
  onDeny,
}: {
  request: AgentApprovalRequest;
  onAllow: () => void;
  onAlways: () => void;
  onDeny: () => void;
}) {
  const risk = request.risk ?? "medium";
  const riskColor = risk === "high" ? palette.error : risk === "low" ? palette.ok : palette.warn;

  useKeyboard((key) => {
    if (key.ctrl || key.meta) return;
    if (key.name === "escape" || key.name === "n") {
      key.preventDefault();
      onDeny();
      return;
    }
    if (key.name === "a") {
      key.preventDefault();
      onAlways();
      return;
    }
    if (key.name === "y" || key.name === "return" || key.name === "enter") {
      key.preventDefault();
      onAllow();
    }
  });

  return (
    <ModalFrame
      title="Approval required"
      subtitle={request.title}
      footer="y allow once  ·  a allow this action for the run (never high risk)  ·  n deny  ·  esc deny"
      onClose={onDeny}
    >
      <box flexDirection="column" gap={1}>
        <text wrapMode="none">
          <span fg={palette.chipInk} bg={riskColor}>
            <strong>{`${risk.toUpperCase()} RISK`}</strong>
          </span>
          <span fg={palette.muted}>{`  ${request.action ?? request.kind}`}</span>
        </text>
        <text fg={palette.strong} wrapMode="word">{request.detail}</text>
        {request.command ? (
          <box
            flexDirection="column"
            border
            borderStyle="rounded"
            borderColor={palette.rule}
            backgroundColor={palette.panelSoft}
            paddingLeft={1}
            paddingRight={1}
          >
            <text wrapMode="word">
              <span fg={palette.accent}>
                <strong>{`${GLYPH.shell} `}</strong>
              </span>
              <span fg={palette.text}>{request.command}</span>
            </text>
          </box>
        ) : null}
        {request.path ? <text fg={palette.faint}>path  {request.path}</text> : null}
        <text fg={palette.faint}>no response means deny</text>
      </box>
    </ModalFrame>
  );
}

export interface AuthorizeRequest {
  /** The sentence that asked for an attack, kept for the record. */
  prompt: string;
  /** Targets the approval covers, straight from the active scope. */
  targets: string[];
  scopePath: string;
}

/**
 * Explicit consent before active, state-changing testing. Approving writes the
 * wider scope to disk; declining keeps the read-only scope untouched. Nothing
 * is sent until the operator answers.
 */
export function AuthorizeModal({
  request,
  onApprove,
  onReadOnly,
  onCancel,
}: {
  request: AuthorizeRequest;
  onApprove: () => void;
  onReadOnly: () => void;
  onCancel: () => void;
}) {
  useKeyboard((key) => {
    if (key.ctrl || key.meta) return;
    if (key.name === "escape") {
      key.preventDefault();
      onCancel();
      return;
    }
    if (key.name === "y" || key.name === "return" || key.name === "enter") {
      key.preventDefault();
      onApprove();
      return;
    }
    if (key.name === "r") {
      key.preventDefault();
      onReadOnly();
    }
  });

  return (
    <ModalFrame
      title="Authorize intrusive testing"
      subtitle="this is the permission record for the assessment"
      footer="y authorize intrusive  ·  r read-only pass  ·  esc cancel"
      onClose={onCancel}
    >
      <box flexDirection="column" gap={1}>
        <text wrapMode="none">
          <span fg={palette.chipInk} bg={palette.high}>
            <strong>INTRUSIVE</strong>
          </span>
          <span fg={palette.muted}>{"  state-changing checks, payloads, POST/PUT/DELETE, deeper probes"}</span>
        </text>
        <text fg={palette.strong} wrapMode="word">{`"${truncate(request.prompt, 160)}"`}</text>
        <text fg={palette.faint}>targets covered by this approval</text>
        {request.targets.slice(0, 6).map((target) => (
          <text key={target} fg={palette.text} wrapMode="none">
            <span fg={palette.accent}>{`${GLYPH.step} `}</span>
            {truncate(target, 96)}
          </text>
        ))}
        {request.targets.length > 6 ? (
          <text fg={palette.faint}>{`  +${request.targets.length - 6} more`}</text>
        ) : null}
        <text fg={palette.faint} wrapMode="word">
          {`approving writes allowActive + allowIntrusive and appends INTERACTIVE-APPROVAL <timestamp> to ${request.scopePath}`}
        </text>
        <text fg={palette.faint} wrapMode="word">
          r runs the same pass read-only: no state-changing request is sent and the scope file is untouched.
        </text>
      </box>
    </ModalFrame>
  );
}

function KeyableRow({
  selected,
  onMouseDown,
  children,
}: {
  selected: boolean;
  onMouseDown?: () => void;
  children: ReactNode;
}) {
  return (
    <box
      flexDirection="column"
      backgroundColor={selected ? palette.selection : undefined}
      paddingRight={1}
      onMouseDown={onMouseDown}
    >
      {children}
    </box>
  );
}

function SearchRow({
  value,
  onInput,
  focused,
  placeholder,
  onSubmit,
}: {
  value: string;
  onInput: (value: string) => void;
  focused: boolean;
  placeholder: string;
  onSubmit?: () => void;
}) {
  return (
    <box flexDirection="row" paddingLeft={1} paddingRight={1} height={1} flexShrink={0}>
      <text fg={palette.faint}>search  </text>
      <input
        value={value}
        onInput={onInput}
        focused={focused}
        placeholder={placeholder}
        flexGrow={1}
        onSubmit={onSubmit}
      />
    </box>
  );
}

function statusColor(tone: "ok" | "faint" | "warn" | "error"): string {
  if (tone === "ok") return palette.ok;
  if (tone === "warn") return palette.warn;
  if (tone === "error") return palette.error;
  return palette.faint;
}

export function ProvidersModal({
  config,
  onSelect,
  onClose,
  onHint,
}: {
  config: ArgusConfig;
  onSelect: (provider: ProviderProfile) => void;
  onClose: () => void;
  onHint: (text: string) => void;
}) {
  const settings = llmSettings(config);
  const active = resolveProvider(settings);
  const [index, setIndex] = useState(() => Math.max(0, PROVIDERS.findIndex((provider) => provider.id === active.id)));
  const { height, width } = useTerminalDimensions();
  const visible = windowed(PROVIDERS, index, Math.max(3, height - 14));

  function choose(provider: ProviderProfile) {
    if (provider.id === "custom") {
      onHint("custom endpoints need a URL: close this and run /providers url https://host/v1");
      onClose();
      return;
    }
    onSelect(provider);
  }

  useKeyboard((key) => {
    if (key.ctrl || key.meta) return;
    if (key.name === "escape") {
      key.preventDefault();
      onClose();
      return;
    }
    if (key.name === "down" || key.name === "j") {
      key.preventDefault();
      setIndex((value) => Math.min(PROVIDERS.length - 1, value + 1));
      return;
    }
    if (key.name === "up" || key.name === "k") {
      key.preventDefault();
      setIndex((value) => Math.max(0, value - 1));
      return;
    }
    if (key.name === "return" || key.name === "enter") {
      key.preventDefault();
      const provider = PROVIDERS[index];
      if (provider) choose(provider);
    }
  });

  return (
    <ModalFrame
      title="Providers"
      subtitle="OpenAI-compatible endpoints · enter selects · /models picks a model"
      footer="↑↓ select  ·  enter use  ·  wheel scrolls  ·  esc close"
      onClose={onClose}
      onScroll={(direction) =>
        setIndex((value) => Math.min(PROVIDERS.length - 1, Math.max(0, value + (direction === "up" ? -1 : 1))))
      }
    >
      {visible.items.map((provider, offset) => {
        const absolute = visible.offset + offset;
        const current = provider.id === active.id;
        const key = !provider.requiresKey
          ? "no key needed"
          : process.env[provider.apiKeyEnv ?? ""]
            ? "key set"
            : `no ${provider.apiKeyEnv ?? "key"}`;
        return (
          <KeyableRow
            key={provider.id}
            selected={absolute === index}
            onMouseDown={() => {
              setIndex(absolute);
              choose(provider);
            }}
          >
            <text wrapMode="none">
              <span fg={absolute === index ? palette.accent : palette.ghost}>
                {absolute === index ? `${GLYPH.bar} ` : "  "}
              </span>
              <span fg={current ? palette.ok : palette.ghost}>{current ? `${GLYPH.done} ` : "  "}</span>
              <span fg={palette.text}>{provider.label.padEnd(18)}</span>
              <span fg={palette.faint}>{truncate(provider.baseUrl || "(set a custom url)", Math.max(18, width - 60))}</span>
              <span fg={palette.faint}>
                {`  ${provider.models.length > 0 ? `${provider.models.length} models` : "live only"} · ${key}`}
              </span>
            </text>
          </KeyableRow>
        );
      })}
      <text fg={palette.faint}>model catalog for every provider is grouped in /models</text>
    </ModalFrame>
  );
}

export function ModelsModal({
  config,
  onSelect,
  onClose,
}: {
  config: ArgusConfig;
  onSelect: (provider: ProviderProfile, model: string) => void;
  onClose: () => void;
}) {
  const settings = llmSettings(config);
  const active = resolveProvider(settings);
  const [query, setQuery] = useState("");
  const [live, setLive] = useState<Record<string, LiveModels>>({});
  const [index, setIndex] = useState(0);
  const initialized = useRef(false);
  const firstQuery = useRef(true);
  const { height } = useTerminalDimensions();
  const rowsHeight = Math.max(4, Math.floor(height * 0.74) - 10);

  useEffect(() => {
    let cancelled = false;
    // Only the active endpoint is queried. Optional local servers should not
    // delay the picker when they are not running.
    if (active.requiresKey && !apiKeyPresent(settings)) {
      setLive((previous) => ({
        ...previous,
        [active.id]: {
          models: previous[active.id]?.models ?? [],
          status: "error",
          note: `add ${settings.apiKeyEnv ?? "an api key"} to discover live models`,
        },
      }));
      return () => {
        cancelled = true;
      };
    }
    setLive((previous) => ({ ...previous, [active.id]: { ...previous[active.id], status: "loading" } }));
    listProviderModels(providerSettings(active, settings))
      .then((models) => {
        if (cancelled) return;
        setLive((previous) => ({ ...previous, [active.id]: { models, status: "live" } }));
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        const detail = error instanceof Error ? error.message : String(error);
        setLive((previous) => ({ ...previous, [active.id]: { ...previous[active.id], status: "error", note: detail } }));
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings.baseUrl, settings.apiKeyEnv, settings.model, active.id]);

  const groups = useMemo(() => buildProviderGroups(config, live), [config, live]);
  const rows = useMemo(() => buildModelRows(groups, query, 24), [groups, query]);
  const selectable = useMemo(() => selectableModelRows(rows), [rows]);
  const clamped = Math.min(index, Math.max(0, selectable.length - 1));
  const selected = selectable[clamped];
  const selectedRowIndex = rows.findIndex((row) => row.key === selected?.key);
  const visible = windowed(rows, selectedRowIndex < 0 ? 0 : selectedRowIndex, rowsHeight);
  const liveCount = Object.values(live).filter((state) => state.status === "live").length;
  const loading = Object.values(live).some((state) => state.status === "loading");

  useEffect(() => {
    if (initialized.current || selectable.length === 0) return;
    initialized.current = true;
    const position = selectable.findIndex((row) => row.providerId === active.id && row.model === settings.model);
    if (position >= 0) setIndex(position);
  }, [selectable, active.id, settings.model]);

  useEffect(() => {
    if (firstQuery.current) {
      firstQuery.current = false;
      return;
    }
    setIndex(0);
  }, [query]);

  useKeyboard((key) => {
    if (key.ctrl || key.meta) return;
    if (key.name === "escape") {
      key.preventDefault();
      onClose();
      return;
    }
    if (key.name === "down") {
      key.preventDefault();
      key.stopPropagation();
      setIndex(Math.min(Math.max(0, selectable.length - 1), clamped + 1));
      return;
    }
    if (key.name === "up") {
      key.preventDefault();
      key.stopPropagation();
      setIndex(Math.max(0, clamped - 1));
      return;
    }
    if (key.name === "tab") {
      key.preventDefault();
      key.stopPropagation();
      setIndex((value) => (selectable.length === 0 ? 0 : (value + 1) % selectable.length));
      return;
    }
    if (key.name === "return" || key.name === "enter") {
      key.preventDefault();
      const picked = selectable[clamped];
      if (!picked?.model) return;
      const group = groups.find((entry) => entry.provider.id === picked.providerId);
      if (group) onSelect(group.provider, picked.model);
    }
  });

  return (
    <ModalFrame
      title="Models"
      subtitle={`${active.label} active · ${groups.length} providers · ${liveCount} discovered live${loading ? " · discovering..." : ""}`}
      footer="↑↓ select  ·  tab next  ·  enter use  ·  wheel scrolls  ·  type to search  ·  esc close"
      onClose={onClose}
      onScroll={(direction) =>
        setIndex((value) =>
          Math.min(Math.max(0, selectable.length - 1), Math.max(0, value + (direction === "up" ? -1 : 1))),
        )
      }
    >
      <SearchRow value={query} onInput={setQuery} focused placeholder="filter providers or models" />
      {selected ? (
        <text fg={palette.faint} wrapMode="none">
          {truncate(
            `${groups.find((group) => group.provider.id === selected.providerId)?.provider.label ?? selected.providerId} -> ${selected.model}${selected.active ? " | active" : ""}`,
            92,
          )}
        </text>
      ) : (
        <text fg={palette.faint} wrapMode="none">{query ? `no model matches "${query}"` : "no models available"}</text>
      )}
      <box flexDirection="column" flexGrow={1}>
        {visible.items.map((row) => {
          if (row.kind === "provider") {
            const group = groups.find((entry) => entry.provider.id === row.providerId);
            const suffix =
              group?.status === "live"
                ? `live ${group.liveCount}`
                : group?.status === "loading"
                  ? "discovering..."
                  : group?.status === "error"
                    ? "live discovery failed"
                    : "known catalog";
            return (
              <box key={row.key} height={1} flexShrink={0}>
                <text wrapMode="none">
                  <span fg={palette.accent}>{`${GLYPH.bar} `}</span>
                  <span fg={row.active ? palette.ok : palette.strong}>
                    {row.active ? `${row.label}${GLYPH.done}` : row.label}
                  </span>
                  <span fg={palette.faint}>{`  ${suffix} · ${group?.keyLabel ?? ""}`}</span>
                </text>
              </box>
            );
          }
          if (row.kind === "note") {
            return (
            <box key={row.key} height={1} flexShrink={0}>
              <text fg={palette.faint} wrapMode="none">{`    ${GLYPH.step} ${row.label}`}</text>
            </box>
            );
          }
          const isSelected = row.key === selected?.key;
          return (
            <box
              key={row.key}
              height={1}
              flexShrink={0}
              backgroundColor={isSelected ? palette.selection : undefined}
              paddingRight={1}
              onMouseDown={() => {
                const pick = selectable.findIndex((entry) => entry.key === row.key);
                if (pick >= 0) setIndex(pick);
                const group = groups.find((entry) => entry.provider.id === row.providerId);
                if (group && row.model) onSelect(group.provider, row.model);
              }}
            >
              <text wrapMode="none">
                <span fg={isSelected ? palette.accent : palette.ghost}>{isSelected ? `${GLYPH.bar} ` : "  "}</span>
                <span fg={row.active ? palette.ok : palette.ghost}>{row.active ? `${GLYPH.done} ` : "  "}</span>
                <span fg={palette.text}>{truncate(row.label, 90)}</span>
              </text>
            </box>
          );
        })}
      </box>
    </ModalFrame>
  );
}

interface ConnectRow {
  id: string;
  kind: "provider" | "mcp";
  label: string;
  detail: string;
  provider?: ProviderProfile;
  server?: string;
}

export function ConnectModal({
  config,
  onApply,
  onClose,
  onHint,
  initialKeyFor,
  startInKey = false,
  readClipboard = readClipboardText,
}: {
  config: ArgusConfig;
  onApply: (provider: ProviderProfile) => void;
  onClose: () => void;
  onHint: (text: string, tone?: "ok" | "warn" | "error") => void;
  /** Provider id or name to open in key-entry mode (used by /key). */
  initialKeyFor?: string;
  /** Opens the selected provider (or active provider) directly in key entry. */
  startInKey?: boolean;
  /** Overridable for tests; defaults to the platform clipboard. */
  readClipboard?: () => Promise<string | undefined>;
}) {
  const settings = llmSettings(config);
  const active = resolveProvider(settings);
  const managerRef = useRef<McpManager | null>(null);
  if (!managerRef.current) managerRef.current = new McpManager();
  const manager = managerRef.current;

  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const [mode, setMode] = useState<"list" | "detail">("list");
  const [detail, setDetail] = useState<ProviderProfile | undefined>();
  const [keyMode, setKeyMode] = useState(false);
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ text: string; tone: "ok" | "warn" | "error" | "faint" }>();
  const [discovered, setDiscovered] = useState<string[]>([]);
  const [statuses, setStatuses] = useState<Record<string, { text: string; tone: "ok" | "error" | "pending" }>>({});
  const openingRef = useRef(false);
  const applyingRef = useRef(false);
  const connectingRef = useRef(false);
  const savingRef = useRef(false);
  const bootedRef = useRef(false);
  const { height, width } = useTerminalDimensions();
  const rowsHeight = Math.max(4, Math.floor(height * 0.74) - 11);

  useEffect(() => {
    return () => {
      void manager.disconnect();
    };
  }, [manager]);

  const availableProviders = PROVIDERS.filter((provider) => provider.id !== "custom" || provider.id === active.id);
  const orderedProviders = [
    ...availableProviders.filter((provider) => provider.id === active.id),
    ...availableProviders.filter((provider) => provider.id !== active.id),
  ];
  const providerRows: ConnectRow[] = searchProviders(orderedProviders, query).map((provider) => {
    const isActive = provider.id === active.id;
    const envName = envFor(provider);
    const key = !provider.requiresKey
      ? "no key needed"
      : envName && process.env[envName]
        ? "key set"
        : `needs ${envName ?? "a key"} | enter to add`;
    const models = provider.models.slice(0, 4).join(", ");
    return {
      id: `provider:${provider.id}`,
      kind: "provider" as const,
      label: `provider | ${provider.label}${isActive ? " (active)" : ""}`,
      detail: `${provider.models.length > 0 ? `${provider.models.length} models | ${models}` : "models discovered live"} | ${key}`,
      provider,
    };
  });
  const managerText = query.trim().toLowerCase();
  const mcpRows: ConnectRow[] = Object.entries(config.mcpServers ?? {})
    .filter(([name, server]) => {
      if (!managerText) return true;
      return (
        name.toLowerCase().includes(managerText) ||
        (server.url ?? "").toLowerCase().includes(managerText) ||
        [server.command, ...(server.args ?? [])].filter(Boolean).join(" ").toLowerCase().includes(managerText)
      );
    })
    .map(([name, server]) => ({
      id: `mcp:${name}`,
      kind: "mcp" as const,
      label: `mcp | ${name}`,
      detail: server.url ?? [server.command, ...(server.args ?? [])].filter(Boolean).join(" "),
      server: name,
    }));
  const rows: ConnectRow[] = [...providerRows, ...mcpRows];
  const clamped = Math.min(index, Math.max(0, rows.length - 1));
  const selectedRow = rows[clamped];
  const visible = windowed(rows, clamped, rowsHeight);

  function envFor(provider: ProviderProfile): string | undefined {
    return provider.id === active.id ? settings.apiKeyEnv || provider.apiKeyEnv : provider.apiKeyEnv;
  }

  function normalizeProvider(provider: ProviderProfile): ProviderProfile {
    return provider.id === active.id
      ? { ...provider, baseUrl: settings.baseUrl || provider.baseUrl, apiKeyEnv: settings.apiKeyEnv || provider.apiKeyEnv }
      : provider;
  }

  useEffect(() => {
    if (!startInKey || bootedRef.current) return;
    bootedRef.current = true;
    const wanted = initialKeyFor?.trim().toLowerCase();
    const chosen = wanted
      ? PROVIDERS.find(
          (provider) =>
            provider.id === wanted ||
            provider.label.toLowerCase() === wanted ||
            provider.label.toLowerCase().includes(wanted),
        )
      : active;
    if (!chosen) {
      setQuery(wanted ?? "");
      setNotice({ text: `unknown provider "${wanted}" - pick one below`, tone: "warn" });
      return;
    }
    openProvider(chosen, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function verify(provider: ProviderProfile) {
    setBusy(true);
    setDiscovered([]);
    setNotice({ text: "verifying endpoint...", tone: "faint" });
    try {
      const models = await listProviderModels(providerSettings(provider, settings));
      setDiscovered(models);
      setNotice({ text: `reachable | ${models.length} models`, tone: "ok" });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setNotice({ text: message, tone: "error" });
    } finally {
      setBusy(false);
    }
  }

  function openProvider(provider: ProviderProfile, keyEntry = false) {
    if (openingRef.current) return;
    openingRef.current = true;
    const normalized = normalizeProvider(provider);
    const envName = envFor(normalized);
    const hasKey = Boolean(envName && process.env[envName]);
    const wantsKey = Boolean(envName) && (keyEntry || (normalized.requiresKey && !hasKey));
    setDetail(normalized);
    setMode("detail");
    setDiscovered([]);
    setSecret("");
    setKeyMode(wantsKey);
    setNotice(
      !envName && keyEntry
        ? { text: "no key variable for this endpoint - set one with /providers key ENV_VAR", tone: "warn" }
        : wantsKey
          ? { text: `paste your ${envName} key - ctrl+v or terminal paste, then enter saves and activates`, tone: "faint" }
          : hasKey
            ? { text: `key set from ${envName} | enter uses this provider`, tone: "ok" }
            : { text: "enter uses this provider | k adds a key", tone: "faint" },
    );
    setTimeout(() => {
      openingRef.current = false;
    }, 0);
  }

  function chooseProvider(provider: ProviderProfile) {
    if (applyingRef.current) return;
    const envName = envFor(provider);
    if (provider.requiresKey && !(envName && process.env[envName])) {
      openProvider(provider, true);
      return;
    }
    applyingRef.current = true;
    onApply(normalizeProvider(provider));
    setTimeout(() => {
      applyingRef.current = false;
    }, 0);
  }

  function chooseSelected() {
    const row = rows[clamped];
    if (!row) return;
    if (row.kind === "provider" && row.provider) chooseProvider(row.provider);
    else if (row.kind === "mcp") void connectMcp(row);
  }

  async function connectMcp(row: ConnectRow) {
    const server = row.server ? config.mcpServers?.[row.server] : undefined;
    if (!row.server || !server || connectingRef.current) return;
    connectingRef.current = true;
    setBusy(true);
    setStatuses((previous) => ({ ...previous, [row.id]: { text: "connecting...", tone: "pending" } }));
    try {
      const connection = await manager.connect(row.server, server);
      setStatuses((previous) => ({
        ...previous,
        [row.id]: { text: `connected | ${connection.tools.length} tools`, tone: "ok" },
      }));
      onHint(`${row.server} connected | ${connection.tools.length} tools`, "ok");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setStatuses((previous) => ({ ...previous, [row.id]: { text: message, tone: "error" } }));
      onHint(`${row.label} failed: ${message}`, "error");
    } finally {
      connectingRef.current = false;
      setBusy(false);
    }
  }

  async function saveKey() {
    if (!detail || savingRef.current) return;
    const envName = envFor(detail);
    const value = secret.trim();
    if (!envName) {
      setNotice({ text: "this endpoint has no key variable; set one with /providers key ENV_VAR", tone: "warn" });
      return;
    }
    if (!value) {
      setNotice({ text: "paste a key first - nothing was saved", tone: "warn" });
      return;
    }
    savingRef.current = true;
    setBusy(true);
    try {
      await saveCredential(config.dataDir, envName, value);
      setSecret("");
      setKeyMode(false);
      onHint(`key saved -> ${envName} | activating ${detail.label}`, "ok");
      onApply({ ...detail, apiKeyEnv: envName });
    } catch (error) {
      setNotice({ text: error instanceof Error ? error.message : String(error), tone: "error" });
    } finally {
      savingRef.current = false;
      setBusy(false);
    }
  }

  usePaste((event) => {
    if (!keyMode) return;
    const text = new TextDecoder().decode(event.bytes);
    const printable = [...text].filter((char) => char >= " " && char <= "~").join("").trim();
    if (printable) setSecret((value) => value + printable);
  });

  useKeyboard((key) => {
    if (keyMode && (key.ctrl || key.meta) && key.name.toLowerCase() === "v") {
      key.preventDefault();
      void (async () => {
        const text = await readClipboard();
        const printable = text
          ? [...text]
              .filter((char) => char >= " " && char <= "~")
              .join("")
              .trim()
              .slice(0, 8_192)
          : "";
        if (!printable) {
          setNotice({ text: "clipboard empty or unavailable - use your terminal paste shortcut", tone: "warn" });
          return;
        }
        setSecret((value) => (value + printable).slice(0, 8_192));
        setNotice({ text: `pasted ${printable.length} chars - enter saves & activates`, tone: "faint" });
      })();
      return;
    }
    if (key.ctrl || key.meta) return;
    if (mode === "detail") {
      if (keyMode) {
        if (key.name === "escape") {
          key.preventDefault();
          setKeyMode(false);
          setSecret("");
          return;
        }
        if (key.name === "return" || key.name === "enter") {
          key.preventDefault();
          if (secret.trim() && !savingRef.current) void saveKey();
          return;
        }
        if (key.name === "backspace") {
          key.preventDefault();
          setSecret((value) => value.slice(0, -1));
          return;
        }
        const source = key.sequence && key.sequence.length > 0 ? key.sequence : key.name.length === 1 ? key.name : "";
        const printable = [...source].filter((char) => char >= " " && char <= "~").join("");
        if (printable) {
          key.preventDefault();
          setSecret((value) => value + printable);
        }
        return;
      }
      if (key.name === "escape") {
        key.preventDefault();
        setMode("list");
        setDetail(undefined);
        setNotice(undefined);
        return;
      }
      if (key.name === "k") {
        key.preventDefault();
        const envName = detail?.id === active.id ? settings.apiKeyEnv || detail?.apiKeyEnv : detail?.apiKeyEnv;
        if (!envName) {
          setNotice({ text: "no key variable for this endpoint - /providers key ENV_VAR", tone: "warn" });
          return;
        }
        setKeyMode(true);
        setSecret("");
        return;
      }
      if (key.name === "r") {
        key.preventDefault();
        if (detail) void verify(detail);
        return;
      }
      if (key.name === "return" || key.name === "enter") {
        key.preventDefault();
        if (!detail || applyingRef.current) return;
        applyingRef.current = true;
        onApply(detail);
        setTimeout(() => {
          applyingRef.current = false;
        }, 0);
      }
      return;
    }
    if (key.name === "escape") {
      key.preventDefault();
      onClose();
      return;
    }
    if (key.name === "down") {
      key.preventDefault();
      key.stopPropagation();
      setIndex(Math.min(Math.max(0, rows.length - 1), clamped + 1));
      return;
    }
    if (key.name === "up") {
      key.preventDefault();
      key.stopPropagation();
      setIndex(Math.max(0, clamped - 1));
      return;
    }
    if (key.name === "return" || key.name === "enter") {
      key.preventDefault();
      chooseSelected();
    }
  });

  if (mode === "detail" && detail) {
    const isActive = detail.id === active.id;
    const envName = isActive ? settings.apiKeyEnv || detail.apiKeyEnv : detail.apiKeyEnv;
    const known = detail.models;
    const models = discovered.length > 0 ? [...new Set([...discovered, ...known])].sort((a, b) => a.localeCompare(b)) : known;
    return (
      <ModalFrame
        title={`${detail.label}${isActive ? " (active)" : ""}`}
        subtitle={`${detail.baseUrl || "(no base url)"} | ${envName ?? "no key variable"} | ${envName && process.env[envName] ? "key set" : "no key"}`}
        footer={
          keyMode
            ? busy
              ? "saving the key..."
              : "ctrl+v or terminal paste | enter save & activate | esc back | hidden"
            : "enter use | k replace key | r verify | esc back"
        }
        onClose={onClose}
      >
        <text fg={statusColor(notice?.tone ?? "faint")} wrapMode="none">{truncate(notice?.text ?? " ", Math.max(30, width - 10))}</text>
        {detail.keysUrl ? (
          <text fg={palette.accent} wrapMode="none">{truncate(`get a key | ${detail.keysUrl}`, Math.max(30, width - 10))}</text>
        ) : null}
        {keyMode ? (
          <box flexDirection="row" paddingLeft={1} height={1}>
            <text fg={palette.text}>{`${envName ?? "API key"}  `}</text>
            <text fg={palette.ok}>{secret.length > 0 ? "-".repeat(Math.min(secret.length, Math.max(8, width - 30))) : "(empty)"}</text>
            <text fg={palette.faint}>{`  ${secret.length} chars - never stored in the transcript`}</text>
          </box>
        ) : null}
        <box flexDirection="column" flexGrow={1} paddingTop={1}>
          <text fg={palette.faint} wrapMode="none">
            {busy ? "discovering models..." : `${models.length} models${discovered.length > 0 ? " | live" : " | known catalog"}`}
          </text>
          {models.slice(0, Math.max(4, rowsHeight - 4)).map((model) => (
            <box key={model} height={1} flexShrink={0}>
              <text wrapMode="none">
                <span fg={isActive && model === settings.model ? palette.ok : palette.ghost}>
                  {isActive && model === settings.model ? `${GLYPH.done} ` : "  "}
                </span>
                <span fg={palette.text}>{truncate(model, Math.max(30, width - 12))}</span>
              </text>
            </box>
          ))}
          {models.length > Math.max(4, rowsHeight - 4) ? (
            <text fg={palette.faint}>{`+${models.length - Math.max(4, rowsHeight - 4)} more | /models shows the full grouped catalog`}</text>
          ) : null}
        </box>
      </ModalFrame>
    );
  }

  return (
    <ModalFrame
      title="Connections"
      subtitle={`${providerRows.length} provider(s) · ${mcpRows.length} MCP server(s) · enter uses a provider or adds its key`}
      footer="↑↓ select  ·  enter use/add key  ·  wheel scrolls  ·  type to search  ·  esc close"
      onClose={onClose}
      onScroll={(direction) =>
        setIndex((value) => Math.min(Math.max(0, rows.length - 1), Math.max(0, value + (direction === "up" ? -1 : 1))))
      }
    >
      <SearchRow
        value={query}
        onInput={setQuery}
        focused={!keyMode}
        placeholder="search providers, models or MCP servers"
        onSubmit={() => chooseSelected()}
      />
      <box flexDirection="column" flexGrow={1}>
        {visible.items.map((row) => {
          const status = statuses[row.id];
          return (
            <KeyableRow
              key={row.id}
              selected={row.id === selectedRow?.id}
              onMouseDown={() => {
                setIndex(rows.findIndex((entry) => entry.id === row.id));
                if (row.kind === "provider" && row.provider) chooseProvider(row.provider);
                else if (row.kind === "mcp") void connectMcp(row);
              }}
            >
              <text wrapMode="none">
                <span fg={row.id === selectedRow?.id ? palette.accent : palette.ghost}>
                  {row.id === selectedRow?.id ? `${GLYPH.bar} ` : "  "}
                </span>
                <span fg={row.kind === "provider" ? palette.text : palette.muted}>{row.label.padEnd(30)} </span>
                <span fg={palette.faint}>{truncate(row.detail, Math.max(20, width - 44))}</span>
              </text>
              {status ? <text fg={statusColor(status.tone === "pending" ? "warn" : status.tone)} wrapMode="none">{`  ${status.text}`}</text> : null}
            </KeyableRow>
          );
        })}
        {rows.length === 0 ? <text fg={palette.faint} wrapMode="none">nothing matches this search</text> : null}
        {query === "" && mcpRows.length === 0 ? (
          <text fg={palette.faint} wrapMode="none">no MCP servers configured - add mcpServers to argus.config.json</text>
        ) : null}
        {query === "" && providerRows.length > 0 && apiKeyPresent(settings) === false && active.requiresKey ? (
          <text fg={palette.warn} wrapMode="none">
            no key in {settings.apiKeyEnv || "the provider variable"} - press enter here to add it, or type /key
          </text>
        ) : null}
      </box>
    </ModalFrame>
  );
}

export function DashboardModal({
  findings,
  phases,
  target,
  profile,
  status,
  runId,
  elapsedMs,
  dependencies,
  store,
  lastRunId,
  onClose,
}: {
  findings: Finding[];
  phases: DashboardPhase[];
  target?: string;
  profile?: string;
  status?: string;
  runId?: string;
  elapsedMs?: number;
  dependencies?: DependencyGraphSnapshot;
  store: RunStore;
  lastRunId?: string;
  onClose: () => void;
}) {
  const [offset, setOffset] = useState(0);
  const [loaded, setLoaded] = useState<{
    findings: Finding[];
    phases: DashboardPhase[];
    target?: string;
    profile?: string;
    status?: string;
    runId?: string;
    elapsedMs?: number;
    dependencies?: DependencyGraphSnapshot;
  }>();
  const [loading, setLoading] = useState(false);
  const { height, width } = useTerminalDimensions();
  const rows = Math.max(6, Math.floor(height * 0.88) - 8);
  const innerWidth = Math.max(40, Math.floor(width * 0.92) - 6);

  useEffect(() => {
    if (findings.length > 0 || phases.length > 0) return;
    let cancelled = false;
    setLoading(true);
    (async () => {
      try {
        const id = lastRunId ?? (await store.list(1))[0]?.id;
        if (!id) return;
        const handle = await store.load(id);
        if (!handle || cancelled) return;
        setLoaded({
          findings: handle.findings,
          phases: handle.record.phaseSummary.map((phase) => ({
            id: phase.id,
            label: phase.label,
            status: phase.status,
            durationMs: phase.durationMs,
          })),
          target: handle.record.target.display,
          profile: handle.record.profile,
          status: handle.record.status,
          runId: handle.record.id,
          dependencies: handle.record.dependencies,
          elapsedMs:
            handle.record.startedAt && handle.record.finishedAt
              ? Math.max(0, Date.parse(handle.record.finishedAt) - Date.parse(handle.record.startedAt))
              : undefined,
        });
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [findings.length, phases.length, lastRunId, store]);

  const input = {
    findings: findings.length > 0 ? findings : loaded?.findings ?? [],
    phases: phases.length > 0 ? phases : loaded?.phases ?? [],
    target: target ?? loaded?.target,
    profile: profile ?? loaded?.profile,
    status: status ?? loaded?.status,
    runId: runId ?? loaded?.runId,
    elapsedMs: elapsedMs ?? loaded?.elapsedMs,
    dependencies: dependencies ?? loaded?.dependencies,
  };
  const lines = buildDashboard(input, innerWidth);
  const clamped = Math.min(offset, Math.max(0, lines.length - rows));
  const visible = lines.slice(clamped, clamped + rows);

  useKeyboard((key) => {
    if (key.ctrl || key.meta) return;
    if (key.name === "escape") {
      key.preventDefault();
      onClose();
      return;
    }
    if (key.name === "down") {
      key.preventDefault();
      key.stopPropagation();
      setOffset(Math.min(Math.max(0, lines.length - rows), clamped + 1));
      return;
    }
    if (key.name === "up") {
      key.preventDefault();
      key.stopPropagation();
      setOffset(Math.max(0, clamped - 1));
      return;
    }
    if (key.name === "pagedown") {
      key.preventDefault();
      setOffset(Math.min(Math.max(0, lines.length - rows), clamped + rows));
      return;
    }
    if (key.name === "pageup") {
      key.preventDefault();
      setOffset(Math.max(0, clamped - rows));
      return;
    }
    if (key.name === "home") {
      key.preventDefault();
      setOffset(0);
      return;
    }
    if (key.name === "end") {
      key.preventDefault();
      setOffset(Math.max(0, lines.length - rows));
    }
  });

  return (
    <ModalFrame
      title="Dashboard"
      subtitle={loading ? "loading the latest run..." : `${lines.length} rows | ${input.findings.length} findings | ${Math.round(((clamped + rows) / Math.max(1, lines.length)) * 100)}%`}
      footer="↑↓ scroll  ·  pgup/pgdn page  ·  wheel scrolls  ·  esc close"
      wide
      onClose={onClose}
      onScroll={(direction) =>
        setOffset((value) =>
          Math.min(Math.max(0, lines.length - rows), Math.max(0, value + (direction === "up" ? -3 : 3))),
        )
      }
    >
      <box flexDirection="column" flexGrow={1}>
        {visible.map((line, index) => (
          <text key={`${clamped + index}`} wrapMode="none">
            {line.tag ? (
              <span fg={palette.chipInk} bg={dashColor(line.tone)}>
                <strong>{line.tag}</strong>
              </span>
            ) : null}
            <span fg={dashColor(line.tone)}>{`${line.tag ? " " : ""}${line.text}`}</span>
            {line.rule ? <span fg={palette.rule}>{` ${ruleLine(Math.max(0, innerWidth - line.text.length - 2))}`}</span> : null}
          </text>
        ))}
        {lines.length > rows ? (
          <text fg={palette.faint}>{`${clamped + 1}-${Math.min(lines.length, clamped + rows)} of ${lines.length}`}</text>
        ) : null}
      </box>
    </ModalFrame>
  );
}

function dashColor(tone: DashTone): string {
  if (tone === "text") return palette.strong;
  if (tone === "muted") return palette.muted;
  if (tone === "faint") return palette.faint;
  if (tone === "accent") return palette.accent;
  if (tone === "ok") return palette.ok;
  if (tone === "warn") return palette.warn;
  if (tone === "error") return palette.error;
  return severityColor[tone];
}

const PREVIEW_TONE: Record<PreviewTone, string> = {
  text: palette.text,
  add: palette.ok,
  del: palette.error,
  hunk: palette.accent,
  meta: palette.faint,
};

/**
 * Read-only preview panel for one file or one pending change. The agent opens it
 * with the `preview` tool (before it asks to write) and the operator can open it
 * at any time with `/preview <path>`. It never writes anything.
 */
export function PreviewModal({ payload, onClose }: { payload: PreviewPayload; onClose: () => void }) {
  const { height, width } = useTerminalDimensions();
  const rows = Math.max(6, Math.floor(height * 0.88) - 8);
  const innerWidth = Math.max(40, Math.floor(width * 0.92) - 8);
  const all = useMemo(() => previewRows(payload), [payload]);
  const [revealed, setRevealed] = useState(all.length <= 12 ? all.length : 0);

  // A short staggered reveal: the panel draws like a page instead of flashing in.
  useEffect(() => {
    if (all.length <= 12) {
      setRevealed(all.length);
      return;
    }
    setRevealed(0);
    const chunk = Math.max(1, Math.ceil(all.length / 12));
    const timer = setInterval(() => {
      setRevealed((count) => {
        const next = count + chunk;
        if (next >= all.length) clearInterval(timer);
        return Math.min(all.length, next);
      });
    }, 18);
    return () => clearInterval(timer);
  }, [all]);

  const [offset, setOffset] = useState(0);
  const shown = all.slice(0, revealed);
  const busy = revealed < all.length;
  const clamped = Math.min(offset, Math.max(0, shown.length - rows));
  const visible = shown.slice(clamped, clamped + rows);
  const percent = Math.round(((clamped + visible.length) / Math.max(1, all.length)) * 100);

  useKeyboard((key) => {
    if (key.ctrl || key.meta) return;
    if (key.name === "escape") {
      key.preventDefault();
      onClose();
      return;
    }
    if (key.name === "down" || key.name === "j") {
      key.preventDefault();
      key.stopPropagation();
      setOffset(Math.min(Math.max(0, all.length - rows), clamped + 1));
      return;
    }
    if (key.name === "up" || key.name === "k") {
      key.preventDefault();
      key.stopPropagation();
      setOffset(Math.max(0, clamped - 1));
      return;
    }
    if (key.name === "pagedown") {
      key.preventDefault();
      setOffset(Math.min(Math.max(0, all.length - rows), clamped + rows));
      return;
    }
    if (key.name === "pageup") {
      key.preventDefault();
      setOffset(Math.max(0, clamped - rows));
      return;
    }
    if (key.name === "home") {
      key.preventDefault();
      setOffset(0);
      return;
    }
    if (key.name === "end") {
      key.preventDefault();
      setOffset(Math.max(0, all.length - rows));
    }
  });

  return (
    <ModalFrame
      title={previewTitle(payload)}
      subtitle={`${previewSubtitle(payload)} | ${percent}%`}
      footer={busy ? "rendering lines...  ·  esc close" : "↑↓ or j/k scroll  ·  pgup/pgdn page  ·  home/end  ·  esc close"}
      wide
      onClose={onClose}
      onScroll={(direction) =>
        setOffset((value) =>
          Math.min(Math.max(0, all.length - rows), Math.max(0, value + (direction === "up" ? -3 : 3))),
        )
      }
    >
      <box flexDirection="column" flexGrow={1}>
        {visible.length === 0 ? (
          <text fg={palette.faint}>{busy ? "rendering..." : "no preview rows"}</text>
        ) : null}
        {visible.map((row, index) => (
          <text key={`${clamped + index}`} wrapMode="none">
            <span fg={palette.ghost}>{`${row.no !== undefined ? String(row.no).padStart(5) : "     "} `}</span>
            <span fg={PREVIEW_TONE[row.tone]}>{`${row.marker} `}</span>
            <span fg={row.tone === "text" ? palette.text : PREVIEW_TONE[row.tone]}>{truncate(row.text, innerWidth)}</span>
          </text>
        ))}
        {busy ? <text fg={palette.accent}>{`${spinnerFrame(revealed)} rendering ${revealed}/${all.length} lines`}</text> : null}
        {!busy && all.length > rows ? (
          <text fg={palette.faint}>{`${clamped + 1}-${Math.min(all.length, clamped + rows)} of ${all.length}`}</text>
        ) : null}
        {!busy && payload.truncated ? (
          <text fg={palette.warn}>{`truncated | /preview ${payload.path} --start N reads further`}</text>
        ) : null}
        {!busy && payload.note ? <text fg={palette.faint}>{payload.note}</text> : null}
      </box>
    </ModalFrame>
  );
}
