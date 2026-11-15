import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { InputRenderable } from "@opentui/core";
import { useKeyboard, useRenderer, useSelectionHandler, useTerminalDimensions } from "@opentui/react";
import { extractTargets, type AgentApprovalRequest, type AgentPlanItem } from "../core/agent";
import type { ArgusEvent } from "../core/events";
import { saveScopeFile } from "../core/config";
import { ArgusEngine } from "../core/engine";
import { ensureProjectMemory } from "../core/memory";
import { wantsAttackRequest } from "../core/prompt-scope";
import { resumeCommand, SessionMemory } from "../core/session";
import { permissionSummary } from "../core/permissions";
import { buildFixPlan } from "../core/remediation";
import { authorizeIntrusive, ensureLocalScope } from "../core/scope";
import type { ArgusConfig, Finding, Severity } from "../core/types";
import { findingRiskScore, rankFindings, truncate } from "../core/util";
import { runAgentPrompt } from "./agent-runner";
import { TerminalPanel } from "./terminal";
import type { TerminalSpec } from "./terminal-spec";
import { copyText, transcriptToText } from "./clipboard";
import { matchCommands, runCommand, runSummary, type CommandDeps, type CommandSpec, type ScanRequest } from "./commands";
import { useNow, useScopePreview } from "./hooks";
import { interpretLocalPrompt, isAssessmentPrompt, type LocalIntent } from "./intent";
import { previewNote, type PreviewPayload } from "./preview";
import {
  ApprovalModal,
  AuthorizeModal,
  ConnectModal,
  DashboardModal,
  ModelsModal,
  PreviewModal,
  ProvidersModal,
  type AuthorizeRequest,
} from "./modals";
import {
  apiKeyPresent,
  keyStatus,
  llmSettings,
  resolveProvider,
  saveLlmSettings,
  type ProviderProfile,
} from "./providers";
import {
  createScanState,
  elapsedMs,
  formatElapsed,
  meter,
  reduceScanEvent,
  scanProgress,
  windowed,
  type ScanState,
  type TranscriptEntry,
  type TranscriptKind,
} from "./state";
import { GLYPH, MARK, palette, ruleLine, severityColor, severityTag, spinnerFrame, stripMark } from "./theme";

const ARG_COMMANDS = new Set(["/scan", "/findings", "/report", "/scope", "/http", "/jwt"]);

type PendingApproval = AgentApprovalRequest & { respond: (allow: boolean, always?: boolean) => void };

type ModalState =
  | { kind: "providers" }
  | { kind: "models" }
  | { kind: "connect"; keyFor?: string; startInKey?: boolean }
  | { kind: "dashboard" }
  | { kind: "preview"; payload: PreviewPayload }
  | null;

function defaultScopePath(): string {
  const local = resolve("scope.json");
  return existsSync(local) ? local : "scope.json";
}

interface EntryStyle {
  mark: string;
  markColor: string;
  bodyColor: string;
}

/** Marker and colours for one transcript line; findings render with a chip. */
function entryStyle(kind: TranscriptKind): EntryStyle {
  switch (kind) {
    case "ok":
      return { mark: `${GLYPH.done} `, markColor: palette.ok, bodyColor: palette.text };
    case "warn":
      return { mark: `${GLYPH.fail} `, markColor: palette.warn, bodyColor: palette.warn };
    case "error":
      return { mark: "× ", markColor: palette.error, bodyColor: palette.error };
    case "info":
    case "phase":
      return { mark: `${GLYPH.step} `, markColor: palette.ghost, bodyColor: palette.muted };
    case "dim":
    default:
      return { mark: "", markColor: palette.faint, bodyColor: palette.faint };
  }
}

/** One transcript line: heading rule, operator prompt, finding chip or status. */
function EntryLine({ entry, width }: { entry: TranscriptEntry; width: number }) {
  if (entry.kind === "system") {
    const title = entry.text.toUpperCase();
    const fill = Math.max(0, width - title.length - 3);
    return (
      <text wrapMode="none">
        <span fg={palette.accent}>
          <strong>{title}</strong>
        </span>
        {fill > 0 ? <span fg={palette.ghost}>{` ${ruleLine(fill)}`}</span> : null}
      </text>
    );
  }
  if (entry.kind === "user") {
    return (
      <text wrapMode="word">
        <span fg={palette.accent}>
          <strong>{`${GLYPH.prompt} `}</strong>
        </span>
        <span fg={palette.strong}>{entry.text}</span>
      </text>
    );
  }
  if (entry.kind === "finding") {
    const severity = entry.severity ?? "info";
    return (
      <text wrapMode="word">
        <span fg={palette.chipInk} bg={severityColor[severity]}>
          <strong>{severityTag[severity]}</strong>
        </span>
        <span fg={palette.text}>{` ${entry.text}`}</span>
      </text>
    );
  }
  const style = entryStyle(entry.kind);
  return (
    <text wrapMode="word">
      <span fg={style.markColor}>{style.mark}</span>
      <span fg={style.bodyColor}>{entry.text}</span>
    </text>
  );
}

function sectionText(title: string, lines: string[]): string {
  // A quiet label, an indented body, and one blank line of breathing room.
  return [title, ...lines.map((line) => `  ${line}`), ""].join("\n");
}

export interface ArgusExitInfo {
  /** Workspace session id, so the caller can print the resume command. */
  sessionId: string;
  reason: "quit";
}

export interface ArgusTuiProps {
  config: ArgusConfig;
  /** Overrides the scope file used at startup (handy for tests and alternate profiles). */
  initialScopePath?: string;
  /**
   * Called once the renderer has been torn down. The entrypoint prints the
   * resume command and leaves the process; tests just record the call.
   */
  onExit?: (info: ArgusExitInfo) => void;
}

export function ArgusTui({ config: initialConfig, initialScopePath, onExit }: ArgusTuiProps) {
  const renderer = useRenderer();
  const [config, setConfig] = useState(initialConfig);
  const engineRef = useRef<ArgusEngine | null>(null);
  if (!engineRef.current) engineRef.current = new ArgusEngine(initialConfig);
  const engine = engineRef.current;

  const [entries, setEntries] = useState<TranscriptEntry[]>([]);
  const entryId = useRef(0);
  const [input, setInput] = useState("");
  const inputRef = useRef<InputRenderable | null>(null);
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [suggestionIndex, setSuggestionIndex] = useState(0);
  const suggestionRef = useRef(0);
  const [modal, setModal] = useState<ModalState>(null);
  const [scopePath, setScopePath] = useState(() => initialScopePath ?? defaultScopePath());
  const [scopeRevision, setScopeRevision] = useState(0);
  const scope = useScopePreview(scopePath, scopeRevision);
  const [running, setRunning] = useState(false);
  const [agentBusy, setAgentBusy] = useState(false);
  const [agentNote, setAgentNote] = useState("thinking");
  const [agentStartedAt, setAgentStartedAt] = useState(0);
  const [subagents, setSubagents] = useState<Record<string, "running" | "done" | "error">>({});
  const [plan, setPlan] = useState<AgentPlanItem[]>([]);
  /** Live stdout/stderr from commands and WSL tools, tailed in the LIVE panel. */
  const [terminalLines, setTerminalLines] = useState<Array<{ text: string; tone: "out" | "err" }>>([]);
  /** Non-null while the embedded PTY terminal is on screen. */
  const [terminalSpec, setTerminalSpec] = useState<TerminalSpec | null>(null);
  const [approval, setApproval] = useState<PendingApproval | null>(null);
  const [authorize, setAuthorize] = useState<AuthorizeRequest | null>(null);
  /** Set once the operator answers the authorization prompt, so it never re-asks. */
  const authorizeAnsweredRef = useRef(false);
  /** True while running a pass the operator asked for aggressively. */
  const aggressiveRequestRef = useRef(false);
  const autoApproveRef = useRef<Set<NonNullable<AgentApprovalRequest["action"]>>>(new Set());
  /** Set while an approval prompt is on screen, so a preview never covers it. */
  const approvalOpenRef = useRef(false);
  const pendingPreviewRef = useRef<PreviewPayload | undefined>(undefined);
  const agentBusyRef = useRef(false);
  const lastAnswerRef = useRef("");
  const selectedRef = useRef("");
  const copyAtRef = useRef(0);
  const [scan, setScan] = useState<ScanState>(() => createScanState());
  const [sessionFindings, setSessionFindings] = useState<Finding[]>([]);
  const [lastRunId, setLastRunId] = useState<string | undefined>();
  const abortRef = useRef<AbortController | null>(null);
  const agentAbortRef = useRef<AbortController | null>(null);
  const busy = running || agentBusy;
  const now = useNow(busy, 400);

  useEffect(() => {
    agentBusyRef.current = agentBusy;
  }, [agentBusy]);

  useSelectionHandler((selection) => {
    selectedRef.current = selection?.getSelectedText() ?? "";
  });

  const write = useCallback((kind: TranscriptKind, text: string, severity?: Severity) => {
    const id = entryId.current++;
    // Commands still prefix their own marks; the line marker is drawn once here.
    setEntries((previous) => [...previous, { id, kind, text: stripMark(text), severity }]);
  }, []);

  // Stable per workspace: the same id `argus resume -session <id>` reloads.
  const sessionId = useMemo(() => SessionMemory.forWorkspace(initialConfig.dataDir).id, [initialConfig.dataDir]);
  const exitRef = useRef(false);

  const shutdown = useCallback(() => {
    // Both ctrl+c and /quit land here; leaving must happen exactly once, or a
    // second keypress races the teardown and the process never returns to the shell.
    if (exitRef.current) return;
    exitRef.current = true;
    abortRef.current?.abort();
    agentAbortRef.current?.abort();
    renderer.destroy();
    onExit?.({ sessionId, reason: "quit" });
  }, [onExit, renderer, sessionId]);

  const abort = useCallback(() => {
    if (agentAbortRef.current) {
      write("warn", "aborting agent...");
      agentAbortRef.current.abort();
      return;
    }
    if (abortRef.current) {
      write("warn", "aborting assessment...");
      abortRef.current.abort();
    }
  }, [write]);

  const copySelection = useCallback(async () => {
    const text = renderer.getSelection()?.getSelectedText() ?? selectedRef.current;
    if (!text.trim()) return false;
    const result = await copyText(renderer, text);
    renderer.clearSelection();
    selectedRef.current = "";
    write(
      result.ok ? "ok" : "error",
      result.ok
        ? `copied selection | ${text.length} chars | ${result.channels.join("+")}`
        : result.error ?? "copy failed",
    );
    return true;
  }, [renderer, write]);

  /** Single place that mirrors engine events into the live scan view and transcript. */
  const handleEngineEvent = useCallback(
    (event: ArgusEvent) => {
      if (event.type === "run:start") {
        setScan(reduceScanEvent(createScanState(), event));
        setLastRunId(event.runId);
        if (agentBusyRef.current) setAgentNote(`scan | ${event.target.display}`);
      } else {
        setScan((previous) => reduceScanEvent(previous, event));
      }

      if (event.type === "phase:start") {
        write("phase", event.label);
        if (agentBusyRef.current) setAgentNote(event.label);
      } else if (event.type === "task:start") {
        if (agentBusyRef.current) setAgentNote(event.label);
      } else if (event.type === "task:end" && event.status === "failed") {
        write("error", `${MARK.fail} probe | ${event.label} | ${event.message ?? "unknown error"}`);
      } else if (event.type === "finding") {
        setSessionFindings((previous) =>
          previous.some((finding) => finding.id === event.finding.id) ? previous : [...previous, event.finding],
        );
        write(
          "finding",
          `${event.finding.title} | ${event.finding.url ?? event.finding.target}`,
          event.finding.severity,
        );
        if (agentBusyRef.current) setAgentNote(`finding | ${event.finding.title}`);
      } else if (event.type === "log" && (event.level === "warn" || event.level === "error")) {
        write(event.level === "error" ? "error" : "warn", event.message);
      }
    },
    [write],
  );

  const followEngine = useCallback(() => {
    const failed: string[] = [];
    const unsubscribe = engine.bus.subscribe((event: ArgusEvent) => {
      if (event.type === "task:end" && event.status === "failed") failed.push(event.label);
      handleEngineEvent(event);
    });
    return { failed, unsubscribe };
  }, [engine, handleEngineEvent]);

  const startScan = useCallback(
    async (request: ScanRequest) => {
      if (abortRef.current || agentBusyRef.current) {
        write("warn", "another job is running | press esc to abort it first");
        return;
      }
      const controller = new AbortController();
      abortRef.current = controller;
      setRunning(true);
      setScan(createScanState({ target: request.target, profile: request.profile, status: "running", startedAt: Date.now() }));
      write("info", `target ${request.target}  ·  profile ${request.profile}`);
      const { failed, unsubscribe } = followEngine();

      try {
        const handle = await engine.run(
          {
            target: request.target,
            scopePath: request.scopePath,
            options: {
              profile: request.profile,
              passiveOnly: request.passiveOnly,
              intrusive: request.intrusive,
              allowExternal: request.allowExternal,
              retryFailedTasks: request.retries,
              exportFormats: request.formats,
            },
          },
          { signal: controller.signal },
        );
        setLastRunId(handle.record.id);
        setScan((previous) => ({
          ...previous,
          findings: handle.findings,
          counts: handle.record.counts,
          dependencies: handle.record.dependencies,
          status: handle.record.status,
          finishedAt: handle.record.finishedAt ? Date.parse(handle.record.finishedAt) : Date.now(),
          error: handle.record.error,
        }));
        let reports: string[] = [];
        try {
          const artifacts = await engine.store.listArtifacts(handle.record.id);
          reports = artifacts.filter((artifact) => artifact.name.startsWith("report.")).map((artifact) => artifact.name);
        } catch {
          reports = [];
        }
        write("dim", "");
        for (const [kind, text] of runSummary(handle, failed, reports)) write(kind, text);
        const ranked = rankFindings(handle.findings).slice(0, 6);
        if (ranked.length > 0) {
          write("system", `TOP RISKS | ${Math.min(handle.findings.length, 6)} of ${handle.findings.length}`);
          for (const finding of ranked) {
            write(
              "finding",
              `risk ${findingRiskScore(finding)}  ·  ${finding.title}  ·  ${finding.url ?? finding.target}`,
              finding.severity,
            );
          }
        }
        const scanPlan = buildFixPlan(handle.findings, 5);
        if (scanPlan.length > 0) {
          write("system", "FIX PLAN");
          for (const action of scanPlan) {
            write("finding", `${action.priority} | ${action.remediation}`, action.severity);
            if (action.count > 1) write("dim", `     ${action.count} finding(s) share this fix`);
          }
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        setScan((previous) => ({
          ...previous,
          status: controller.signal.aborted ? "aborted" : "failed",
          error: message,
          finishedAt: Date.now(),
        }));
        write("error", message);
      } finally {
        unsubscribe();
        abortRef.current = null;
        setRunning(false);
      }
    },
    [engine, followEngine, write],
  );

  const commandDeps = useMemo<CommandDeps>(
    () => ({
      config,
      scopePath,
      engine,
      io: {
        write,
        clear: () => {
          lastAnswerRef.current = "";
          setEntries([]);
        },
        quit: shutdown,
      },
      running: busy,
      lastRunId,
      setConfig,
      setScopePath,
      setLastRunId,
      startScan,
      openPreview: (payload) => setModal({ kind: "preview", payload }),
      openTerminal: (spec) => setTerminalSpec(spec),
    }),
    [config, scopePath, engine, write, busy, lastRunId, shutdown, startScan],
  );

  const runLocalIntent = useCallback(
    async (intent: LocalIntent) => {
      if (intent.kind === "modal") {
        setModal({ kind: intent.modal });
        return;
      }
      if (intent.kind === "connect") {
        setModal({ kind: "connect", keyFor: intent.keyFor, startInKey: intent.startInKey ?? Boolean(intent.keyFor) });
        return;
      }
      try {
        // After an intrusive approval, a local scan should actually use the
        // probes the operator just authorized.
        const line =
          intent.kind === "scan" &&
          aggressiveRequestRef.current &&
          scope.scope?.allowIntrusive &&
          !/--intrusive/.test(intent.line)
            ? `${intent.line} --intrusive`
            : intent.line;
        await runCommand(line, commandDeps);
      } catch (error) {
        write("error", error instanceof Error ? error.message : String(error));
      }
    },
    [commandDeps, scope.scope?.allowIntrusive, write],
  );

  useEffect(() => {
    if (!modal) inputRef.current?.focus();
  }, [modal]);

  const executePrompt = useCallback(
    async (line: string) => {
      const activeSettings = llmSettings(config);
      const activeProvider = resolveProvider(activeSettings);
      const needsKey = activeProvider.requiresKey && !apiKeyPresent(activeSettings);
      const local = interpretLocalPrompt(line, {
        workspace: process.cwd(),
        scopeTargets: scope.scope?.allow,
      });
      // With a model configured, only UI navigation stays local: an assessment
      // sentence always reaches the agent, so a keyword inside it ("report",
      // "runs", "findings") can never hijack what the operator actually asked.
      const uiOnly = local?.kind === "modal" || local?.kind === "connect";
      const assessment =
        !needsKey && isAssessmentPrompt(line, { workspace: process.cwd(), scopeTargets: scope.scope?.allow });
      // An attack request against a scope that still locks intrusive testing
      // asks for explicit permission first. Approving writes the wider scope to
      // disk; declining keeps the pass read-only. Nothing is sent while it asks.
      const aggressiveRequest = wantsAttackRequest(line);
      // The prompt has to name the target itself: "explain SSRF" is a question,
      // while "attack example.com" is a request against the named surface.
      const namedTarget = aggressiveRequest && extractTargets(line).length > 0;
      const assessmentLike = assessment || local?.kind === "scan" || namedTarget;
      if (
        assessmentLike &&
        !uiOnly &&
        aggressiveRequest &&
        scope.scope &&
        !scope.scope.allowIntrusive &&
        !authorizeAnsweredRef.current
      ) {
        aggressiveRequestRef.current = true;
        setAuthorize({ prompt: line, targets: scope.scope.allow ?? [], scopePath });
        return;
      }
      if (local && (uiOnly || needsKey || !assessment)) {
        write("dim", `${MARK.note} local ${local.kind === "scan" ? "scan" : "action"} | no model call`);
        await runLocalIntent(local);
        return;
      }
      if (needsKey) {
        write("warn", `no API key for ${activeProvider.label} | free-form prompts need a model`);
        write("dim", `${MARK.note} key | /key ${activeProvider.id} | then press Up and Enter to retry`);
        write("dim", `${MARK.fail} no key | no-key actions | check <target> | show findings | dashboard | /doctor | /tools | /web <query> | /jwt <token>`);
        return;
      }

      const controller = new AbortController();
      agentAbortRef.current = controller;
      const startedAt = Date.now();
      let progressed = false;
      let fallback: LocalIntent | undefined;
      let lastStep = 0;
      let lastNote = "";
      autoApproveRef.current = new Set();
      setAgentBusy(true);
      setAgentNote("planning");
      setAgentStartedAt(startedAt);
      setSubagents({});
      setPlan([]);
      setTerminalLines([]);
      write("dim", `${MARK.run} agent | ${activeProvider.label} | ${activeSettings.model} | ${keyStatus(activeSettings)}`);
      try {
        const result = await runAgentPrompt({
          config,
          engine,
          scopePath,
          prompt: line,
          callbacks: {
            signal: controller.signal,
            onEngineEvent: handleEngineEvent,
            onStep: (step, note) => {
              if (step !== lastStep) {
                lastStep = step;
                lastNote = "";
              }
              setAgentNote(`step ${step} | ${note}`);
              if (note === lastNote) return;
              lastNote = note;
              write("dim", `  ${MARK.step} step ${String(step).padStart(2, "0")} | ${note}`);
            },
            onTool: (tool, status, detail) => {
              progressed = true;
              if (status === "start") write("dim", `  ${MARK.run} ${tool} | running`);
              else if (status === "error") write("warn", `  ${MARK.fail} ${tool} | ${detail ?? "failed"}`);
              else write("dim", `  ${MARK.done} ${tool} | ${detail ?? "done"}`);
            },
            onCommandOutput: (_tool, stream, chunk) => {
              const lines = chunk
                .replace(/\r/g, "")
                .split("\n")
                .filter((text) => text.trim().length > 0);
              if (lines.length === 0) return;
              const tone: "out" | "err" = stream === "stderr" ? "err" : "out";
              setTerminalLines((previous) =>
                [...previous, ...lines.map((text) => ({ text: text.slice(0, 400), tone }))].slice(-200),
              );
            },
            onModelReply: (_step, raw, valid, mode) => {
              // Under native tool calling a text answer with no tool call is the
              // normal final reply, not a protocol error.
              if (valid || mode === "tools") return;
              const preview = truncate(raw.replace(/\s+/g, " ").trim(), 220);
              write("warn", `  ${MARK.fail} model | reply was not agent JSON | ${preview || "(empty)"}`);
            },
            onSubagent: (label, status, detail) => {
              setSubagents((previous) => ({ ...previous, [label]: status === "start" ? "running" : status }));
              if (status === "error") write("warn", `  ${MARK.fail} ${label} | failed | ${detail ?? "unknown error"}`);
              else if (status === "done") write("dim", `  ${MARK.done} ${label} | done | ${detail ?? "finished"}`);
              else write("dim", `  ${MARK.run} ${label} | working | ${detail ?? "starting"}`);
            },
            onPlan: (items) => setPlan(items),
            onPermission: (policy) => write("dim", `${MARK.note} perm | ${permissionSummary(policy)}`),
            onPreview: (payload) => {
              write("dim", `  ${MARK.note} preview | ${previewNote(payload)}`);
              // An approval prompt owns the screen: show the preview right after it.
              if (approvalOpenRef.current) {
                pendingPreviewRef.current = payload;
                return;
              }
              setModal({ kind: "preview", payload });
            },
            approve: (request) => {
              // A run-wide grant never covers high-risk actions; those still ask.
              if (request.action && request.risk !== "high" && autoApproveRef.current.has(request.action)) {
                return Promise.resolve(true);
              }
              return new Promise<boolean>((settle) => {
                approvalOpenRef.current = true;
                setApproval({
                  ...request,
                  respond: (allow, always) => {
                    setApproval(null);
                    approvalOpenRef.current = false;
                    if (allow && always && request.action && request.risk !== "high") {
                      autoApproveRef.current.add(request.action);
                    }
                    const queued = pendingPreviewRef.current;
                    pendingPreviewRef.current = undefined;
                    if (queued) setModal({ kind: "preview", payload: queued });
                    settle(allow);
                  },
                });
              });
            },
          },
        });

        if (result.scopePath) {
          if (result.scopePath !== scopePath) setScopePath(result.scopePath);
          setScopeRevision((value) => value + 1);
          if (result.scopeSource === "prompt") {
            write("ok", `${MARK.done} scope | ${result.scopeUpdated ? "updated" : "derived"} from the request | ${result.scopePath}`);
          }
        }
        if (controller.signal.aborted) {
          write("warn", "agent aborted | partial results saved; type continue to resume");
        }
        const ranked = rankFindings(result.verified);
        const findingLines = ranked.map((finding) => {
          const meta = `${finding.confidence}  ·  ${finding.category}  ·  ${finding.url ?? finding.target}`;
          return [
            `[${severityTag[finding.severity].trim()}] risk ${findingRiskScore(finding)}  ·  ${finding.title}`,
            `  ${meta}`,
            `  ${truncate(finding.evidence.replace(/\s+/g, " ").trim(), 240)}`,
          ].join("\n");
        });
        const fixPlan = buildFixPlan(result.verified, 5);
        const answer = [
          sectionText("RESULT", [result.summary]),
          result.scopeCreated
            ? result.scopeSource === "prompt"
              ? `${MARK.note} scope | prompt-derived | ${result.scopePath}`
              : `${MARK.note} scope | workspace-only scope created | ${result.scopePath}`
            : result.scopePath
              ? ""
              : `${MARK.note} scope | none needed | reading, search and analysis run without one; name a target (path, URL, host) when you want a scan`,

          result.resumedFrom ? `${MARK.note} session | resumed | ${truncate(result.resumedFrom, 160)}` : "",
          sectionText(
            `FINDINGS | ${ranked.length} verified | ${result.dropped} dropped`,
            findingLines.length > 0 ? findingLines : ["no tool-verified findings in this pass"],
          ),
          fixPlan.length > 0
            ? sectionText(
                "FIXES",
                fixPlan.map((action) => `${action.priority} | ${action.remediation}${action.count > 1 ? ` (${action.count} findings)` : ""}`),
              )
            : "",
          result.gaps.length > 0 ? sectionText("GAPS", result.gaps.map((gap) => `- ${gap}`)) : "",
          result.nextSteps.length > 0 ? sectionText("NEXT", result.nextSteps.map((next) => `- ${next}`)) : "",
          result.memorySaved ? `${MARK.done} memory | AGENTS.md updated` : "",
          result.sessionId ? `${MARK.shell} ${resumeCommand(result.sessionId)}` : "",
          `${MARK.note} perm | ${result.permissionSummary}`,
          `${MARK.note} stats | steps=${result.steps} | scans=${result.scans.length} | observed=${result.observed} | elapsed=${formatElapsed(Date.now() - startedAt)}`,
        ]
          .filter(Boolean)
          .join("\n\n");
        lastAnswerRef.current = answer;

        write("dim", "");
        write("system", "RESULT");
        write("info", result.summary);
        if (result.scopeCreated && result.scopeSource !== "prompt") {
          write("info", `${MARK.note} scope | workspace-only scope created | ${result.scopePath}`);
        }
        if (result.resumedFrom) {
          write("info", `${MARK.note} session | resumed | ${truncate(result.resumedFrom, 120)}`);
        }
        write("system", `FINDINGS | ${ranked.length} verified | ${result.dropped} dropped`);
        if (ranked.length > 0) {
          for (const finding of ranked) {
            write(
              "finding",
              `risk ${findingRiskScore(finding)}  ·  ${finding.title}`,
              finding.severity,
            );
            write("dim", `      ${finding.confidence}  ·  ${finding.category}  ·  ${finding.url ?? finding.target}`);
          }
        } else {
          write("dim", "      no tool-verified findings in this pass");
        }
        if (result.dropped > 0) {
          write("warn", `anti-hallucination gate | ${result.dropped} unverified claim(s) dropped`);
        }
        if (fixPlan.length > 0) {
          write("system", "FIXES");
          for (const action of fixPlan) {
            write("finding", `${action.priority} | ${action.remediation}`, action.severity);
            if (action.count > 1) write("dim", `     ${action.count} finding(s) share this fix`);
          }
        }
        if (result.gaps.length > 0) {
          write("system", "GAPS");
          for (const gap of result.gaps) write("warn", `- ${gap}`);
        }
        if (result.nextSteps.length > 0) {
          write("system", "NEXT");
          for (const next of result.nextSteps) write("dim", `- ${next}`);
        }
        if (result.memorySaved) write("dim", `${MARK.done} memory | AGENTS.md updated`);
        if (result.sessionId) write("dim", `${MARK.shell} ${resumeCommand(result.sessionId)}`);
        write(
          "dim",
          `${MARK.note} stats | steps=${result.steps} | scans=${result.scans.length} | observed=${result.observed} | elapsed=${formatElapsed(Date.now() - startedAt)}`,
        );
      } catch (error) {
        if (controller.signal.aborted) {
          write("warn", "agent aborted | progress saved; type continue to resume");
        } else {
          const message = error instanceof Error ? error.message : String(error);
          write("error", message);
          if (/no api key/i.test(message)) {
            write("dim", `${MARK.note} key | /key ${activeProvider.id} | /doctor checks the whole setup`);
          } else if (/cannot reach|timed out|model call failed|HTTP 401|HTTP 403|fetch failed|ECONN|network/i.test(message)) {
            write("dim", `${MARK.fail} endpoint | ${activeSettings.baseUrl} | /doctor checks it | /models switches model`);
            write("dim", `${MARK.note} session | progress saved | type continue to resume from the last objective`);
            if (local && !progressed) fallback = local;
          }
        }
      } finally {
        agentAbortRef.current = null;
        agentBusyRef.current = false;
        setApproval(null);
        setAgentBusy(false);
        setAgentStartedAt(0);
        setAgentNote("planning");
        setSubagents({});
      }
      if (fallback) {
        write("warn", "model unavailable | running the local action instead");
        await runLocalIntent(fallback);
      }
    },
    [config, engine, handleEngineEvent, runLocalIntent, scope.scope?.allow, scopePath, write],
  );

  /**
   * Answers the intrusive-authorization prompt: approve writes the scope and
   * re-runs the request, read-only continues with the current scope, cancel
   * stops before anything is sent.
   */
  const resolveAuthorize = useCallback(
    async (decision: "approve" | "readOnly" | "cancel") => {
      const request = authorize;
      setAuthorize(null);
      if (!request) return;
      if (decision === "cancel") {
        write("info", "authorization | cancelled | nothing was sent");
        return;
      }
      authorizeAnsweredRef.current = true;
      if (decision === "approve" && scope.scope) {
        try {
          const next = authorizeIntrusive(scope.scope);
          const path = await saveScopeFile(next, request.scopePath);
          setScopeRevision((value) => value + 1);
          write("ok", `authorization | intrusive approved | ${path}`);
          write("dim", `${MARK.note} scope | active + intrusive on | approval recorded in the scope file`);
        } catch (error) {
          write(
            "error",
            `authorization | could not write the scope | ${error instanceof Error ? error.message : String(error)}`,
          );
          return;
        }
      } else {
        aggressiveRequestRef.current = false;
        write("info", "authorization | read-only pass | intrusive checks stay locked");
      }
      await executePrompt(request.prompt);
    },
    [authorize, executePrompt, scope.scope, write],
  );

  const runLine = useCallback(
    async (raw: string) => {
      const line = raw.trim();
      if (!line) return;
      // Read-only slash commands are safe while a pass runs: they must not
      // cancel it or queue behind it. /stop is the explicit way to end it.
      const safeWhileRunning = /^\/(stop|findings|pipeline|preview|copy|dashboard|help|status|doctor|scope)(\s|$)/.test(
        line.toLowerCase(),
      );
      if (busy && !safeWhileRunning) {
        write("warn", "a job is running | /stop ends it, /findings reads what it has so far");
        return;
      }
      if (line.toLowerCase() === "/stop") {
        if (!busy) {
          write("info", "nothing is running");
          return;
        }
        write("user", "/stop");
        abort();
        write("dim", "press ctrl+c again to leave argus | type continue to resume where it stopped");
        return;
      }
      setInput("");
      setHistory((previous) => [...previous, line].slice(-100));
      setHistoryIndex(-1);
      write("dim", "");
      write("user", line);

      if (!line.startsWith("/")) {
        await executePrompt(line);
        return;
      }

      const bare = line.toLowerCase();
      if (bare === "/providers") {
        setModal({ kind: "providers" });
        return;
      }
      if (bare === "/models") {
        setModal({ kind: "models" });
        return;
      }
      if (bare === "/connect") {
        setModal({ kind: "connect" });
        return;
      }
      if (bare === "/key" || bare.startsWith("/key ")) {
        const keyFor = line.slice(4).trim().replace(/^["']|["']$/g, "").toLowerCase() || undefined;
        setModal({ kind: "connect", keyFor, startInKey: true });
        return;
      }
      if (bare === "/copy" || bare.startsWith("/copy ")) {
        const mode = line.slice(5).trim().toLowerCase();
        const useLast = mode !== "all" && lastAnswerRef.current.trim().length > 0;
        const text = useLast ? lastAnswerRef.current : transcriptToText(entries);
        if (!text.trim()) {
          write("warn", "nothing to copy yet | ask something or run a scan first");
          return;
        }
        const result = await copyText(renderer, text);
        write(
          result.ok ? "ok" : "error",
          result.ok
            ? `copied ${useLast ? "last answer" : "transcript"} | ${text.length} chars | ${result.channels.join("+")}`
            : result.error ?? "copy failed",
        );
        return;
      }
      if (bare === "/dashboard") {
        setModal({ kind: "dashboard" });
        return;
      }
      try {
        await runCommand(line, commandDeps);
      } catch (error) {
        write("error", error instanceof Error ? error.message : String(error));
      }
    },
    [busy, commandDeps, entries, executePrompt, renderer, write],
  );

  const applyProvider = useCallback(
    async (provider: ProviderProfile) => {
      const current = llmSettings(config);
      if (provider.id === "custom" && !current.baseUrl) {
        write("error", "custom endpoints need a URL | run /providers url https://host/v1");
        setModal(null);
        return;
      }
      try {
        const currentProvider = resolveProvider(current);
        const keepModel =
          provider.id === currentProvider.id ||
          provider.models.length === 0 ||
          provider.models.includes(current.model);
        const model = keepModel ? current.model : provider.models[0]!;
        const next = await saveLlmSettings(config, {
          providerId: provider.id,
          baseUrl: provider.id === "custom" ? current.baseUrl : provider.baseUrl,
          apiKeyEnv: provider.apiKeyEnv ?? current.apiKeyEnv,
          model,
          enabled: true,
        });
        setConfig(next);
        setModal(null);
        write("ok", `${MARK.done} provider | ${provider.label} | ${llmSettings(next).baseUrl}`);
        write("dim", `${MARK.note} model | ${model} | key=${keyStatus(llmSettings(next))} | /models changes the model`);
      } catch (error) {
        write("error", error instanceof Error ? error.message : String(error));
      }
    },
    [config, write],
  );

  const applyModel = useCallback(
    async (provider: ProviderProfile, model: string) => {
      const current = llmSettings(config);
      const isActive = resolveProvider(current).id === provider.id;
      try {
        const next = await saveLlmSettings(config, {
          providerId: provider.id,
          baseUrl: isActive ? current.baseUrl || provider.baseUrl : provider.baseUrl,
          apiKeyEnv: provider.apiKeyEnv ?? (isActive ? current.apiKeyEnv : ""),
          model,
          enabled: true,
        });
        setConfig(next);
        setModal(null);
        write("ok", `${MARK.done} model | ${model}`);
        write("dim", `${MARK.note} provider | ${provider.label} | ${llmSettings(next).baseUrl}`);
      } catch (error) {
        write("error", error instanceof Error ? error.message : String(error));
      }
    },
    [config, write],
  );

  const suggestions = useMemo(() => matchCommands(input), [input]);
  const menu = windowed(suggestions, suggestionIndex, 8);

  useEffect(() => {
    suggestionRef.current = 0;
    setSuggestionIndex(0);
  }, [input]);

  const selectSuggestion = useCallback(
    (command: CommandSpec) => {
      if (command.name === "/providers") {
        setInput("");
        setModal({ kind: "providers" });
        return;
      }
      if (command.name === "/models") {
        setInput("");
        setModal({ kind: "models" });
        return;
      }
      if (command.name === "/connect") {
        setInput("");
        setModal({ kind: "connect" });
        return;
      }
      if (command.name === "/key") {
        setInput("");
        setModal({ kind: "connect", startInKey: true });
        return;
      }
      if (command.name === "/dashboard") {
        setInput("");
        setModal({ kind: "dashboard" });
        return;
      }
      if (ARG_COMMANDS.has(command.name)) {
        setInput(`${command.name} `);
        return;
      }
      setInput("");
      void runLine(command.name);
    },
    [runLine],
  );

  const booted = useRef(false);
  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    write("dim", "authorized security assessment. Only test systems you have written permission to assess.");
    write("dim", 'Try "check example.com and rank what you find", "look at this repo for bugs" or "/help".');
    // Interaction hints live in the footer so /help keeps its full command list visible.
    const bootSettings = llmSettings(initialConfig);
    const bootProvider = resolveProvider(bootSettings);
    if (bootProvider.requiresKey && !apiKeyPresent(bootSettings)) {
      write(
        "warn",
        `No API key for ${bootProvider.label} | /key ${bootProvider.id} adds one | /doctor checks the whole setup`,
      );
      write("dim", `${MARK.fail} no key | check <target> | show findings | dashboard | /web <query> | /jwt <token> | /http <url>`);
    }
    void ensureProjectMemory().catch(() => {});
    void ensureLocalScope(scopePath, process.cwd())
      .then((ensured) => {
        if (ensured.created) {
          write("ok", `${MARK.done} scope | local review scope ready | ${ensured.path}`);
          write("dim", `${MARK.note} scope | name a URL or host in the prompt to extend it automatically`);
        }
        setScopePath(ensured.path);
        setScopeRevision((value) => value + 1);
      })
      .catch((error: unknown) => {
        write("warn", `${MARK.fail} scope | could not initialize a local scope | ${error instanceof Error ? error.message : String(error)}`);
      });
  }, [initialConfig, scopePath, write]);

  useKeyboard((key) => {
    // While the PTY has focus every key belongs to the child process (vim needs
    // Enter, Esc and arrows). ctrl+shift+q is the emergency way out.
    if (terminalSpec) {
      if (key.ctrl && key.shift && key.name === "q") {
        key.preventDefault();
        setTerminalSpec(null);
      }
      return;
    }
    if (key.ctrl && key.name === "c") {
      key.preventDefault();
      // ctrl+c always targets the running pass first: it aborts the job and
      // stays in the app so partial results and the resume hint stay readable.
      // Only an idle ctrl+c leaves for the shell, so the terminal is never
      // left holding a half-dead TUI.
      if (approval) {
        approval.respond(false);
        return;
      }
      if (busy) {
        const stopping =
          (abortRef.current?.signal.aborted ?? false) || (agentAbortRef.current?.signal.aborted ?? false);
        // First press stops the work; while that drains, a second press leaves
        // for the shell so ctrl+c is never swallowed by a stubborn job.
        if (!stopping) {
          abort();
          return;
        }
        shutdown();
        return;
      }
      if (modal) {
        setModal(null);
        return;
      }
      const selection = renderer.getSelection()?.getSelectedText() ?? selectedRef.current;
      if (selection.trim() && Date.now() - copyAtRef.current > 2000) {
        copyAtRef.current = Date.now();
        void copySelection();
        write("dim", "selection copied | ctrl+c again exits");
        return;
      }
      shutdown();
      return;
    }
    if (approval) return;
    if (modal) return;
    if (key.name === "escape") {
      if (busy) abort();
      else setInput("");
      return;
    }
    if (suggestions.length > 0 && !busy && (key.name === "up" || key.name === "down")) {
      key.preventDefault();
      key.stopPropagation();
      const size = suggestions.length;
      const next = (suggestionRef.current + (key.name === "up" ? -1 : 1) + size) % size;
      suggestionRef.current = next;
      setSuggestionIndex(next);
      return;
    }
    if (key.name === "tab") {
      if (suggestions.length === 0) return;
      key.preventDefault();
      key.stopPropagation();
      const picked = suggestions[suggestionRef.current] ?? suggestions[0];
      if (picked) setInput(`${picked.name} `);
      return;
    }
    if (!busy && (key.name === "up" || key.name === "down") && suggestions.length === 0) {
      if (history.length === 0) return;
      key.preventDefault();
      key.stopPropagation();
      if (key.name === "up") {
        const next = historyIndex < 0 ? history.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(next);
        setInput(history[next] ?? "");
      } else if (historyIndex >= 0) {
        const next = historyIndex + 1;
        if (next >= history.length) {
          setHistoryIndex(-1);
          setInput("");
        } else {
          setHistoryIndex(next);
          setInput(history[next] ?? "");
        }
      }
      return;
    }      if (key.name === "return" || key.name === "enter") {
      key.preventDefault();
      const pending = input.trim().toLowerCase();
      const keepsRunning = /^\/(stop|findings|pipeline|preview|copy|dashboard|help|status|doctor|scope)(\s|$)/.test(pending);
      if (busy && !keepsRunning) {
        write("warn", "a job is running | /stop ends it, /findings reads what it has so far");
        return;
      }
      if (suggestions.length > 0) {
        const picked = suggestions[suggestionRef.current] ?? suggestions[0];
        if (picked) {
          selectSuggestion(picked);
          return;
        }
      }
      void runLine(input);
    }
  });

  const settings = llmSettings(config);
  const provider = resolveProvider(settings);
  const progress = scanProgress(scan);
  const { width } = useTerminalDimensions();
  const spin = spinnerFrame(Math.floor(now / 140));
  const runningSubagents = Object.entries(subagents)
    .filter(([, status]) => status === "running")
    .map(([label]) => label);

  const findings = sessionFindings.length > 0 ? sessionFindings : scan.findings;
  const counts = scan.counts;
  const scanLabel = progress.task?.label ?? progress.phase?.label ?? "scanning";
  const planned = plan.filter((item) => item.status === "done").length;
  const activePlan = plan.find((item) => item.status === "running") ?? plan.find((item) => item.status === "pending");
  const transcriptWidth = Math.max(40, width - 4);
  // The scope path sits on the right of the masthead; give it a share of the
  // row instead of a fixed slice that would clip the authorization details.
  const pathBudget = Math.min(44, Math.max(18, Math.floor(width * 0.3)));
  // The split view opens by itself while a pass runs: no command, no modal.
  // The left side stays the transcript; the right side is the live wire view.
  const liveOpen = busy;
  const liveWidth = Math.max(32, Math.min(56, Math.floor(width * 0.36)));
  const traffic = scan.logs.filter((entry) => entry.source === "attack").slice(-9);
  const liveFindings = findings.slice(-5).reverse();

  // One status line above the prompt: live work while it runs, the session
  // summary while it does not. Nothing decorative.
  let statusText: string;
  let statusTone: string = palette.faint;
  if (running) {
    statusText = `${spin}  ${truncate(scanLabel, 46)}  ${meter(progress.done, progress.total, 14)}  ${progress.done}/${
      progress.total
    }  ${formatElapsed(elapsedMs(scan, now))}`;
    statusTone = palette.warn;
  } else if (agentBusy) {
    const agents = runningSubagents.length > 0 ? `  agents ${truncate(runningSubagents.join(" "), 34)}` : "";
    statusText = `${spin}  ${truncate(agentNote, 52)}  ${formatElapsed(Math.max(0, now - agentStartedAt))}${agents}`;
    statusTone = palette.accent;
  } else if (findings.length > 0) {
    statusText = `${findings.length} finding${findings.length === 1 ? "" : "s"}  ·  ${counts.critical} crit  ${counts.high} high  ${counts.medium} med  ${counts.low} low`;
    statusTone = palette.muted;
  } else {
    statusText = "ready  ·  name a target to assess, or / for commands";
  }
  const statusRight =
    plan.length > 0
      ? `plan ${planned}/${plan.length}${activePlan ? `  ${truncate(activePlan.task, 40)}` : ""}`
      : busy
        ? "esc interrupt"
        : "";
  const scopeTone =
    scope.error || (scope.scope && !scope.validation?.ok) ? palette.warn : scope.scope ? palette.muted : palette.faint;
  const scopeText = scope.error
    ? `scope  ${truncate(scope.error, 60)}`
    : scope.scope
      ? `scope  ${truncate(scope.scope.name, 34)}  ·  ${scope.validation?.ok ? "valid" : "invalid"}  ·  ${truncate(scope.scope.authorizationRef, 32)}`
      : scope.loading
        ? "scope  loading..."
        : "scope  none loaded  ·  /scope init";

  if (terminalSpec) {
    return (
      <box flexDirection="column" width="100%" height="100%">
        <box
          height={2}
          flexShrink={0}
          flexDirection="row"
          border={["bottom"]}
          borderColor={palette.rule}
          paddingLeft={2}
          paddingRight={2}
        >
          <text fg={palette.accent} wrapMode="none">
            <strong>TERMINAL</strong>
          </text>
          <text fg={palette.faint} wrapMode="none">{`  ${terminalSpec.title}`}</text>
          <box flexGrow={1} />
          <text fg={palette.ghost} wrapMode="none">exit the program (:q / exit) to return</text>
        </box>
        <TerminalPanel
          spec={terminalSpec}
          onExit={(code) => {
            setTerminalSpec(null);
            write("dim", `terminal | exit ${code}`);
          }}
        />
      </box>
    );
  }

  return (
    <box flexDirection="column" width="100%" height="100%">
      <box
        height={3}
        flexDirection="column"
        justifyContent="center"
        border={["bottom"]}
        borderColor={palette.rule}
        paddingLeft={2}
        paddingRight={2}
      >
        <box flexDirection="row">
          <text wrapMode="none">
            <span fg={palette.accent}>
              <strong>{`${GLYPH.brand} ARGUS`}</strong>
            </span>
            <span fg={palette.faint}>  security assessment</span>
          </text>
          <box flexGrow={1} />
          <text wrapMode="none">
            <span fg={palette.muted}>{provider.label}</span>
            <span fg={palette.ghost}> · </span>
            <span fg={palette.muted}>{settings.model}</span>
          </text>
        </box>
        <box flexDirection="row">
          <text fg={scopeTone} wrapMode="none">
            {truncate(scopeText, Math.max(24, width - pathBudget - 6))}
          </text>
          <box flexGrow={1} />
          <text fg={palette.ghost} wrapMode="none">
            {truncate(scopePath, pathBudget)}
          </text>
        </box>
      </box>

      <box flexGrow={1} flexDirection="row">
        <scrollbox
          flexGrow={1}
          stickyScroll
          stickyStart="bottom"
          focusable={false}
          paddingLeft={2}
          paddingRight={2}
          paddingTop={1}
        >
          {entries.map((entry) => (
            <EntryLine key={entry.id} entry={entry} width={transcriptWidth} />
          ))}
          {entries.length === 0 ? (
            <box flexDirection="column" paddingBottom={1}>
              <text fg={palette.muted}>Ask in plain English. For example:</text>
              <text fg={palette.faint}>{`  ${GLYPH.prompt} check example.com and rank what you find`}</text>
              <text fg={palette.faint}>{`  ${GLYPH.prompt} look at this repo for bugs`}</text>
              <text fg={palette.faint}>{`  ${GLYPH.prompt} preview src/cli.ts`}</text>
            </box>
          ) : null}
          <box height={1} />
        </scrollbox>

        {liveOpen ? (
          <box
            width={liveWidth}
            flexShrink={0}
            flexDirection="column"
            border={["left"]}
            borderColor={palette.rule}
            paddingLeft={1}
            paddingRight={1}
            paddingTop={1}
          >
            <text fg={palette.accent} wrapMode="none">
              <strong>{`${spin} LIVE`}</strong>
              <span fg={palette.faint}>{`  ${truncate(scan.target ?? "agent", liveWidth - 10)}`}</span>
            </text>
            <text fg={palette.muted} wrapMode="none">
              {running
                ? `${truncate(scan.profile ?? "scan", 14)}  ${meter(progress.done, progress.total, 10)}  ${progress.done}/${
                    progress.total
                  }`
                : truncate(agentNote, liveWidth - 4)}
            </text>
            <text fg={palette.faint} wrapMode="none">
              {truncate(running ? scanLabel : "agent working", liveWidth - 4)}
            </text>

            <box height={1} />
            <text fg={palette.ghost} wrapMode="none">{"TERMINAL"}</text>
            {terminalLines.length === 0 ? (
              <text fg={palette.faint} wrapMode="none">
                {running ? "no command output yet" : "waiting for the agent"}
              </text>
            ) : (
              terminalLines.slice(-8).map((line, index) => (
                <text
                  key={`term-${terminalLines.length}-${index}`}
                  fg={line.tone === "err" ? palette.warn : palette.faint}
                  wrapMode="none"
                >
                  {truncate(line.text, liveWidth - 4)}
                </text>
              ))
            )}

            <box height={1} />
            <text fg={palette.ghost} wrapMode="none">{"TRAFFIC"}</text>
            {traffic.length === 0 ? (
              <text fg={palette.faint} wrapMode="none">
                {running ? "waiting for the first payload" : "no payloads yet"}
              </text>
            ) : (
              traffic.map((line, index) => (
                <text
                  key={`${line.at}-${index}`}
                  fg={/\|\s(?:5\d\d|4\d\d)\s/.test(line.message) ? palette.warn : palette.faint}
                  wrapMode="none"
                >
                  {truncate(line.message, liveWidth - 4)}
                </text>
              ))
            )}

            <box height={1} />
            <text fg={palette.ghost} wrapMode="none">{"FINDINGS"}</text>
            {liveFindings.length === 0 ? (
              <text fg={palette.faint} wrapMode="none">
                {running ? "none yet" : "none"}
              </text>
            ) : (
              liveFindings.map((finding) => (
                <text key={finding.id} wrapMode="none">
                  <span fg={severityColor[finding.severity]}>{severityTag[finding.severity]}</span>
                  <span fg={palette.text}>{` ${truncate(finding.title, liveWidth - 10)}`}</span>
                </text>
              ))
            )}

            <box flexGrow={1} />
            <text fg={palette.ghost} wrapMode="none">
              {"/stop ends  ·  ctrl+c stop"}
            </text>
          </box>
        ) : null}
      </box>

      <box height={1} flexShrink={0} flexDirection="row" paddingLeft={3} paddingRight={3}>
        <text fg={statusTone} wrapMode="none">
          {truncate(statusText, Math.max(24, width - 34))}
        </text>
        <box flexGrow={1} />
        {statusRight ? (
          <text fg={palette.faint} wrapMode="none">
            {truncate(statusRight, 46)}
          </text>
        ) : null}
      </box>

      {!modal && suggestions.length > 0 ? (
        <box
          flexDirection="column"
          height={menu.items.length}
          flexShrink={0}
          paddingLeft={1}
          paddingRight={1}
        >
          {menu.items.map((command, index) => {
            const absolute = menu.offset + index;
            const selected = absolute === suggestionIndex;
            return (
              <box
                key={command.name}
                height={1}
                flexShrink={0}
                backgroundColor={selected ? palette.selection : undefined}
                onMouseDown={() => selectSuggestion(command)}
              >
                <text wrapMode="none">
                  <span fg={palette.accent}>{selected ? `${GLYPH.bar} ` : "  "}</span>
                  <span fg={palette.strong}>{command.name.padEnd(13)}</span>
                  <span fg={palette.faint}>{command.summary}</span>
                </text>
              </box>
            );
          })}
        </box>
      ) : null}

      <box
        border
        borderStyle="rounded"
        borderColor={busy ? palette.borderFocus : palette.border}
        height={3}
        flexShrink={0}
        marginLeft={2}
        marginRight={2}
        paddingLeft={1}
        paddingRight={1}
        onMouseDown={() => {
          if (!modal) inputRef.current?.focus();
        }}
      >
        <box flexDirection="row">
          <text fg={busy ? palette.warn : palette.accent}>
            <strong>{`${GLYPH.prompt} `}</strong>
          </text>
          <input
            ref={inputRef}
            value={input}
            onInput={setInput}
            focused={!modal}
            placeholder={busy ? "esc to interrupt" : "Ask in plain English, or / for commands"}
            flexGrow={1}
            onMouseDown={() => {
              if (!modal) inputRef.current?.focus();
            }}
          />
        </box>
      </box>

      <box height={1} flexShrink={0} flexDirection="row" paddingLeft={3} paddingRight={3}>
        <text fg={palette.ghost}>/help  tab complete  /stop interrupt  ctrl+c stop · exit</text>
        <box flexGrow={1} />
        <text fg={palette.faint}>{keyStatus(settings)}</text>
      </box>

      {approval ? (
        <ApprovalModal
          request={approval}
          onAllow={() => approval.respond(true)}
          onAlways={() => approval.respond(true, true)}
          onDeny={() => approval.respond(false)}
        />
      ) : null}

      {authorize ? (
        <AuthorizeModal
          request={authorize}
          onApprove={() => void resolveAuthorize("approve")}
          onReadOnly={() => void resolveAuthorize("readOnly")}
          onCancel={() => void resolveAuthorize("cancel")}
        />
      ) : null}

      {modal?.kind === "providers" ? (
        <ProvidersModal
          config={config}
          onSelect={(picked) => void applyProvider(picked)}
          onClose={() => setModal(null)}
          onHint={(text) => {
            write("warn", text);
            setModal(null);
          }}
        />
      ) : null}

      {modal?.kind === "models" ? (
        <ModelsModal config={config} onSelect={(picked, model) => void applyModel(picked, model)} onClose={() => setModal(null)} />
      ) : null}

      {modal?.kind === "connect" ? (
        <ConnectModal
          config={config}
          initialKeyFor={modal.keyFor}
          startInKey={modal.startInKey}
          onApply={(picked) => void applyProvider(picked)}
          onClose={() => setModal(null)}
          onHint={(text, tone) => write(tone === "ok" ? "ok" : tone === "error" ? "error" : "warn", text)}
        />
      ) : null}

      {modal?.kind === "preview" ? <PreviewModal payload={modal.payload} onClose={() => setModal(null)} /> : null}

      {modal?.kind === "dashboard" ? (
        <DashboardModal
          findings={sessionFindings.length > 0 ? sessionFindings : scan.findings}
          phases={scan.phases}
          target={scan.target}
          profile={scan.profile}
          status={scan.runId ? scan.status : undefined}
          runId={scan.runId}
          elapsedMs={scan.startedAt ? (scan.finishedAt ?? now) - scan.startedAt : undefined}
          dependencies={scan.dependencies}
          store={engine.store}
          lastRunId={lastRunId}
          onClose={() => setModal(null)}
        />
      ) : null}
    </box>
  );
}
