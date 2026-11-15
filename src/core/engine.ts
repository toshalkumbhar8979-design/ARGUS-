import { resolve } from "node:path";
import type {
  ArgusConfig,
  Finding,
  FindingDraft,
  PhaseSummary,
  ProfileId,
  RunHandle,
  RunOptions,
  RunRecord,
  Target,
  TaskStatus,
  ToolAvailability,
} from "./types";
import { loadScopeFile } from "./config";
import { EventBus } from "./events";
import { HttpClient } from "./http";
import { ScopeGuard } from "./scope";
import { RunStore } from "./store";
import { createPlan, type ScanPlan } from "./planner";
import { discoverTools } from "./tools";
import { emptyCounts, expandHome, fingerprint, newId, sleep, sortFindings } from "./util";
import { writeReports } from "./report";
import { runConnectors } from "./connectors";

export interface RunRequest {
  target: string;
  scopePath: string;
  options: RunOptions;
}

export class ArgusEngine {
  readonly config: ArgusConfig;
  readonly store: RunStore;
  readonly bus: EventBus;
  private toolCache?: ToolAvailability[];

  constructor(config: ArgusConfig, store?: RunStore, bus?: EventBus) {
    this.config = config;
    this.store = store ?? new RunStore(config.dataDir);
    this.bus = bus ?? new EventBus();
  }

  async tools(refresh = false): Promise<ToolAvailability[]> {
    if (!refresh && this.toolCache) return this.toolCache;
    this.toolCache = await discoverTools();
    return this.toolCache;
  }

  async plan(target: Target, profile: ProfileId, scope: import("./types").ScopePolicy, options: RunOptions): Promise<ScanPlan> {
    const tools = (await this.tools()).filter((tool) => !this.config.disabledTools.includes(tool.id));
    return createPlan(target, profile, scope, options, tools);
  }

  /**
   * Records an agent-authored finding (manual exploitation, source review) on an
   * existing run so it flows through the same dedupe, pipeline and reports as
   * probe findings. Recording the same title/URL/target twice returns the first
   * finding, which makes retried tool calls idempotent.
   */
  async recordFinding(runId: string, draft: FindingDraft): Promise<Finding> {
    const handle = await this.store.load(runId);
    if (!handle) throw new Error(`Run not found: ${runId}`);
    const target = (draft.target ?? handle.record.target.display).trim().toLowerCase();
    const identity = (title: string, value: string) => `${title.trim().toLowerCase()}|${value.trim().toLowerCase()}`;
    const key = identity(draft.title, draft.url ?? target);
    const existing = handle.findings.find(
      (finding) => identity(finding.title, finding.url ?? finding.target.trim().toLowerCase()) === key,
    );
    if (existing) return existing;

    const finding: Finding = {
      id: newId("finding"),
      runId,
      title: draft.title,
      severity: draft.severity,
      category: draft.category,
      confidence: draft.confidence ?? "likely",
      target: draft.target ?? handle.record.target.display,
      url: draft.url,
      evidence: draft.evidence ?? "",
      description: draft.description ?? "No description provided.",
      remediation: draft.remediation ?? "Validate the finding and apply the relevant mitigation.",
      references: draft.references ?? [],
      cwe: draft.cwe,
      owasp: draft.owasp,
      cvss: draft.cvss,
      tool: draft.tool,
      timestamp: new Date().toISOString(),
      fingerprint: fingerprint([runId, draft.dedupeKey ?? key]),
      metadata: { ...(draft.metadata ?? {}), source: "agent" },
    };
    await this.store.appendFinding(runId, finding);
    handle.record.counts[finding.severity] += 1;
    await this.store.saveRun(handle.record);
    this.bus.emit({ type: "finding", runId, finding });
    return finding;
  }

  async run(request: RunRequest, hooks: import("./types").EngineHooks = {}): Promise<RunHandle> {
    const scopePath = resolve(expandHome(request.scopePath));
    const scope = await loadScopeFile(scopePath);
    const guard = new ScopeGuard(scope);
    guard.assertUsable();
    const profile = request.options.profile ?? this.config.defaultProfile;
    const target = guard.resolveTarget(request.target, profile);
    const options = this.normalizeOptions(request.options, scope, profile);
    const runId = newId("run");
    const createdAt = new Date().toISOString();
    const record: RunRecord = {
      id: runId,
      target,
      profile,
      scope,
      scopePath,
      options,
      status: "running",
      createdAt,
      startedAt: createdAt,
      counts: emptyCounts(),
      phaseSummary: [],
      dataDir: this.config.dataDir,
    };
    await this.store.init();
    await this.store.saveRun(record);

    const findings: Finding[] = [];
    const seen = new Map<string, Finding>();
    let findingWrites: Promise<void> = Promise.resolve();
    let eventWrites: Promise<void> = Promise.resolve();
    const unsubscribe = this.bus.subscribe((event) => {
      try {
        hooks.onEvent?.(event);
      } catch {
        // event consumers must not break a scan
      }
      eventWrites = eventWrites.then(() => this.store.appendEvent(runId, event)).catch(() => {});
    });

    const commit = (draft: FindingDraft): Finding => {
      const dedupeKey = draft.dedupeKey ?? fingerprint([draft.title, draft.target ?? target.display, draft.url]);
      if (!seen.has(dedupeKey)) {
        const finding: Finding = {
          id: newId("finding"),
          runId,
          title: draft.title,
          severity: draft.severity,
          category: draft.category,
          confidence: draft.confidence ?? "possible",
          target: draft.target ?? target.display,
          url: draft.url,
          evidence: draft.evidence ?? "",
          description: draft.description ?? "No description provided.",
          remediation: draft.remediation ?? "Validate the finding and apply the relevant vendor or framework mitigation.",
          references: draft.references ?? [],
          cwe: draft.cwe,
          owasp: draft.owasp,
          tool: draft.tool,
          timestamp: new Date().toISOString(),
          fingerprint: fingerprint([runId, dedupeKey]),
          metadata: draft.metadata,
        };
        findings.push(finding);
        seen.set(dedupeKey, finding);
        record.counts[finding.severity] += 1;
        findingWrites = findingWrites.then(() => this.store.appendFinding(runId, finding)).catch(() => {});
        this.bus.emit({ type: "finding", runId, finding });
        try {
          hooks.onFinding?.(finding);
        } catch {
          // finding consumers must not break a scan
        }
      }
      return seen.get(dedupeKey)!;
    };

    const abortController = new AbortController();
    const signal = hooks.signal ?? abortController.signal;
    const http = new HttpClient(guard, {
      timeoutMs: options.timeoutMs ?? this.config.timeoutMs,
      maxRps: options.maxRps ?? scope.maxRps ?? this.config.maxRps,
      userAgent: this.config.userAgent,
      maxRedirects: 5,
      maxBodyBytes: 2_000_000,
    });
    const runDir = this.store.runDir(runId);
    const ctx: import("./types").ProbeContext = {
      runId,
      target,
      scope,
      guard,
      options,
      http,
      guardRequest: async (fn) => fn(),
      addFindings: (drafts) => drafts.map(commit),
      emit: (event) => {
        this.bus.emit(event);
      },
      log: (level, message, source) => {
        this.bus.emit({ type: "log", runId, level, message, source });
      },
      signal,
      state: new Map(),
      dataDir: this.config.dataDir,
      runDir,
      workspace: target.path ?? process.cwd(),
    };

    this.bus.emit({ type: "run:start", runId, target, profile, at: createdAt });
    for (const warning of guard.validation.warnings) ctx.log("warn", warning, "scope");

    let status: "completed" | "failed" | "aborted" = "completed";
    let errorMessage: string | undefined;
    let plan: ScanPlan | undefined;
    const startedAt = Date.now();
    // Ruthless mode retries transient probe failures instead of silently skipping them.
    const retryBudget = Math.max(0, Math.min(5, Math.floor(options.retryFailedTasks ?? 0)));
    if (retryBudget > 0) ctx.log("info", `Retry policy: up to ${retryBudget} extra attempt(s) per probe`, "plan");

    try {
      const tools = (await this.tools()).filter((tool) => !this.config.disabledTools.includes(tool.id));
      plan = await createPlan(target, profile, scope, options, tools);
      for (const note of plan.notes) ctx.log("info", note, "plan");
      ctx.log("info", `Plan: ${plan.taskCount} tasks across ${plan.phases.length} phases`, "plan");

      for (const phase of plan.phases) {
        if (signal.aborted) {
          status = "aborted";
          break;
        }
        const phaseStart = Date.now();
        const phaseSummary: PhaseSummary = { id: phase.id, label: phase.label, status: "running" };
        record.phaseSummary.push(phaseSummary);
        this.bus.emit({ type: "phase:start", runId, phase: phase.id, label: phase.label });
        let failed = 0;
        for (const task of phase.tasks) {
          if (signal.aborted) {
            status = "aborted";
            break;
          }
          const taskStart = Date.now();
          this.bus.emit({ type: "task:start", runId, phase: phase.id, task: task.id, label: task.label });
          let taskStatus: TaskStatus = "done";
          let message: string | undefined;
          let attempt = 0;
          for (;;) {
            attempt += 1;
            try {
              const drafts = (await task.run(ctx)) ?? [];
              for (const draft of drafts) commit(draft);
              message = `${drafts.length} findings`;
              break;
            } catch (error) {
              const detail = error instanceof Error ? error.message : String(error);
              if (!signal.aborted && attempt <= retryBudget) {
                ctx.log(
                  "warn",
                  `${task.label}: attempt ${attempt}/${retryBudget + 1} failed — retrying (${detail})`,
                  task.id,
                );
                try {
                  await sleep(150 * attempt, signal);
                } catch {
                  taskStatus = "skipped";
                  message = "aborted";
                  break;
                }
                continue;
              }
              taskStatus = signal.aborted ? "skipped" : "failed";
              failed += 1;
              message = detail;
              ctx.log("warn", `${task.label}: ${detail}`, task.id);
              break;
            }
          }
          this.bus.emit({
            type: "task:end",
            runId,
            phase: phase.id,
            task: task.id,
            label: task.label,
            status: taskStatus,
            durationMs: Date.now() - taskStart,
            message,
          });
          if (signal.aborted) {
            status = "aborted";
            break;
          }
        }
        phaseSummary.status = status === "aborted" ? "skipped" : failed > 0 ? "failed" : "done";
        phaseSummary.durationMs = Date.now() - phaseStart;
        this.bus.emit({ type: "phase:end", runId, phase: phase.id, status: phaseSummary.status, durationMs: phaseSummary.durationMs });
        await this.store.saveRun(record);
        if (status === "aborted") break;
      }
      if (signal.aborted) status = "aborted";
    } catch (error) {
      status = "failed";
      errorMessage = error instanceof Error ? error.message : String(error);
      ctx.log("error", errorMessage, "engine");
    } finally {
      http.close();
    }

    const dependencyGraph = ctx.state.get("repo:dependencies");
    if (dependencyGraph) record.dependencies = dependencyGraph as import("./types").DependencyGraphSnapshot;
    record.status = status;
    record.finishedAt = new Date().toISOString();
    record.error = errorMessage;
    record.counts = emptyCounts();
    for (const finding of findings) record.counts[finding.severity] += 1;
    await this.store.saveRun(record);
    await findingWrites;
    await eventWrites;

    const handle: RunHandle = { record, findings: sortFindings(findings) };
    const formats = [...new Set<import("./types").ReportFormat>(options.exportFormats ?? ["markdown", "json", "sarif"])];
    try {
      const paths = await writeReports(this.store, handle, formats);
      for (const path of paths) this.bus.emit({ type: "log", runId, level: "info", message: `Report written: ${path}`, source: "report" });
      if (this.config.connectors.length > 0) {
        await runConnectors(this.config.connectors, handle, this.bus);
      }
    } catch (error) {
      this.bus.emit({ type: "log", runId, level: "warn", message: `Report generation failed: ${error instanceof Error ? error.message : String(error)}`, source: "report" });
    }

    this.bus.emit({
      type: "run:end",
      runId,
      status,
      durationMs: Date.now() - startedAt,
      counts: record.counts,
    });
    await eventWrites;
    unsubscribe();
    if (status === "failed" && errorMessage) throw new Error(errorMessage);
    return handle;
  }

  private normalizeOptions(options: RunOptions, scope: import("./types").ScopePolicy, profile: ProfileId): RunOptions {
    return {
      ...options,
      profile,
      maxRps: options.maxRps ?? scope.maxRps ?? this.config.maxRps,
      timeoutMs: options.timeoutMs ?? this.config.timeoutMs,
      concurrency: options.concurrency ?? this.config.concurrency,
      allowExternal: Boolean(scope.allowExternal) && options.allowExternal !== false,
      intrusive: Boolean(scope.allowIntrusive) && Boolean(options.intrusive),
      exportFormats: options.exportFormats ?? ["markdown", "json", "sarif"],
    };
  }
}
