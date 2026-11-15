import type { Finding, ProfileId, RunStatus, SeverityCounts, Target, TaskStatus } from "./types";

export type EventLevel = "debug" | "info" | "warn" | "error";

export type ArgusEvent =
  | { type: "run:start"; runId: string; target: Target; profile: ProfileId; at: string }
  | { type: "phase:start"; runId: string; phase: string; label: string; at: string }
  | { type: "phase:end"; runId: string; phase: string; status: TaskStatus; durationMs: number; at: string }
  | { type: "task:start"; runId: string; phase: string; task: string; label: string; at: string }
  | { type: "task:end"; runId: string; phase: string; task: string; label: string; status: TaskStatus; durationMs: number; message?: string; at: string }
  | { type: "finding"; runId: string; finding: Finding; at: string }
  | { type: "log"; runId?: string; level: EventLevel; message: string; source?: string; at: string }
  | { type: "run:end"; runId: string; status: RunStatus; durationMs: number; counts: SeverityCounts; at: string }
  | { type: "tool:status"; runId?: string; tool: string; status: "detected" | "missing" | "running" | "done" | "skipped" | "failed"; message?: string; at: string }
  | { type: "mcp:status"; server: string; status: "connected" | "disconnected" | "error"; message?: string; at: string }
  | { type: "connector:status"; connector: string; status: "sent" | "failed" | "skipped"; message?: string; at: string };

type WithoutAt<T> = T extends unknown ? Omit<T, "at"> & { at?: string } : never;
export type ArgusEventInput = WithoutAt<ArgusEvent>;

export class EventBus {
  private listeners = new Set<(event: ArgusEvent) => void>();
  private history: ArgusEvent[] = [];
  private maxHistory: number;

  constructor(maxHistory = 2000) {
    this.maxHistory = maxHistory;
  }

  subscribe(listener: (event: ArgusEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit(event: ArgusEventInput): ArgusEvent {
    const complete = { ...event, at: event.at ?? new Date().toISOString() } as ArgusEvent;
    this.history.push(complete);
    if (this.history.length > this.maxHistory) this.history.splice(0, this.history.length - this.maxHistory);
    for (const listener of this.listeners) {
      try {
        listener(complete);
      } catch {
        // listeners must never break a scan
      }
    }
    return complete;
  }

  recent(limit = 100): ArgusEvent[] {
    return this.history.slice(-limit);
  }

  clear(): void {
    this.history = [];
  }
}

export function eventLine(event: ArgusEvent): string {
  switch (event.type) {
    case "run:start":
      return `RUN START ${event.profile} :: ${event.target.display}`;
    case "phase:start":
      return `PHASE ${event.label}`;
    case "phase:end":
      return `PHASE ${event.phase} ${event.status} (${event.durationMs}ms)`;
    case "task:start":
      return `  > ${event.label}`;
    case "task:end":
      return `  < ${event.label} ${event.status}${event.message ? ` — ${event.message}` : ""}`;
    case "finding":
      return `[${event.finding.severity.toUpperCase()}] ${event.finding.title}`;
    case "log":
      return `${event.level.toUpperCase()}${event.source ? `:${event.source}` : ""} ${event.message}`;
    case "run:end":
      return `RUN END ${event.status}`;
    case "tool:status":
      return `TOOL ${event.tool} ${event.status}${event.message ? ` — ${event.message}` : ""}`;
    case "mcp:status":
      return `MCP ${event.server} ${event.status}${event.message ? ` — ${event.message}` : ""}`;
    case "connector:status":
      return `CONNECTOR ${event.connector} ${event.status}${event.message ? ` — ${event.message}` : ""}`;
  }
}
