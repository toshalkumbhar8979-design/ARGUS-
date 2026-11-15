import { describe, expect, test } from "bun:test";
import type { ArgusEvent } from "../src/core/events";
import type { Finding, Target } from "../src/core/types";
import {
  buildFindingDetail,
  createScanState,
  elapsedMs,
  formatElapsed,
  moveIndex,
  reduceScanEvent,
  scanProgress,
  windowed,
  wrapText,
} from "../src/tui/state";

const target: Target = {
  raw: "https://example.com",
  kind: "web",
  host: "example.com",
  scheme: "https",
  url: "https://example.com/",
  display: "https://example.com/",
};

const finding: Finding = {
  id: "finding-1",
  runId: "run-1",
  title: "Missing security headers",
  severity: "medium",
  category: "headers",
  confidence: "confirmed",
  target: "https://example.com/",
  url: "https://example.com/",
  evidence: "content-security-policy header is absent",
  description: "The response lacks a content security policy.",
  remediation: "Send a restrictive Content-Security-Policy header.",
  references: ["https://owasp.org/www-project-secure-headers/"],
  cwe: "CWE-693",
  tool: "native",
  timestamp: "2026-10-24T10:00:03.000Z",
  fingerprint: "abc123",
};

function fold(events: ArgusEvent[]) {
  return events.reduce(reduceScanEvent, createScanState());
}

describe("tui scan reducer", () => {
  test("folds run, phase, task and finding events into a view model", () => {
    const state = fold([
      { type: "run:start", runId: "run-1", target, profile: "web", at: "2026-10-24T10:00:00.000Z" },
      { type: "phase:start", runId: "run-1", phase: "recon", label: "Reconnaissance", at: "2026-10-24T10:00:00.100Z" },
      { type: "task:start", runId: "run-1", phase: "recon", task: "dns", label: "DNS records", at: "2026-10-24T10:00:00.200Z" },
      {
        type: "task:end",
        runId: "run-1",
        phase: "recon",
        task: "dns",
        label: "DNS records",
        status: "done",
        durationMs: 42,
        message: "0 findings",
        at: "2026-10-24T10:00:00.300Z",
      },
      { type: "finding", runId: "run-1", finding, at: "2026-10-24T10:00:03.000Z" },
      { type: "log", runId: "run-1", level: "warn", message: "scope expires soon", source: "scope", at: "2026-10-24T10:00:04.000Z" },
      {
        type: "run:end",
        runId: "run-1",
        status: "completed",
        durationMs: 5_000,
        counts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 },
        at: "2026-10-24T10:00:05.000Z",
      },
    ]);

    expect(state.runId).toBe("run-1");
    expect(state.status).toBe("completed");
    expect(state.phases).toHaveLength(1);
    expect(state.phases[0]?.label).toBe("Reconnaissance");
    expect(state.phases[0]?.tasks[0]?.status).toBe("done");
    expect(state.phases[0]?.tasks[0]?.durationMs).toBe(42);
    expect(state.findings).toHaveLength(1);
    expect(state.counts.medium).toBe(1);
    expect(state.logs.at(-1)?.level).toBe("warn");
    expect(scanProgress(state)).toMatchObject({ total: 1, done: 1, failed: 0 });
    expect(elapsedMs(state, Date.parse("2026-10-24T10:00:05.000Z"))).toBe(5_000);
  });

  test("ignores duplicate finding events", () => {
    const event: ArgusEvent = { type: "finding", runId: "run-1", finding, at: "2026-10-24T10:00:03.000Z" };
    const state = fold([event, event]);
    expect(state.findings).toHaveLength(1);
    expect(state.counts.medium).toBe(1);
  });

  test("marks the active task while a phase runs", () => {
    const state = fold([
      { type: "phase:start", runId: "run-1", phase: "audit", label: "Audit", at: "2026-10-24T10:00:00.000Z" },
      { type: "task:start", runId: "run-1", phase: "audit", task: "headers", label: "Security headers", at: "2026-10-24T10:00:00.100Z" },
    ]);
    const progress = scanProgress(state);
    expect(progress.total).toBe(1);
    expect(progress.task?.label).toBe("Security headers");
    expect(progress.phase?.id).toBe("audit");
  });
});

describe("tui helpers", () => {
  test("wraps text to width and hard-breaks long tokens", () => {
    expect(wrapText("alpha beta gamma", 10)).toEqual(["alpha beta", "gamma"]);
    expect(wrapText("abcdefghijkl", 5)).toEqual(["abcde", "fghij", "kl"]);
    expect(wrapText("one\n\ntwo", 20)).toEqual(["one", "", "two"]);
  });

  test("windows a list around the selection", () => {
    const items = Array.from({ length: 20 }, (_, index) => index);
    expect(windowed(items, 10, 5)).toEqual({ items: [8, 9, 10, 11, 12], offset: 8 });
    expect(windowed(items, 0, 5).offset).toBe(0);
    expect(windowed([1, 2], 1, 5)).toEqual({ items: [1, 2], offset: 0 });
  });

  test("formats elapsed time and wraps selection indices", () => {
    expect(formatElapsed(65_000)).toBe("01:05");
    expect(formatElapsed(3_665_000)).toBe("1:01:05");
    expect(moveIndex(0, -1, 3)).toBe(2);
    expect(moveIndex(2, 1, 3)).toBe(0);
    expect(moveIndex(0, 1, 0)).toBe(0);
  });

  test("builds a readable finding detail", () => {
    const lines = buildFindingDetail(finding, 48);
    const body = lines.join("\n");
    expect(body).toContain("EVIDENCE");
    expect(body).toContain("content-security-policy header is absent");
    expect(body).toContain("REMEDIATION");
    expect(body).toContain("CWE-693");
    expect(lines.every((line) => line.length <= 48)).toBe(true);
  });
});
