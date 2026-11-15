import { describe, expect, test } from "bun:test";
import { buildPipeline, isConfirmedLpe, isExploitable, isValidated, renderPipelineMarkdown } from "../src/core/pipeline";
import type { Finding } from "../src/core/types";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "finding-1",
    runId: "run-1",
    title: "Missing CSP",
    severity: "medium",
    category: "misconfiguration",
    confidence: "confirmed",
    target: "https://example.com/",
    url: "https://example.com/",
    evidence: "content-security-policy absent",
    description: "No CSP.",
    remediation: "Add a restrictive Content-Security-Policy.",
    references: [],
    tool: "native",
    timestamp: "2026-10-24T10:00:00.000Z",
    fingerprint: "fp",
    ...overrides,
  };
}

describe("assessment pipeline", () => {
  test("validates only findings with evidence and more than 'possible' confidence", () => {
    expect(isValidated(finding({}))).toBe(true);
    expect(isValidated(finding({ confidence: "possible" }))).toBe(false);
    expect(isValidated(finding({ evidence: "  " }))).toBe(false);
    expect(isValidated(finding({ severity: "info" }))).toBe(false);
  });

  test("exploitability needs a validated, confirmed finding in an attack category", () => {
    expect(isExploitable(finding({ category: "injection", severity: "high" }))).toBe(true);
    expect(isExploitable(finding({ category: "injection", confidence: "likely" }))).toBe(false);
    expect(isExploitable(finding({ category: "misconfiguration", severity: "low" }))).toBe(false);
  });

  test("LPE detection is explicit, never assumed", () => {
    expect(isConfirmedLpe(finding({ category: "code", title: "Kernel LPE via io_uring", severity: "critical" }))).toBe(true);
    expect(isConfirmedLpe(finding({ category: "injection", title: "SQL injection", severity: "critical" }))).toBe(false);
  });

  test("candidate findings stop at discovery and are not counted as reports", () => {
    const pipeline = buildPipeline([
      finding({ id: "candidate", confidence: "possible" }),
      finding({ id: "valid", category: "injection", severity: "high" }),
    ]);
    expect(pipeline.stages[0]!.count).toBe(2);
    expect(pipeline.stages[1]!.count).toBe(1);
    expect(pipeline.stages[1]!.status).toBe("partial");
  });

  test("validated findings produce candidate patches and await human review", () => {
    const pipeline = buildPipeline([
      finding({ id: "a", remediation: "Add CSP." }),
      finding({ id: "b", remediation: "Add CSP." }),
      finding({ id: "c", remediation: "Set HSTS." }),
    ]);
    expect(pipeline.stages.find((stage) => stage.id === "patch")!.count).toBe(2);
    expect(pipeline.review.status).toBe("awaiting");
  });

  test("an empty run reports empty stages instead of simulated results", () => {
    const pipeline = buildPipeline([]);
    expect(pipeline.stages.every((stage) => stage.status === "empty")).toBe(true);
    expect(pipeline.concretePatches).toBe(0);
  });

  test("markdown rendering lists every stage in order", () => {
    const text = renderPipelineMarkdown(buildPipeline([finding({})])).join("\n");
    expect(text).toContain("Vulnerability discovery");
    expect(text).toContain("Dynamic validation");
    expect(text).toContain("Exploitability assessment");
    expect(text).toContain("Patch generation");
    expect(text).toContain("Human researchers");
    expect(text.indexOf("Vulnerability discovery")).toBeLessThan(text.indexOf("Human researchers"));
  });
});
