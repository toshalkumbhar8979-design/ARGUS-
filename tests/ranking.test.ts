import { describe, expect, test } from "bun:test";
import type { Finding } from "../src/core/types";
import { findingRiskScore, rankFindings } from "../src/core/util";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "finding-1",
    runId: "run-1",
    title: "Missing header",
    severity: "low",
    category: "headers",
    confidence: "possible",
    target: "https://example.com/",
    evidence: "header absent",
    description: "A header is missing.",
    remediation: "Add the header.",
    references: [],
    tool: "native",
    timestamp: "2026-10-24T10:00:00.000Z",
    fingerprint: "fp",
    ...overrides,
  };
}

describe("finding risk ranking", () => {
  test("weights confirmed exploitability above possible severity noise", () => {
    const confirmedHigh = finding({
      id: "finding-high",
      title: "Authenticated command injection",
      severity: "high",
      category: "injection",
      confidence: "confirmed",
    });
    const possibleLow = finding({
      id: "finding-low",
      title: "Server banner",
      severity: "low",
      category: "exposure",
      confidence: "possible",
    });
    expect(findingRiskScore(confirmedHigh)).toBeGreaterThan(findingRiskScore(possibleLow));

    const ranked = rankFindings([possibleLow, confirmedHigh]);
    expect(ranked[0]?.id).toBe("finding-high");
    expect(ranked[1]?.id).toBe("finding-low");
  });

  test("does not mutate the stored severity or confidence", () => {
    const critical = finding({ severity: "critical", confidence: "possible" });
    const ranked = rankFindings([critical]);
    expect(ranked[0]?.severity).toBe("critical");
    expect(ranked[0]?.confidence).toBe("possible");
  });
});
