import { describe, expect, test } from "bun:test";
import { applyLatestVersions, buildDependencyGraph, compareVersions } from "../src/core/dependencies";
import { buildFixPlan } from "../src/core/remediation";
import type { Finding } from "../src/core/types";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "finding-1",
    runId: "run-1",
    title: "Issue",
    severity: "medium",
    category: "code",
    confidence: "confirmed",
    target: "repo",
    evidence: "evidence",
    description: "description",
    remediation: "Apply the fix.",
    references: [],
    tool: "test",
    timestamp: "2026-10-24T10:00:00.000Z",
    fingerprint: "fp",
    ...overrides,
  };
}

describe("dependency graph", () => {
  test("resolves direct and transitive npm edges from bun.lock", () => {
    const graph = buildDependencyGraph([
      {
        relative: "package.json",
        content: JSON.stringify({ dependencies: { alpha: "^1.0.0", beta: "^2.0.0" } }),
      },
      {
        relative: "bun.lock",
        content: `{
          "lockfileVersion": 2,
          "workspaces": { "": { "dependencies": { "alpha": "^1.0.0", "beta": "^2.0.0" } } },
          "packages": {
            "alpha": ["alpha@1.0.0", "", { "dependencies": { "shared": "^1.2.0" } }],
            "beta": ["beta@2.0.0", "", {}],
            "shared": ["shared@1.2.0", "", {}],
          },
        }`,
      },
    ]);
    expect(graph.summary.nodes).toBe(3);
    expect(graph.summary.direct).toBe(2);
    expect(graph.summary.transitive).toBe(1);
    expect(graph.summary.edges).toBe(3);
    expect(graph.summary.packageManager).toBe("bun");
    expect(graph.edges.some((edge) => edge.from === "npm:alpha@1.0.0" && edge.to === "npm:shared@1.2.0")).toBe(true);
  });

  test("marks outdated direct dependencies without mutating transitive ones", () => {
    const graph = buildDependencyGraph([
      { relative: "package.json", content: JSON.stringify({ dependencies: { alpha: "1.0.0" } }) },
      {
        relative: "bun.lock",
        content: JSON.stringify({
          workspaces: { "": { dependencies: { alpha: "1.0.0" } } },
          packages: {
            alpha: ["alpha@1.0.0", "", { dependencies: { shared: "1.0.0" } }],
            shared: ["shared@1.0.0", "", {}],
          },
        }),
      },
    ]);
    applyLatestVersions(graph, new Map([["alpha", "1.1.0"], ["shared", "2.0.0"]]));
    expect(graph.summary.outdated).toBe(1);
    expect(graph.nodes.find((node) => node.name === "alpha")?.outdated).toBe(true);
    expect(graph.nodes.find((node) => node.name === "shared")?.outdated).toBeUndefined();
  });

  test("compares semantic versions and prereleases", () => {
    expect(compareVersions("1.2.3", "1.2.2")).toBe(1);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
    expect(compareVersions("1.2.3-beta.1", "1.2.3")).toBe(-1);
    expect(compareVersions("v2.0.0", "1.9.9")).toBe(1);
  });
});

describe("remediation plan", () => {
  test("groups shared fixes, prioritizes severity and drops inventory notes", () => {
    const plan = buildFixPlan([
      finding({ id: "1", title: "Header A", severity: "low", remediation: "Set the security headers." }),
      finding({ id: "2", title: "Header B", severity: "medium", remediation: "Set the security headers." }),
      finding({ id: "3", title: "SQL injection", severity: "critical", remediation: "Use parameterized queries." }),
      finding({
        id: "4",
        title: "Dependency inventory collected (external lookup skipped)",
        severity: "info",
        category: "supply-chain",
        remediation: "Enable external intelligence.",
      }),
    ]);
    expect(plan.length).toBe(2);
    expect(plan[0]?.priority).toBe("P1");
    expect(plan[0]?.remediation).toBe("Use parameterized queries.");
    expect(plan[1]?.count).toBe(2);
    expect(plan.some((action) => action.remediation.includes("Enable external"))).toBe(false);
  });
});
