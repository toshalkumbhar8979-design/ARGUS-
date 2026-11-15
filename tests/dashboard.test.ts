import { describe, expect, test } from "bun:test";
import { defaultConfig } from "../src/core/config";
import type { ArgusConfig, Finding } from "../src/core/types";
import { buildProviderGroups, buildModelRows, searchProviders, selectableModelRows } from "../src/tui/catalog";
import { PROVIDERS } from "../src/tui/providers";
import { bar, buildDashboard, riskGrade, riskScore, severityCounts } from "../src/tui/dashboard";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "finding-1",
    runId: "run-1",
    title: "Missing CSP",
    severity: "medium",
    category: "headers",
    confidence: "confirmed",
    target: "https://example.com/",
    url: "https://example.com/",
    evidence: "csp absent",
    description: "No CSP.",
    remediation: "Add CSP.",
    references: [],
    tool: "native",
    timestamp: "2026-10-24T10:00:00.000Z",
    fingerprint: "fp",
    ...overrides,
  };
}

const findings = [
  finding({ id: "finding-1", severity: "critical", title: "SQL injection", category: "injection" }),
  finding({ id: "finding-2", severity: "high", title: "Exposed .env", category: "secrets" }),
  finding({ id: "finding-3", severity: "medium", title: "Missing CSP" }),
  finding({ id: "finding-4", severity: "info", title: "Server banner", category: "exposure", confidence: "possible" }),
];

describe("dashboard metrics", () => {
  test("counts severities and weights confirmed findings above possible ones", () => {
    const counts = severityCounts(findings);
    expect(counts.critical).toBe(1);
    expect(counts.high).toBe(1);
    expect(counts.medium).toBe(1);
    expect(counts.info).toBe(1);
    expect(riskScore([finding({ severity: "critical", confidence: "confirmed" })])).toBeGreaterThan(
      riskScore([finding({ severity: "critical", confidence: "possible" })]),
    );
    expect(riskGrade(0).label).toBe("clean");
    expect(riskGrade(90).label).toBe("critical");
  });

  test("draws proportional block gauges with a minimum fill for non-zero values", () => {
    expect(bar(0, 10, 5)).toBe("░░░░░");
    expect(bar(5, 10, 4)).toBe("██░░");
    expect(bar(1, 1000, 4)).toBe("█░░░");
  });
});

describe("dashboard charts", () => {
  test("renders risk, severity, categories, coverage and findings", () => {
    const lines = buildDashboard(
      {
        target: "https://example.com/",
        profile: "deep",
        status: "completed",
        runId: "run-1",
        findings,
        phases: [
          {
            id: "audit",
            label: "Audit",
            status: "failed",
            durationMs: 1200,
            tasks: [
              { status: "done" },
              { status: "failed" },
            ],
          },
        ],
        elapsedMs: 2500,
      },
      96,
    );
    const text = lines.map((line) => line.text).join("\n");
    expect(text).toContain("RISK");
    expect(text).toContain("/100");
    expect(text).toContain("REMEDIATION");
    expect(text).toContain("SEVERITY");
    expect(text).toContain("CATEGORIES");
    expect(text).toContain("injection");
    expect(text).toContain("COVERAGE");
    expect(text).toContain("1/2");
    expect(text).toContain("FINDINGS");
    expect(text).toContain("SQL injection");
    expect(text).not.toContain("#");
    const injection = lines.find((line) => line.tag && line.text.includes("SQL injection"));
    expect(injection?.tag).toBe("CRIT");
    expect(injection?.tone).toBe("critical");
  });

  test("explains an empty run instead of drawing fake data", () => {
    const lines = buildDashboard({ target: "scope", status: "pending", findings: [], phases: [] }, 80);
    expect(lines.map((line) => line.text).join("\n")).toContain("clean pass");
  });

  test("shows dependency graph and outdated packages in a dedicated section", () => {
    const lines = buildDashboard(
      {
        target: "https://example.com/",
        findings,
        phases: [],
        dependencies: {
          manifests: ["package.json"],
          lockfiles: ["bun.lock"],
          nodes: [
            { key: "npm:react@19.3.1", name: "react", version: "19.3.1", ecosystem: "npm", direct: true, latest: "19.4.0", outdated: true },
            { key: "npm:scheduler@0.27.0", name: "scheduler", version: "0.27.0", ecosystem: "npm", direct: false },
          ],
          edges: [{ from: "root", to: "npm:react@19.3.1" }, { from: "npm:react@19.3.1", to: "npm:scheduler@0.27.0" }],
          summary: {
            nodes: 2,
            direct: 1,
            transitive: 1,
            edges: 2,
            outdated: 1,
            ecosystems: ["npm"],
            packageManager: "bun",
            latestCheck: "registry",
          },
          notes: [],
        },
      },
      96,
    );
    const text = lines.map((line) => line.text).join("\n");
    expect(text).toContain("DEPENDENCIES");
    expect(text).toContain("19.3.1 -> 19.4.0");
    expect(text).toContain("outdated");
    expect(text).toContain("GRAPH");
    expect(text).toContain("scheduler 0.27.0");
  });
});

describe("provider and model catalog", () => {
  const config: ArgusConfig = {
    ...defaultConfig(),
    llm: { enabled: true, providerId: "openai", baseUrl: "https://api.openai.com/v1", model: "gpt-4.1-mini", apiKeyEnv: "OPENAI_API_KEY" },
  };

  test("puts the active provider first and nests its models", () => {
    const groups = buildProviderGroups(config);
    expect(groups[0]?.provider.id).toBe("openai");
    expect(groups[0]?.active).toBe(true);
    expect(groups[0]?.activeModel).toBe("gpt-4.1-mini");
    expect(groups.find((group) => group.provider.id === "deepseek")?.models).toContain("deepseek-reasoner");

    const rows = buildModelRows(groups, "");
    const header = rows.find((row) => row.kind === "provider" && row.providerId === "openai");
    const model = rows.find((row) => row.kind === "model" && row.model === "gpt-4.1-mini");
    expect(header?.label).toBe("OpenAI");
    expect(header?.active).toBe(true);
    expect(model?.active).toBe(true);
    expect(selectableModelRows(rows).every((row) => row.kind === "model")).toBe(true);
  });

  test("filters by provider and by model while keeping group headers", () => {
    const groups = buildProviderGroups(config);
    const deepseek = buildModelRows(groups, "deepseek");
    expect(deepseek[0]?.kind).toBe("provider");
    expect(deepseek.some((row) => row.label === "DeepSeek")).toBe(true);
    expect(deepseek.some((row) => row.model === "deepseek-chat")).toBe(true);
    expect(deepseek.some((row) => row.providerId === "ollama")).toBe(true);
    expect(deepseek.some((row) => row.providerId === "groq")).toBe(false);

    const gpt = buildModelRows(groups, "gpt-4.1");
    expect(gpt.some((row) => row.model === "gpt-4.1")).toBe(true);
    expect(gpt.some((row) => row.model === "llama3.2")).toBe(false);
  });

  test("ranks a provider name match above a model-only match", () => {
    const results = searchProviders(PROVIDERS, "deepseek");
    expect(results[0]?.id).toBe("deepseek");
    expect(results.map((provider) => provider.id)).toContain("openrouter");
  });

  test("ships the NVIDIA NIM profile with model ids from its live catalog", () => {
    const nvidia = PROVIDERS.find((provider) => provider.id === "nvidia");
    expect(nvidia).toBeDefined();
    expect(nvidia?.label).toBe("NVIDIA NIM");
    expect(nvidia?.baseUrl).toBe("https://integrate.api.nvidia.com/v1");
    expect(nvidia?.apiKeyEnv).toBe("NVIDIA_API_KEY");
    expect(nvidia?.models).toContain("nvidia/nemotron-3-super-120b-a12b");
    expect(nvidia?.models).toContain("nvidia/nemotron-3.5-lightning-30b-a3b");
    expect(nvidia?.models).toContain("deepseek-ai/deepseek-v4.1-flash");
    expect(nvidia?.models.length).toBeGreaterThanOrEqual(10);
  });
});
