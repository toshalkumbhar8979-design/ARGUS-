import { describe, expect, test } from "bun:test";
import { createPlan } from "../src/core/planner";
import type { ScopePolicy, Target, ToolAvailability } from "../src/core/types";

function scope(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    version: 1,
    name: "Planner test",
    authorizedBy: "Security Team",
    authorizationRef: "TEST-ROE-PLAN",
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
    allow: ["https://example.com"],
    deny: [],
    allowedPorts: [80, 443],
    allowActive: true,
    allowIntrusive: false,
    allowExternal: false,
    ...overrides,
  };
}

function webTarget(): Target {
  return { raw: "https://example.com", kind: "web", host: "example.com", port: 443, scheme: "https", url: "https://example.com/", baseUrl: "https://example.com", display: "example.com" };
}

function fakeTool(id: string, binary: string, intrusive: boolean): ToolAvailability {
  return {
    id,
    name: id,
    category: "test",
    binary,
    installed: true,
    path: `C:\\tools\\${binary}.exe`,
    install: "test",
    intrusive,
    description: "test tool",
  };
}

describe("planner", () => {
  test("quick profile includes only baseline web checks", async () => {
    const plan = await createPlan(webTarget(), "quick", scope(), { profile: "quick" }, []);
    const ids = plan.phases.flatMap((phase) => phase.tasks.map((task) => task.id));
    expect(ids).toContain("web-baseline");
    expect(ids).toContain("web-headers");
    expect(ids).not.toContain("cors");
    expect(ids).not.toContain("exposures");
  });

  test("passive mode filters active tasks", async () => {
    const plan = await createPlan(webTarget(), "web", scope(), { profile: "web", passiveOnly: true }, []);
    const ids = plan.phases.flatMap((phase) => phase.tasks.map((task) => task.id));
    expect(ids).toContain("web-baseline");
    expect(ids).not.toContain("cors");
    expect(ids).not.toContain("methods");
    expect(ids).not.toContain("exposures");
  });

  test("disabled active scope filters active tasks", async () => {
    const plan = await createPlan(webTarget(), "web", scope({ allowActive: false }), { profile: "web" }, []);
    const ids = plan.phases.flatMap((phase) => phase.tasks.map((task) => task.id));
    expect(ids).not.toContain("cors");
    expect(ids).not.toContain("ports");
  });

  test("intrusive adapters require scope and run consent", async () => {
    const tools = [fakeTool("sqlmap", "sqlmap", true), fakeTool("nuclei", "nuclei", false)];
    const locked = await createPlan(webTarget(), "deep", scope(), { profile: "deep", intrusive: false }, tools);
    expect(locked.phases.flatMap((phase) => phase.tasks.map((task) => task.id))).not.toContain("ext-sqlmap");
    const unlocked = await createPlan(
      webTarget(),
      "deep",
      scope({ allowIntrusive: true }),
      { profile: "deep", intrusive: true },
      tools,
    );
    const ids = unlocked.phases.flatMap((phase) => phase.tasks.map((task) => task.id));
    expect(ids).toContain("ext-sqlmap");
    expect(ids).toContain("ext-nuclei");
  });

  test("repository targets always use repository probes", async () => {
    const target: Target = { raw: process.cwd(), kind: "repo", path: process.cwd(), display: process.cwd() };
    const plan = await createPlan(target, "quick", scope({ allow: [process.cwd()] }), { profile: "quick" }, []);
    const ids = plan.phases.flatMap((phase) => phase.tasks.map((task) => task.id));
    expect(ids).toContain("repo-secrets");
    expect(ids).toContain("repo-dependencies");
    expect(ids).toContain("repo-iac");
    expect(ids).toContain("repo-code");
  });
});
