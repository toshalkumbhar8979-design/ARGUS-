import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ensurePromptScope,
  isGeneratedScope,
  parsePromptScopeSignal,
  promptScopePolicy,
} from "../src/core/prompt-scope";
import { validateScope } from "../src/core/scope";
import type { ScopePolicy } from "../src/core/types";

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "argus-prompt-scope-"));
}

function operatorScope(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    version: 1,
    name: "Operator scope",
    authorizedBy: "Security Team",
    authorizationRef: "ROE-42",
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    allow: ["https://example.com"],
    deny: [],
    allowedPorts: [443],
    allowActive: true,
    allowIntrusive: false,
    allowExternal: false,
    ...overrides,
  };
}

describe("prompt scope", () => {
  test("derives authorization from a plain target without a scope file", () => {
    const scope = promptScopePolicy("audit https://example.com for bugs");
    expect(scope).toBeDefined();
    expect(scope?.allow).toContain("example.com");
    expect(scope?.allow).toContain("*.example.com");
    expect(scope?.allowActive).toBe(true);
    expect(scope?.allowIntrusive).toBe(false);
    expect(scope?.allowExternal).toBe(true);
    expect(scope?.authorizationRef).toStartWith("PROMPT ");
    expect(validateScope(scope!).ok).toBe(true);
  });

  test("a bare domain authorizes its subdomains without editing a file", () => {
    const scope = promptScopePolicy("audit example.com for bugs");
    expect(scope?.allow).toContain("example.com");
    expect(scope?.allow).toContain("*.example.com");
    expect(validateScope(scope!).ok).toBe(true);
  });

  test("a later prompt naming a new host grows the derived scope", async () => {
    const dir = await tempDir();
    const path = join(dir, "scope.prompt.json");
    await writeFile(
      path,
      `${JSON.stringify(promptScopePolicy("audit example.com", { workspace: dir })!, null, 2)}\n`,
    );
    const ensured = await ensurePromptScope(path, "now check api.example.net", {
      workspace: dir,
      targets: ["api.example.net"],
      override: true,
    });
    expect(ensured.scope.allow).toContain("api.example.net");
    expect(ensured.scope.allow).toContain("example.com");
    await rm(dir, { recursive: true, force: true });
  });

  test("honors plain-English passive, intrusive and offline switches", () => {
    expect(promptScopePolicy("passive only: check example.com")?.allowActive).toBe(false);
    expect(promptScopePolicy("do a full aggressive assessment of example.com")?.allowIntrusive).toBe(true);
    expect(promptScopePolicy("inspect example.com offline, no external lookups")?.allowExternal).toBe(false);
    expect(promptScopePolicy("scan example.com and its subdomains")?.allow).toContain("*.example.com");
  });

  test("treats an existing local path as the workspace target", async () => {
    const root = await tempDir();
    try {
      const scope = promptScopePolicy(`check ${root} for bugs`, { targets: [root], workspace: root });
      expect(scope?.allow).toEqual([root]);
      expect(scope?.allowActive).toBe(false);
      expect(scope?.allowExternal).toBe(true);
      expect(validateScope(scope!).ok).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("creates a durable scope file and updates it as targets are added", async () => {
    const root = await tempDir();
    const path = join(root, "scope.json");
    try {
      const first = await ensurePromptScope(path, "audit one.example", { workspace: root });
      expect(first.created).toBe(true);
      expect(first.source).toBe("prompt");
      const saved = JSON.parse(await readFile(path, "utf8")) as ScopePolicy;
      expect(saved.allow).toContain("one.example");
      expect(isGeneratedScope(saved)).toBe(true);

      const second = await ensurePromptScope(path, "also audit two.example", { workspace: root });
      expect(second.path).toBe(path);
      expect(second.updated).toBe(true);
      expect(second.scope.allow).toContain("one.example");
      expect(second.scope.allow).toContain("two.example");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("never overwrites an operator-authored scope", async () => {
    const root = await tempDir();
    const path = join(root, "scope.json");
    const manual = operatorScope();
    await writeFile(path, `${JSON.stringify(manual, null, 2)}\n`, "utf8");
    try {
      const ensured = await ensurePromptScope(path, "audit other.example", { workspace: root });
      expect(ensured.source).toBe("prompt");
      expect(ensured.path).toBe(join(root, "scope.prompt.json"));
      expect(ensured.scope.allow).toContain("https://example.com");
      expect(ensured.scope.allow).toContain("other.example");
      const original = JSON.parse(await readFile(path, "utf8")) as ScopePolicy;
      expect(original.name).toBe("Operator scope");
      expect(original.allow).toEqual(["https://example.com"]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("parses explicit scope switches without magic flags", () => {
    const parsed = parsePromptScopeSignal("passive, no external, include subdomains, full");
    expect(parsed.passive).toBe(true);
    expect(parsed.external).toBe(false);
    expect(parsed.broad).toBe(true);
    expect(parsed.intrusive).toBe(true);
  });
});
