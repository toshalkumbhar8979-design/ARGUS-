import { describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ensureLocalScope, localScopePolicy, validateScope, ScopeGuard, isCidr } from "../src/core/scope";
import type { ScopePolicy } from "../src/core/types";

function scope(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    version: 1,
    name: "Test engagement",
    authorizedBy: "Security Team",
    authorizationRef: "TEST-ROE-001",
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    allow: ["https://example.com", "*.example.org", "10.0.0.0/8"],
    deny: ["https://example.com/private"],
    allowedPorts: [80, 443, 8443],
    allowActive: true,
    allowIntrusive: false,
    allowExternal: false,
    ...overrides,
  };
}

describe("scope validation", () => {
  test("accepts a valid authorization", () => {
    const result = validateScope(scope());
    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test("rejects expired authorization", () => {
    const result = validateScope(scope({ expiresAt: new Date(Date.now() - 1000).toISOString() }));
    expect(result.ok).toBe(false);
    expect(result.expired).toBe(true);
  });

  test("rejects intrusive mode without active mode", () => {
    const result = validateScope(scope({ allowActive: false, allowIntrusive: true }));
    expect(result.ok).toBe(false);
    expect(result.errors.join(" ")).toContain("allowIntrusive requires allowActive=true");
  });
});

describe("scope guard", () => {
  test("allows in-scope URLs and blocks deny-listed paths", () => {
    const guard = new ScopeGuard(scope());
    expect(guard.checkUrl("https://example.com/products?id=1").allowed).toBe(true);
    expect(guard.checkUrl("https://example.com/private/delete").allowed).toBe(false);
    expect(guard.checkUrl("https://api.example.org/v1").allowed).toBe(true);
    expect(guard.checkUrl("https://example.net").allowed).toBe(false);
  });

  test("blocks cloud metadata endpoints", () => {
    const guard = new ScopeGuard(scope({ allow: ["http://169.254.169.254", "http://metadata.google.internal"] }));
    expect(guard.checkUrl("http://169.254.169.254/latest/meta-data").allowed).toBe(false);
    expect(guard.checkUrl("http://metadata.google.internal/computeMetadata/v1").allowed).toBe(false);
  });

  test("checks IPv4 CIDR containment correctly", () => {
    const guard = new ScopeGuard(scope({ allow: ["10.0.0.0/8"], deny: ["10.1.2.0/24"] }));
    expect(isCidr("10.0.0.0/8")).toBe(true);
    expect(guard.checkNetworkRange("10.20.0.0/16").allowed).toBe(true);
    expect(guard.checkNetworkRange("11.0.0.0/16").allowed).toBe(false);
    expect(guard.checkNetworkRange("10.1.2.128/25").allowed).toBe(false);
    expect(guard.checkNetworkRange("10.1.3.0/24").allowed).toBe(true);
  });

  test("rejects an allowed CIDR broader than the authorization", () => {
    const guard = new ScopeGuard(scope({ allow: ["10.1.0.0/16"] }));
    expect(guard.checkNetworkRange("10.0.0.0/8").allowed).toBe(false);
    expect(guard.checkNetworkRange("10.1.5.0/24").allowed).toBe(true);
  });

  test("enforces allowed ports", () => {
    const guard = new ScopeGuard(scope({ allow: ["https://example.com:9000"] }));
    expect(guard.checkPort(9000).allowed).toBe(false);
    expect(guard.checkPort(443).allowed).toBe(true);
  });

  test("creates a workspace-only scope for autonomous source review", async () => {
    const root = await mkdtemp(join(tmpdir(), "argus-auto-scope-"));
    const scopePath = join(root, "scope.json");
    const ensured = await ensureLocalScope(scopePath, root);
    expect(ensured.created).toBe(true);
    expect(ensured.scope.allow).toEqual([root]);
    expect(ensured.scope.allowActive).toBe(false);
    expect(ensured.scope.allowIntrusive).toBe(false);
    expect(ensured.scope.allowExternal).toBe(false);
    expect(validateScope(ensured.scope).ok).toBe(true);

    const guard = new ScopeGuard(ensured.scope);
    expect(guard.checkLocalPath(root).allowed).toBe(true);
    expect(guard.checkUrl("https://example.com").allowed).toBe(false);

    const saved = JSON.parse(await readFile(scopePath, "utf8")) as ScopePolicy;
    expect(saved.authorizationRef).toContain("no network");
    const again = await ensureLocalScope(scopePath, root);
    expect(again.created).toBe(false);
  });

  test("never overwrites an operator-authored scope", async () => {
    const root = await mkdtemp(join(tmpdir(), "argus-auto-scope-existing-"));
    const scopePath = join(root, "scope.json");
    await writeFile(scopePath, `${JSON.stringify(scope({ name: "Operator scope" }), null, 2)}\n`, "utf8");
    const ensured = await ensureLocalScope(scopePath, root);
    expect(ensured.created).toBe(false);
    expect(ensured.scope.name).toBe("Operator scope");
  });

  test("keeps the auto scope local-only even when handed a remote-shaped workspace", () => {
    const policy = localScopePolicy(process.cwd());
    expect(policy.allow).toHaveLength(1);
    expect(policy.allow?.[0]).not.toMatch(/^https?:/);
    expect(policy.allowActive).toBe(false);
  });

  test("checks repository paths", async () => {
    const root = await mkdtemp(join(tmpdir(), "argus-scope-"));
    const repo = join(root, "repo");
    await mkdir(repo);
    await writeFile(join(repo, "file.txt"), "hello");
    const guard = new ScopeGuard(scope({ allow: [repo] }));
    expect(guard.checkLocalPath(repo).allowed).toBe(true);
    expect(guard.checkLocalPath(join(root, "other")).allowed).toBe(false);
    expect(guard.resolveTarget(repo, "repo").kind).toBe("repo");
  });
});
