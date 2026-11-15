import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig, saveScopeFile } from "../src/core/config";
import { ArgusEngine } from "../src/core/engine";
import type { ScopePolicy } from "../src/core/types";

let root: string;
let repo: string;
let dataDir: string;
let scopePath: string;

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "argus-repo-"));
  repo = join(root, "app");
  dataDir = join(root, "data");
  await mkdir(join(repo, "src"), { recursive: true });
  await mkdir(join(repo, ".github", "workflows"), { recursive: true });
  await writeFile(join(repo, ".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=supersecretvalue123\n");
  await writeFile(
    join(repo, "package.json"),
    JSON.stringify({ name: "fixture", dependencies: { lodash: "4.17.20", express: "^4.18.2" } }, null, 2),
  );
  await writeFile(join(repo, "Dockerfile"), "FROM node:latest\nUSER root\nENV API_TOKEN=abcdef1234567890\nCOPY . .\n");
  await writeFile(
    join(repo, ".github", "workflows", "ci.yml"),
    "on: pull_request_target\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo \"${{ github.event.pull_request.title }}\"\n",
  );
  await writeFile(join(repo, "src", "app.js"), "const result = eval(req.query.code);\napp.use(cors({ origin: true }));\n");
  const scope: ScopePolicy = {
    version: 1,
    name: "Repo integration",
    authorizedBy: "Security Team",
    authorizationRef: "TEST-ROE-REPO",
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    allow: [repo],
    deny: [],
    maxRps: 20,
    allowActive: false,
    allowIntrusive: false,
    allowExternal: false,
  };
  scopePath = join(root, "scope.json");
  await saveScopeFile(scope, scopePath);
});

afterAll(async () => {
  if (root) await rm(root, { recursive: true, force: true });
});

describe("repository assessment", () => {
  test("finds secrets, IaC weaknesses, supply-chain inventory, and code patterns", async () => {
    const config = { ...defaultConfig(), dataDir, maxRps: 20 };
    const engine = new ArgusEngine(config);
    const handle = await engine.run({
      target: repo,
      scopePath,
      options: { profile: "repo", allowExternal: false, exportFormats: ["json"] },
    });
    expect(handle.record.status).toBe("completed");
    expect(handle.record.target.kind).toBe("repo");
    expect(handle.findings.length).toBeGreaterThan(5);
    const categories = new Set(handle.findings.map((finding) => finding.category));
    expect(categories.has("secrets")).toBe(true);
    expect(categories.has("iac")).toBe(true);
    expect(categories.has("supply-chain")).toBe(true);
    expect(categories.has("code")).toBe(true);
    expect(handle.findings.some((finding) => finding.title.includes(".env"))).toBe(true);
    expect(handle.findings.some((finding) => finding.title.toLowerCase().includes("docker"))).toBe(true);
    expect(handle.findings.some((finding) => finding.title.includes("eval"))).toBe(true);
  });

  test("duplicate IaC lines each carry their own real line index", async () => {
    const dir = await mkdtemp(join(tmpdir(), "argus-iac-lines-"));
    const repoDir = join(dir, "app");
    await mkdir(repoDir, { recursive: true });
    await writeFile(
      join(repoDir, "pod.yaml"),
      [
        "apiVersion: v1",
        "kind: Pod",
        "spec:",
        "  containers:",
        "    - name: one",
        "      securityContext:",
        "        privileged: true",
        "    - name: two",
        "      securityContext:",
        "        privileged: true",
        "",
      ].join("\n"),
    );
    const policy: ScopePolicy = {
      version: 1,
      name: "Duplicate line check",
      authorizedBy: "Security Team",
      authorizationRef: "TEST-ROE-DUP",
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      allow: [repoDir],
      deny: [],
      allowActive: false,
      allowIntrusive: false,
      allowExternal: false,
    };
    const policyPath = join(dir, "scope.json");
    await saveScopeFile(policy, policyPath);
    const engine = new ArgusEngine({ ...defaultConfig(), dataDir: join(dir, "data"), maxRps: 10 });
    try {
      const handle = await engine.run({
        target: repoDir,
        scopePath: policyPath,
        options: { profile: "repo", allowExternal: false, exportFormats: [] },
      });
      const hits = handle.findings.filter((finding) => finding.title.includes("Privileged Kubernetes"));
      expect(hits.map((finding) => finding.metadata?.line)).toEqual([7, 10]);
      expect(hits.map((finding) => finding.metadata?.source)).toEqual([
        "        privileged: true",
        "        privileged: true",
      ]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
