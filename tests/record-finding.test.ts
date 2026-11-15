import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig } from "../src/core/config";
import { createEngineBackend } from "../src/core/agent";
import { ArgusEngine } from "../src/core/engine";
import { RunStore } from "../src/core/store";
import type { RunRecord } from "../src/core/types";

let dataDir: string;
let store: RunStore;
let engine: ArgusEngine;

const record: RunRecord = {
  id: "run-manual",
  target: {
    raw: "https://example.com",
    kind: "web",
    host: "example.com",
    scheme: "https",
    display: "https://example.com/",
  },
  profile: "web",
  scope: {
    version: 1,
    name: "manual",
    authorizedBy: "operator",
    authorizationRef: "T-1",
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    allow: ["example.com"],
    allowActive: true,
  },
  scopePath: "scope.json",
  options: { profile: "web" },
  status: "completed",
  createdAt: new Date().toISOString(),
  counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  phaseSummary: [],
  dataDir: "",
};

beforeAll(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "argus-record-"));
  store = new RunStore(dataDir);
  await store.init();
  record.dataDir = dataDir;
  await store.saveRun(record);
  engine = new ArgusEngine({ ...defaultConfig(), dataDir }, store);
});

afterAll(async () => {
  if (dataDir) await rm(dataDir, { recursive: true, force: true });
});

describe("agent-authored findings", () => {
  test("a recorded finding lands on the run with counts and an id", async () => {
    const finding = await engine.recordFinding("run-manual", {
      title: "IDOR on /api/orders/{id}",
      severity: "high",
      category: "access-control",
      confidence: "confirmed",
      evidence: "GET /api/orders/1002 returned another tenant's order for account 1001.",
      description: "Order lookup trusts the path id without an ownership check.",
      remediation: "Scope the query by the session user.",
      tool: "argus-agent",
    });

    expect(finding.id).toStartWith("finding-");
    expect(finding.runId).toBe("run-manual");
    expect(finding.confidence).toBe("confirmed");
    expect(finding.metadata?.source).toBe("agent");

    const handle = await store.load("run-manual");
    expect(handle?.findings.map((entry) => entry.id)).toContain(finding.id);
    expect(handle?.record.counts.high).toBe(1);
  });

  test("recording the same finding twice is idempotent", async () => {
    const first = await engine.recordFinding("run-manual", {
      title: "Reflected XSS in /search",
      severity: "medium",
      category: "injection",
      evidence: "q=<script>alert(1)</script> is reflected unescaped.",
      description: "Search reflects the query without encoding.",
      remediation: "Encode the query on output.",
      tool: "argus-agent",
    });
    const second = await engine.recordFinding("run-manual", {
      title: "Reflected XSS in /search",
      severity: "medium",
      category: "injection",
      evidence: "q=<script>alert(1)</script> is reflected unescaped.",
      description: "Search reflects the query without encoding.",
      remediation: "Encode the query on output.",
      tool: "argus-agent",
    });
    expect(second.id).toBe(first.id);
    const handle = await store.load("run-manual");
    expect(handle?.findings.filter((entry) => entry.title === "Reflected XSS in /search")).toHaveLength(1);
    expect(handle?.record.counts.medium).toBe(1);
  });

  test("a CVSS score is stored on the finding", async () => {
    const finding = await engine.recordFinding("run-manual", {
      title: "SQL injection in /api/products?sort=",
      severity: "critical",
      category: "injection",
      evidence: "sort=id) AND 1=1 returns all rows; sort=id) AND 1=2 returns none.",
      description: "The sort parameter is concatenated into the query.",
      remediation: "Use a parameterized query or an allow-list of sortable columns.",
      cwe: "CWE-89",
      cvss: { score: 9.8, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
      tool: "argus-agent",
    });
    expect(finding.cvss?.score).toBe(9.8);
    const handle = await store.load("run-manual");
    expect(handle?.findings.find((entry) => entry.id === finding.id)?.cvss?.vector).toContain("CVSS:3.1");
  });

  test("recorded findings are recallable through vector memory", async () => {
    const config = { ...defaultConfig(), dataDir };
    const backend = createEngineBackend(engine, config, join(dataDir, "scope.json"), process.cwd(), []);
    await backend.recordFinding!({
      title: "SSRF through the avatar import URL",
      severity: "high",
      category: "ssrf",
      evidence: "POST /avatar with url=http://127.0.0.1:8080/admin fetched the internal page.",
      description: "The importer fetches any URL, including loopback services.",
      remediation: "Allow-list schemes, hosts and ports; block loopback and metadata IPs.",
      runId: "run-manual",
    });
    const matches = await backend.recall!("webhook ssrf avatar url", 5);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0]?.text).toContain("SSRF");
    expect(matches[0]?.kind).toBe("finding");
  });

  test("an unknown run is rejected instead of writing nowhere", async () => {
    await expect(
      engine.recordFinding("run-missing", {
        title: "x",
        severity: "low",
        category: "code",
        evidence: "e",
        tool: "argus-agent",
      }),
    ).rejects.toThrow(/Run not found/);
  });
});
