import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig } from "../src/core/config";
import { ArgusEngine } from "../src/core/engine";
import { AttackJournal } from "../src/core/journal";
import { generateReport, writeReports } from "../src/core/report";
import { RunStore } from "../src/core/store";
import type { RunRecord } from "../src/core/types";

let dataDir: string;
let store: RunStore;
let engine: ArgusEngine;

const record: RunRecord = {
  id: "run-research",
  target: {
    raw: "https://shop.example.com",
    kind: "web",
    host: "shop.example.com",
    scheme: "https",
    display: "https://shop.example.com/",
  },
  profile: "web",
  scope: {
    version: 1,
    name: "engagement",
    authorizedBy: "Security Team",
    authorizationRef: "ROE-7",
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    allow: ["shop.example.com"],
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
  dataDir = await mkdtemp(join(tmpdir(), "argus-research-"));
  store = new RunStore(dataDir);
  await store.init();
  record.dataDir = dataDir;
  await store.saveRun(record);
  engine = new ArgusEngine({ ...defaultConfig(), dataDir }, store);
  await engine.recordFinding("run-research", {
    title: "IDOR on /api/orders/{id}",
    severity: "high",
    category: "access-control",
    confidence: "confirmed",
    target: "https://shop.example.com",
    url: "https://shop.example.com/api/orders/1002",
    evidence: "GET /api/orders/1002 with account 1001's session returned tenant 1002's order.",
    description: "Order lookup trusts the path id without an ownership check.",
    remediation: "Scope the query by the session user and tenant.",
    cwe: "CWE-639",
    cvss: { score: 8.1, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" },
    tool: "argus-agent",
  });
});

afterAll(async () => {
  if (dataDir) await rm(dataDir, { recursive: true, force: true });
});

describe("research report", () => {
  test("renders the narrative deliverable from stored evidence", async () => {
    const handle = await store.load("run-research");
    expect(handle).not.toBeNull();
    const text = generateReport(handle!, "research");

    expect(text).toStartWith("# Research report:");
    for (const section of [
      "## Executive summary",
      "## Engagement facts",
      "## Method and validation state",
      "## Findings",
      "## Coverage and next steps",
      "## Appendix: finding index",
    ]) {
      expect(text).toContain(section);
    }
    expect(text).toContain("IDOR on /api/orders/{id}");
    expect(text).toContain("CVSS: 8.1");
    expect(text).toContain("CWE-639");
    expect(text).toContain("Confidence: confirmed");
    expect(text).toContain("ROE-7");
    expect(text).toContain("absence of a finding is not absence of a vulnerability");
  });

  test("appends the automatic attack journal with tools and surfaces", async () => {
    const handle = await store.load("run-research");
    const journal = new AttackJournal();
    journal.record({ tool: "http_request", target: "https://shop.example.com/api/orders/1002", ok: true });
    journal.record({ tool: "wsl", target: "sqlmap -u https://shop.example.com/item?id=1", ok: true });
    journal.record({ tool: "http_request", target: "https://shop.example.com/admin", ok: false, detail: "403" });
    const text = generateReport(handle!, "research", { journal: journal.toMarkdown() });
    expect(text).toContain("## Attack journal");
    expect(text).toContain("`http_request` x2");
    expect(text).toContain("### Surfaces and packages touched");
    expect(text).toContain("sqlmap -u https://shop.example.com/item?id=1");
    expect(text).toContain("failed");
  });

  test("writes report.research.md as an artifact", async () => {
    const handle = await store.load("run-research");
    const paths = await writeReports(store, handle!, ["research"]);
    expect(paths).toHaveLength(1);
    expect(paths[0]).toEndWith("report.research.md");
  });

  test("research output only contains recorded findings", async () => {
    const handle = await store.load("run-research");
    await engine.recordFinding("run-research", {
      title: "Reflected XSS in /search",
      severity: "medium",
      category: "injection",
      evidence: "q=<b>argus</b> is reflected unencoded in the results page.",
      description: "The search page reflects the query without encoding.",
      remediation: "Encode output and add a CSP.",
      tool: "argus-agent",
    });
    const refreshed = await store.load("run-research");
    const text = generateReport(refreshed!, "research");
    expect(text).toContain("Reflected XSS in /search");
    expect(text).toContain("2 finding(s) were recorded");
    expect(text).not.toContain("payment bypass");
  });
});
