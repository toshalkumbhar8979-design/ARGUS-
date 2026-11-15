import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig, saveScopeFile } from "../src/core/config";
import { ArgusEngine } from "../src/core/engine";
import type { ScopePolicy } from "../src/core/types";

let server: ReturnType<typeof Bun.serve>;
let dataDir: string;
let scopePath: string;
let baseUrl: string;

beforeAll(async () => {
  server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const url = new URL(request.url);
      if (url.pathname === "/") {
        return new Response("<!doctype html><html><head><title>Argus Test</title></head><body><h1>Home</h1><a href='/app'>App</a></body></html>", {
          headers: { "content-type": "text/html", server: "argus-test" },
        });
      }
      if (url.pathname === "/app") {
        return new Response("application body", { status: 200, headers: { "content-type": "text/plain" } });
      }
      if (url.pathname === "/admin") {
        return new Response("restricted", { status: 401 });
      }
      return new Response("not found", { status: 404 });
    },
  });
  if (!server.port) throw new Error("Test server did not bind a port.");
  const port = server.port;
  baseUrl = `http://127.0.0.1:${port}`;
  dataDir = await mkdtemp(join(tmpdir(), "argus-engine-"));
  const scope: ScopePolicy = {
    version: 1,
    name: "Engine integration",
    authorizedBy: "Security Team",
    authorizationRef: "TEST-ROE-ENGINE",
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    allow: [baseUrl],
    deny: [],
    allowedPorts: [port],
    maxRps: 100,
    allowActive: true,
    allowIntrusive: false,
    allowExternal: false,
  };
  scopePath = join(dataDir, "scope.json");
  await saveScopeFile(scope, scopePath);
});

afterAll(async () => {
  server.stop(true);
  if (dataDir) await rm(dataDir, { recursive: true, force: true });
});

describe("engine integration", () => {
  test("runs a quick assessment, persists findings, and writes reports", async () => {
    const config = { ...defaultConfig(), dataDir, maxRps: 100, timeoutMs: 5000 };
    const engine = new ArgusEngine(config);
    const events: string[] = [];
    const handle = await engine.run(
      { target: baseUrl, scopePath, options: { profile: "quick", allowExternal: false, exportFormats: ["json", "markdown"] } },
      { onEvent: (event) => events.push(event.type) },
    );
    expect(handle.record.status).toBe("completed");
    expect(handle.record.id).toStartWith("run-");
    expect(handle.findings.length).toBeGreaterThan(0);
    const totalCounts = Object.values(handle.record.counts).reduce((sum, count) => sum + count, 0);
    expect(totalCounts).toBe(handle.findings.length);
    expect(events).toContain("run:start");
    expect(events).toContain("phase:start");
    expect(events).toContain("finding");
    expect(events).toContain("run:end");

    const runFiles = await readdir(join(dataDir, "runs", handle.record.id));
    expect(runFiles).toContain("run.json");
    expect(runFiles).toContain("findings.jsonl");
    expect(runFiles).toContain("events.jsonl");
    expect(runFiles).toContain("report.json");
    expect(runFiles).toContain("report.md");

    const loaded = await engine.store.load(handle.record.id);
    expect(loaded?.findings.length).toBe(handle.findings.length);
  });

  test("rejects an out-of-scope target before creating a run", async () => {
    const config = { ...defaultConfig(), dataDir, maxRps: 100 };
    const engine = new ArgusEngine(config);
    await expect(
      engine.run({ target: "http://127.0.0.1:1", scopePath, options: { profile: "quick" } }),
    ).rejects.toThrow(/Scope|outside|allowed/i);
  });
});
