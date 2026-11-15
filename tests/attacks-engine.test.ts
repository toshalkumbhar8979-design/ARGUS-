import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
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
      const host = request.headers.get("host") ?? "";
      if (url.pathname === "/report") {
        const month = url.searchParams.get("month") ?? "";
        if (/['"]/.test(month)) {
          return new Response("SQLSTATE[42000]: syntax error at or near", {
            status: 500,
            headers: { "content-type": "text/plain" },
          });
        }
        return new Response("<html><body>monthly report</body></html>", {
          headers: { "content-type": "text/html" },
        });
      }
      if (url.pathname === "/app.js") {
        return new Response('const region = "us-east-1"; const key = "AKIAQWERTYUIOPASDFGH";', {
          headers: { "content-type": "application/javascript" },
        });
      }
      if (url.pathname === "/" || url.pathname === "/login") {
        const query = [...url.searchParams.values()].join(" ");
        if (query.includes("etc/passwd")) {
          return new Response("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", {
            headers: { "content-type": "text/plain" },
          });
        }
        const arithmetic = /\$\(\(\((\d+)\)\*\((\d+)\)\)\)/.exec(query);
        if (arithmetic) {
          return new Response(String(Number(arithmetic[1]) * Number(arithmetic[2])), {
            headers: { "content-type": "text/plain" },
          });
        }
        if (query.includes("169.254.169.254")) {
          return new Response('{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","Token":"redacted"}', {
            headers: { "content-type": "application/json" },
          });
        }
        if (query.includes("'")) {
          return new Response("You have an error in your SQL syntax; check the manual for your MySQL server version", {
            status: 500,
            headers: { "content-type": "text/plain" },
          });
        }
        const injection =
          url.searchParams.get("next")?.includes("X-Argus-") ||
          (host && host !== `127.0.0.1:${server.port}`);
        return new Response(
          `<!doctype html><html><head><title>Argus active test</title></head><body>
            <a href="/download?file=readme.txt">Download</a>
            <a href="/fetch?url=http://example.com">Fetch</a>
            <a href="/report?month=2026-10">Monthly report</a>
            <form action="/login" method="GET"><input name="user" /><input name="pass" type="password" /></form>
            <script src="/app.js"></script>
            ${injection ? host : ""}
          </body></html>`,
          { headers: { "content-type": "text/html" } },
        );
      }
      return new Response("not found", { status: 404 });
    },
  });
  if (!server.port) throw new Error("Test server did not bind a port.");
  baseUrl = `http://127.0.0.1:${server.port}`;
  dataDir = await mkdtemp(join(tmpdir(), "argus-attacks-"));
  const scope: ScopePolicy = {
    version: 1,
    name: "Active probe integration",
    authorizedBy: "Security Team",
    authorizationRef: "TEST-ROE-ATTACKS",
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    allow: [baseUrl],
    deny: [],
    allowedPorts: [server.port],
    maxRps: 200,
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

describe("active web probes", () => {
  test("detects traversal, SQLi, command injection, SSRF, bundle secrets and login transport", async () => {
    const engine = new ArgusEngine({ ...defaultConfig(), dataDir, maxRps: 200, timeoutMs: 5_000 });
    const handle = await engine.run({
      target: baseUrl,
      scopePath,
      options: { profile: "api", allowExternal: false, exportFormats: ["json"] },
    });
    const titles = handle.findings.map((finding) => finding.title).join("\n");
    expect(titles).toContain("Path traversal in parameter");
    expect(titles).toContain("SQL injection in parameter");
    expect(titles).toContain("Command injection in parameter");
    expect(titles).toContain("Server-side request forgery in parameter");
    expect(titles).toContain("Secret exposed in client bundle");
    expect(titles).toContain("Login form submits credentials with GET");
  }, 30_000);

  test("attacks parameters discovered on a linked page, not just the entry URL", async () => {
    const engine = new ArgusEngine({ ...defaultConfig(), dataDir, maxRps: 200, timeoutMs: 5_000 });
    const handle = await engine.run({
      target: baseUrl,
      scopePath,
      options: { profile: "api", allowExternal: false, exportFormats: ["json"] },
    });
    // /report?month= never appears on the landing page's own query string; the
    // crawl has to find it, and the SQLi probe has to hit that endpoint.
    const hit = handle.findings.find(
      (finding) => finding.title.startsWith("SQL injection") && finding.url?.includes("/report"),
    );
    expect(hit).toBeDefined();
    expect(hit?.evidence).toContain("month");
  }, 30_000);
});
