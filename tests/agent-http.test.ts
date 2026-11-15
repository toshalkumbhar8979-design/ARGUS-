import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createServer, type Server } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createEngineBackend } from "../src/core/agent";
import { defaultConfig } from "../src/core/config";
import { ArgusEngine } from "../src/core/engine";
import type { ScopePolicy } from "../src/core/types";

let temp: string | undefined;
let server: Server;
let target: string;

beforeAll(async () => {
  server = createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ method: request.method, path }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  target = `http://127.0.0.1:${address.port}/`;
});

afterEach(async () => {
  if (temp) await rm(temp, { recursive: true, force: true });
  temp = undefined;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

async function expectFailure(promise: Promise<unknown>, pattern: RegExp): Promise<void> {
  // Bun 1.4's expect(...).rejects can segfault later in the test process when
  // another test file opens a server, so assert the rejection manually.
  try {
    await promise;
  } catch (error) {
    expect(error instanceof Error ? error.message : String(error)).toMatch(pattern);
    return;
  }
  throw new Error(`expected a rejection matching ${pattern}`);
}

async function backendFor(allowActive: boolean, allowIntrusive: boolean) {
  temp = await mkdtemp(join(tmpdir(), "argus-http-"));
  const scope: ScopePolicy = {
    version: 1,
    name: "HTTP test",
    authorizedBy: "Security Team",
    authorizationRef: "TICKET-HTTP-1",
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    allow: [target],
    allowActive,
    allowIntrusive,
  };
  const scopePath = join(temp, "scope.json");
  await writeFile(scopePath, `${JSON.stringify(scope, null, 2)}\n`, "utf8");
  const config = { ...defaultConfig(), dataDir: temp };
  const backend = createEngineBackend(new ArgusEngine(config), config, scopePath, temp);
  return { backend, target };
}

describe("scoped HTTP agent tool", () => {
  test("returns status, headers and body for an in-scope request", async () => {
    const { backend, target } = await backendFor(true, false);
    const response = await backend.httpRequest!({ url: target, method: "GET" });
    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("application/json");
    expect(response.body).toContain('"method":"GET"');
    expect(response.bodyBytes).toBeGreaterThan(0);
  });

  test("allows POST with active scope but blocks intrusive methods without allowIntrusive", async () => {
    const { backend, target } = await backendFor(true, false);
    const posted = await backend.httpRequest!({ url: target, method: "POST", body: "x=1" });
    expect(posted.status).toBe(200);
    expect(posted.body).toContain('"method":"POST"');
    await expectFailure(backend.httpRequest!({ url: target, method: "PUT", body: "x=1" }), /allowIntrusive/);
  });

  test("blocks active methods when allowActive is false and rejects out-of-scope URLs", async () => {
    const { backend, target } = await backendFor(false, false);
    await expectFailure(backend.httpRequest!({ url: target, method: "POST", body: "x=1" }), /allowActive/);
    await expectFailure(backend.httpRequest!({ url: "https://outside.example/", method: "GET" }), /scope violation/);
  });

  test("rejects a GET body, newline headers and unsafe header names", async () => {
    const { backend, target } = await backendFor(true, false);
    await expectFailure(backend.httpRequest!({ url: target, method: "GET", body: "x=1" }), /does not accept a body/);
    await expectFailure(
      backend.httpRequest!({ url: target, method: "GET", headers: { "x-test": "ok\r\nx-evil: 1" } }),
      /contains a newline/,
    );
    await expectFailure(
      backend.httpRequest!({ url: target, method: "GET", headers: { "bad header": "x" } }),
      /invalid header name/,
    );
  });
});
