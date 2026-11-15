import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { request as httpRequest } from "node:http";
import { InterceptProxy } from "../src/core/proxy";

let target: ReturnType<typeof Bun.serve>;
let proxy: InterceptProxy;
let proxyUrl: string;

function viaProxy(url: string, method = "GET", body?: string): Promise<{ status: number; body: string }> {
  return new Promise((done, fail) => {
    const request = httpRequest(
      {
        host: "127.0.0.1",
        port: Number(new URL(proxyUrl).port),
        path: url,
        method,
        headers: body ? { "content-type": "application/json", "content-length": Buffer.byteLength(body) } : {},
      },
      (response) => {
        let text = "";
        response.on("data", (chunk) => {
          text += chunk.toString();
        });
        response.on("end", () => done({ status: response.statusCode ?? 0, body: text }));
      },
    );
    request.on("error", fail);
    if (body) request.write(body);
    request.end();
  });
}

beforeAll(async () => {
  target = Bun.serve({
    port: 0,
    fetch(request) {
      const url = new URL(request.url);
      if (url.pathname === "/boom") return new Response("nope", { status: 500 });
      return Response.json({ path: url.pathname, method: request.method, query: url.search });
    },
  });
  proxy = new InterceptProxy();
  proxyUrl = (await proxy.start()).url;
});

afterAll(async () => {
  await proxy.stop();
  target.stop(true);
});

describe("intercepting proxy", () => {
  test("forwards a request and records it with a response preview", async () => {
    const response = await viaProxy(`http://127.0.0.1:${target.port}/hello?a=1`);
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body).path).toBe("/hello");

    const rows = proxy.history({ contains: "/hello" });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.method).toBe("GET");
    expect(rows[0]?.status).toBe(200);
    expect(rows[0]?.path).toBe("/hello?a=1");
    expect(rows[0]?.responsePreview).toContain("/hello");
  });

  test("records a 500 without treating it as a proxy failure", async () => {
    const response = await viaProxy(`http://127.0.0.1:${target.port}/boom`);
    expect(response.status).toBe(500);
    expect(proxy.history({ status: 500 })).toHaveLength(1);
  });

  test("holds a request, then forwards it when allowed", async () => {
    proxy.setIntercept(true);
    const pending = viaProxy(`http://127.0.0.1:${target.port}/held`, "POST", JSON.stringify({ a: 1 }));
    let held = proxy.pending();
    for (let attempt = 0; attempt < 50 && held.length === 0; attempt += 1) {
      await new Promise((done) => setTimeout(done, 20));
      held = proxy.pending();
    }
    expect(held).toHaveLength(1);
    expect(held[0]?.method).toBe("POST");
    expect(held[0]?.requestBody).toContain("\"a\":1");
    expect(proxy.allow(held[0]!.id)).toBe(true);
    const response = await pending;
    expect(response.status).toBe(200);
    proxy.setIntercept(false);
  });

  test("modifications are applied before forwarding", async () => {
    proxy.setIntercept(true);
    const pending = viaProxy(`http://127.0.0.1:${target.port}/original`);
    let held = proxy.pending();
    for (let attempt = 0; attempt < 50 && held.length === 0; attempt += 1) {
      await new Promise((done) => setTimeout(done, 20));
      held = proxy.pending();
    }
    const destination = `http://127.0.0.1:${target.port}/rewritten`;
    expect(proxy.allow(held[0]!.id, { url: destination })).toBe(true);
    const response = await pending;
    expect(JSON.parse(response.body).path).toBe("/rewritten");
    proxy.setIntercept(false);
  });

  test("drops a held request with 403", async () => {
    proxy.setIntercept(true);
    const pending = viaProxy(`http://127.0.0.1:${target.port}/drop-me`);
    let held = proxy.pending();
    for (let attempt = 0; attempt < 50 && held.length === 0; attempt += 1) {
      await new Promise((done) => setTimeout(done, 20));
      held = proxy.pending();
    }
    expect(proxy.drop(held[0]!.id)).toBe(true);
    const response = await pending;
    expect(response.status).toBe(403);
    expect(proxy.history({ status: 403 })).toHaveLength(1);
    proxy.setIntercept(false);
  });

  test("rejects a non-proxy request with a clear 400", async () => {
    const response = await new Promise<{ status: number; body: string }>((done, fail) => {
      const request = httpRequest(
        {
          host: "127.0.0.1",
          port: Number(new URL(proxyUrl).port),
          path: "/relative",
          method: "GET",
        },
        (res) => {
          let text = "";
          res.on("data", (chunk) => (text += chunk.toString()));
          res.on("end", () => done({ status: res.statusCode ?? 0, body: text }));
        },
      );
      request.on("error", fail);
      request.end();
    });
    expect(response.status).toBe(400);
    expect(response.body).toContain("absolute http://");
  });

  test("stops cleanly", async () => {
    expect(proxy.running).toBe(true);
    await proxy.stop();
    expect(proxy.running).toBe(false);
    await proxy.start(0);
    expect(proxy.running).toBe(true);
  });
});
