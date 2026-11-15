import { describe, expect, test } from "bun:test";
import { TrafficLog } from "../src/core/traffic";

function log(): TrafficLog {
  const traffic = new TrafficLog();
  traffic.record({ method: "GET", url: "https://example.com/", status: 200, statusText: "OK", bytes: 100, elapsedMs: 12 });
  traffic.record({ method: "GET", url: "https://example.com/login", status: 200, statusText: "OK", bytes: 200, elapsedMs: 20 });
  traffic.record({ method: "POST", url: "https://api.example.com/v1/orders", status: 401, statusText: "Unauthorized", bytes: 40, elapsedMs: 9, contentType: "application/json" });
  traffic.record({ method: "GET", url: "https://api.example.com/v1/orders/7", status: 403, statusText: "Forbidden", bytes: 30, elapsedMs: 8 });
  return traffic;
}

describe("traffic log", () => {
  test("records host and path from the request url", () => {
    const rows = log().list();
    expect(rows).toHaveLength(4);
    expect(rows[0]?.host).toBe("example.com");
    expect(rows[2]?.host).toBe("api.example.com");
    expect(rows[2]?.path).toBe("/v1/orders");
    expect(rows[0]?.id).toBe("req-1");
  });

  test("filters by host, status, method and text", () => {
    const traffic = log();
    expect(traffic.list({ host: "api.example.com" })).toHaveLength(2);
    expect(traffic.list({ status: 401 })).toHaveLength(1);
    expect(traffic.list({ method: "post" })).toHaveLength(1);
    expect(traffic.list({ contains: "/v1/orders" })).toHaveLength(2);
    expect(traffic.list({ host: "api.example.com", status: 200 })).toHaveLength(0);
  });

  test("returns the newest rows first when limited", () => {
    const rows = log().list({ limit: 2 });
    expect(rows.map((entry) => entry.status)).toEqual([401, 403]);
  });

  test("builds a per-host sitemap with methods and last status", () => {
    const map = log().sitemap();
    expect(map.map((host) => host.host)).toEqual(["api.example.com", "example.com"]);
    const api = map[0]!;
    expect(api.requests).toBe(2);
    expect(api.endpoints).toEqual([
      { path: "/v1/orders", methods: ["POST"], lastStatus: 401, count: 1 },
      { path: "/v1/orders/7", methods: ["GET"], lastStatus: 403, count: 1 },
    ]);
  });

  test("drops the oldest entries past the cap", () => {
    const traffic = new TrafficLog(2);
    for (const path of ["/a", "/b", "/c"]) {
      traffic.record({ method: "GET", url: `https://example.com${path}`, status: 200, statusText: "OK", bytes: 1, elapsedMs: 1 });
    }
    expect(traffic.size).toBe(2);
    expect(traffic.list().map((entry) => entry.path)).toEqual(["/b", "/c"]);
  });
});
