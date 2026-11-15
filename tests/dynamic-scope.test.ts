import { describe, expect, test } from "bun:test";
import { createEngineBackend, targetIsAllowed } from "../src/core/agent";

describe("dynamic target authorization", () => {
  test("a named host covers its URL, port and path forms", () => {
    expect(targetIsAllowed("https://example.com/login", ["example.com"])).toBe(true);
    expect(targetIsAllowed("example.com:8443", ["https://example.com"])).toBe(true);
    expect(targetIsAllowed("http://example.com/", ["example.com"])).toBe(true);
  });

  test("a named bare domain covers discovered subdomains", () => {
    expect(targetIsAllowed("https://api.example.com/v1", ["example.com"])).toBe(true);
    expect(targetIsAllowed("dev.internal.example.com", ["example.com"])).toBe(true);
  });

  test("unrelated hosts and lookalikes stay out", () => {
    expect(targetIsAllowed("https://evil.com", ["example.com"])).toBe(false);
    expect(targetIsAllowed("https://example.com.evil.com", ["example.com"])).toBe(false);
    expect(targetIsAllowed("https://notexample.com", ["example.com"])).toBe(false);
  });

  test("an IP target does not imply neighbouring IPs", () => {
    expect(targetIsAllowed("http://10.0.0.5:8080", ["10.0.0.5"])).toBe(true);
    expect(targetIsAllowed("http://10.0.0.6", ["10.0.0.5"])).toBe(false);
  });

  test("a local workspace still covers its own subdirectories", () => {
    const workspace = process.cwd();
    expect(targetIsAllowed(`${workspace}/src`, [workspace])).toBe(true);
  });

  test("an agent scan of a named host persists scope instead of refusing", async () => {
    const calls: string[] = [];
    const runs: Array<{ target: string; scopePath: string }> = [];
    const engine = {
      run: async (request: { target: string; scopePath: string }) => {
        runs.push(request);
        return { record: { id: "run-1" } } as never;
      },
    };
    const backend = createEngineBackend(engine as never, {} as never, "C:/tmp/scope.prompt.json", "C:/tmp/ws", [], {
      allowedTargets: ["example.com"],
      authorize: async (target) => {
        calls.push(target);
        return "C:/tmp/scope.prompt.json";
      },
    });
    await backend.scan({ target: "https://api.example.com/v1" } as never, {});
    // The named domain covers a discovered API host, without a scope edit.
    expect(calls).toEqual(["https://api.example.com/v1"]);
    expect(runs[0]?.scopePath).toBe("C:/tmp/scope.prompt.json");

    await backend.scan({ target: "https://api.example.com/v1" } as never, {});
    expect(calls).toHaveLength(1);

    await backend.scan({ target: "https://unrelated.test" } as never, {});
    expect(calls).toHaveLength(1);
  });
});
