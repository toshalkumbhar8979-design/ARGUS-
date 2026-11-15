import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VectorMemory } from "../src/core/vectormemory";

let dir: string;
let file: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "argus-vector-"));
  file = join(dir, "memory.jsonl");
});

afterAll(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("vector memory", () => {
  test("ranks the related technique above unrelated notes", async () => {
    const memory = new VectorMemory(file);
    await memory.add({ text: "IDOR on /api/orders/{id}: swapping the path id returned another tenant's order", kind: "finding" });
    await memory.add({ text: "JWT alg none accepted: unsigned token with role admin reached the dashboard", kind: "finding" });
    await memory.add({ text: "Missing HSTS header on the marketing site", kind: "finding" });

    const matches = memory.search("jwt token alg none", 3);
    expect(matches[0]?.entry.text).toContain("JWT alg none");
    expect(matches[0]?.score).toBeGreaterThan(0);
    expect(matches[0]!.entry.id).toStartWith("mem-");
    const idor = memory.search("idor tenant order", 3);
    expect(idor[0]?.entry.text).toContain("IDOR on /api/orders");
    const headers = memory.search("missing hsts header", 3);
    expect(headers[0]?.entry.text).toContain("HSTS");
  });

  test("ignores duplicate text and empty input", async () => {
    const memory = new VectorMemory(join(dir, "dedupe.jsonl"));
    expect(await memory.add({ text: "SSRF through the webhook URL", kind: "finding" })).toBeDefined();
    expect(await memory.add({ text: "SSRF through the webhook URL", kind: "finding" })).toBeUndefined();
    expect(await memory.add({ text: "   ", kind: "finding" })).toBeUndefined();
    expect(memory.size).toBe(1);
  });

  test("persists entries and rebuilds the index on load", async () => {
    const fresh = new VectorMemory(join(dir, "persist.jsonl"));
    await fresh.add({ text: "Path traversal in the export filename reads outside the upload directory", kind: "finding" });
    const reloaded = new VectorMemory(join(dir, "persist.jsonl"));
    await reloaded.load();
    expect(reloaded.size).toBe(1);
    expect(reloaded.search("path traversal export filename")[0]?.entry.text).toContain("Path traversal");
  });

  test("empty and unrelated queries do not fabricate matches", () => {
    const memory = new VectorMemory(join(dir, "none.jsonl"));
    expect(memory.search("")).toEqual([]);
    expect(memory.search("quantum blockchain").length).toBe(0);
  });
});
