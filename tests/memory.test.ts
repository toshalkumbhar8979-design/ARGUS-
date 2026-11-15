import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  appendProjectMemory,
  ensureProjectMemory,
  memoryForPrompt,
  memoryPath,
  pruneMemory,
  redactSecrets,
} from "../src/core/memory";

let temp: string;

beforeEach(async () => {
  temp = await mkdtemp(join(tmpdir(), "argus-memory-"));
  delete process.env.ARGUS_MEMORY;
});

afterEach(async () => {
  delete process.env.ARGUS_MEMORY;
  await rm(temp, { recursive: true, force: true });
});

describe("AGENTS.md memory", () => {
  test("creates the file on demand and never overwrites existing content", async () => {
    const path = await ensureProjectMemory(temp);
    expect(path).toBe(memoryPath(temp));
    const initial = await readFile(path, "utf8");
    expect(initial).toContain("# Project memory");
    expect(initial).toContain("## Argus memory");

    await writeFile(path, "# custom\n\nkeep me\n", "utf8");
    await ensureProjectMemory(temp);
    expect(await readFile(path, "utf8")).toContain("keep me");
  });

  test("appends dated entries and dedupes by run key", async () => {
    const first = await appendProjectMemory(temp, "- scans: run-1\n- findings: [high] XSS", {
      title: "1 finding",
      key: "runs:run-1",
    });
    expect(first.appended).toBe(true);

    const second = await appendProjectMemory(temp, "- scans: run-1\n- findings: [high] XSS", {
      title: "1 finding",
      key: "runs:run-1",
    });
    expect(second.appended).toBe(false);

    const content = await readFile(memoryPath(temp), "utf8");
    expect(content).toContain("### ");
    expect(content).toContain("runs:run-1");
    expect(content.match(/1 finding/g)?.length).toBe(1);
  });

  test("redacts credential-shaped strings", () => {
    expect(redactSecrets("key sk-abcdefghijk and Bearer abc.def.ghij")).toBe(
      "key [redacted] and Bearer [redacted]",
    );
    expect(redactSecrets("github ghp_abcdefghijk aws AKIAABCDEFGHIJKLMNOP")).toBe(
      "github [redacted] aws [redacted]",
    );
    expect(redactSecrets("nothing secret here")).toBe("nothing secret here");
  });

  test("serializes parallel appends so no note is lost", async () => {
    await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        appendProjectMemory(temp, `- parallel ${index}`, { title: `parallel ${index}` }),
      ),
    );
    const content = await readFile(memoryPath(temp), "utf8");
    for (let index = 0; index < 8; index += 1) {
      expect(content).toContain(`- parallel ${index}`);
    }
  });

  test("keeps the newest entries when the file grows", async () => {
    for (let index = 0; index < 30; index += 1) {
      await appendProjectMemory(temp, `- entry ${index}`, { title: `run ${index}` });
    }
    const content = await readFile(memoryPath(temp), "utf8");
    const headings = content.match(/^### /gm) ?? [];
    expect(headings.length).toBe(24);
    expect(content).toContain("entry 29");
    expect(content).toContain("entry 6");
    expect(content).not.toContain("entry 5");
  });

  test("prunes a large hand-written file without touching the header", () => {
    const entries = Array.from({ length: 28 }, (_, index) => `### entry ${index}\n- line`).join("\n\n");
    const content = `# Project memory\n\n## Argus memory\n\n${entries}\n`;
    const pruned = pruneMemory(content);
    expect(pruned.startsWith("# Project memory")).toBe(true);
    expect((pruned.match(/^### /gm) ?? []).length).toBe(24);
    expect(pruned).toContain("entry 27");
    expect(pruned).not.toContain("entry 3");
  });

  test("caps the prompt slice", async () => {
    await appendProjectMemory(temp, "- " + "x".repeat(20_000), { title: "huge" });
    const slice = await memoryForPrompt(temp, 600);
    expect(slice.length).toBeLessThanOrEqual(600);
  });

  test("does nothing when ARGUS_MEMORY is off", async () => {
    process.env.ARGUS_MEMORY = "off";
    const result = await appendProjectMemory(temp, "- should not exist", { title: "off" });
    expect(result.appended).toBe(false);
    expect(await readFile(memoryPath(temp), "utf8").catch(() => "")).toBe("");
  });
});
