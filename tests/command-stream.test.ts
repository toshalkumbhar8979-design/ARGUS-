import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createEngineBackend } from "../src/core/agent";
import { defaultConfig } from "../src/core/config";
import { ArgusEngine } from "../src/core/engine";

let temp: string;

beforeAll(async () => {
  temp = await mkdtemp(join(tmpdir(), "argus-stream-"));
});

afterAll(async () => {
  if (temp) await rm(temp, { recursive: true, force: true });
});

describe("live command output", () => {
  test("forwards stdout and stderr chunks before the command finishes", async () => {
    const config = { ...defaultConfig(), dataDir: temp };
    const backend = createEngineBackend(new ArgusEngine(config), config, join(temp, "scope.json"), temp, [temp]);
    const chunks: Array<{ text: string; stream: "stdout" | "stderr" }> = [];
    const result = await backend.runCommand!(
      "printf 'first\\n'; sleep 0.1; printf 'second\\n'; printf 'oops\\n' >&2",
      {
        timeoutMs: 15_000,
        onOutput: (chunk, stream) => chunks.push({ text: chunk, stream }),
      },
    );
    const streamed = chunks.map((chunk) => chunk.text).join("");
    expect(result.exitCode).toBe(0);
    expect(streamed).toContain("first");
    expect(streamed).toContain("second");
    expect(chunks.some((chunk) => chunk.stream === "stderr" && chunk.text.includes("oops"))).toBe(true);
    // The complete output is still returned for the model.
    expect(result.stdout).toContain("second");
    expect(result.stderr).toContain("oops");
  });
});
