import { afterAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ensureScratch, isScratchPath, scratchPath, SCRATCH_DIR_NAME } from "../src/core/scratch";

let temp: string;

afterAll(async () => {
  if (temp) await rm(temp, { recursive: true, force: true });
});

describe("scratch workspace", () => {
  test("creates argus-workspace inside the project, not next to it", async () => {
    temp = await mkdtemp(join(tmpdir(), "argus-scratch-"));
    const dir = await ensureScratch(temp);
    expect(dir).toBe(join(temp, SCRATCH_DIR_NAME));
    expect((await stat(dir)).isDirectory()).toBe(true);
    // Repeated calls are safe.
    expect(await ensureScratch(temp)).toBe(dir);
  });

  test("recognizes children but not lookalike siblings", async () => {
    expect(isScratchPath(temp, scratchPath(temp))).toBe(true);
    expect(isScratchPath(temp, join(scratchPath(temp), "recon", "scan.sh"))).toBe(true);
    expect(isScratchPath(temp, join(temp, "src"))).toBe(false);
    expect(isScratchPath(temp, `${scratchPath(temp)}-evil`)).toBe(false);
  });
});
