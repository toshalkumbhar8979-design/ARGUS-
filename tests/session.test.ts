import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isContinuation, resumeBanner, resumeCommand, SessionMemory } from "../src/core/session";

let temp: string;

beforeEach(async () => {
  temp = await mkdtemp(join(tmpdir(), "argus-session-"));
});

afterEach(async () => {
  await rm(temp, { recursive: true, force: true });
});

describe("session memory", () => {
  test("recognizes natural continue phrasing", () => {
    expect(isContinuation("continue")).toBe(true);
    expect(isContinuation("please keep going")).toBe(true);
    expect(isContinuation("review my resume parser")).toBe(false);
    expect(isContinuation("check example.com")).toBe(false);
  });

  test("the exit banner carries the session and its resume command", () => {
    const banner = resumeBanner("ses-abc123");
    expect(banner).toContain("ses-abc123");
    expect(banner).toContain("argus resume -session ses-abc123");
  });

  test("stores turns per workspace and formats a resumable context", async () => {
    const workspace = join(temp, "repo");
    const session = SessionMemory.forWorkspace(temp, workspace);
    await session.record({
      prompt: "scan the whole code base for bugs",
      summary: "Found one command injection candidate in the build script.",
      status: "ok",
      steps: 6,
      targets: [workspace],
      scans: ["run-1"],
      findings: [{ id: "finding-1", title: "Shell injection", severity: "high" }],
      gaps: ["could not verify the deployment wrapper"],
      nextSteps: ["trace the shell call", "check the wrapper"],
    });

    const turns = await session.load();
    expect(turns).toHaveLength(1);
    expect(turns[0]?.targets).toEqual([workspace]);

    const context = await session.formatForPrompt();
    expect(context).toContain("SESSION CONTEXT");
    expect(context).toContain("scan the whole code base");
    expect(context).toContain("Shell injection");
    expect(context).toContain("trace the shell call");
    expect(context).toContain("continue/resume");

    const raw = await readFile(session.path, "utf8");
    expect(raw).toContain("version");
    expect(raw).toContain("finding-1");
  });

  test("persists a stable id and finds the session by that id", async () => {
    const workspace = join(temp, "repo");
    await mkdir(workspace, { recursive: true });
    const session = SessionMemory.forWorkspace(temp, workspace);
    expect(session.id).toMatch(/^ses-[a-f0-9]{16}$/);
    await session.record({
      prompt: "scan the repository",
      summary: "No verified findings.",
      status: "ok",
      steps: 2,
      targets: [workspace],
      scans: [],
      findings: [],
      gaps: [],
      nextSteps: [],
    });

    const raw = JSON.parse(await readFile(session.path, "utf8")) as { id?: string; workspace?: string };
    expect(raw.id).toBe(session.id);
    expect(raw.workspace).toBe(workspace);

    const found = await SessionMemory.byId(temp, session.id);
    expect(found?.workspace).toBe(workspace);
    expect(found?.session.id).toBe(session.id);
    expect((await found?.session.load())?.[0]?.prompt).toBe("scan the repository");
    expect(await SessionMemory.byId(temp, "ses-does-not-exist")).toBeUndefined();
  });

  test("prints the resume command that finds the session again", async () => {
    const workspace = join(temp, "repo");
    await mkdir(workspace, { recursive: true });
    const session = SessionMemory.forWorkspace(temp, workspace);
    await session.record({
      prompt: "scan the repository",
      summary: "No verified findings.",
      status: "ok",
      steps: 1,
      targets: [workspace],
      scans: [],
      findings: [],
      gaps: [],
      nextSteps: [],
    });

    const command = resumeCommand(session.id);
    expect(command).toBe(`argus resume -session ${session.id}`);
    const printedId = command.split(" ").pop()!;
    expect((await SessionMemory.byId(temp, printedId))?.session.id).toBe(session.id);
  });

  test("redacts credentials before writing to disk", async () => {
    const session = SessionMemory.forWorkspace(temp, temp);
    await session.record({
      prompt: "audit with Bearer abcdefghijklmnop",
      summary: "the key ghp_abcdefghijklmnop was present",
      status: "ok",
      steps: 1,
      targets: [],
      scans: [],
      findings: [],
      gaps: [],
      nextSteps: [],
    });
    const raw = await readFile(session.path, "utf8");
    expect(raw).not.toContain("abcdefghijklmnop");
    expect(raw).not.toContain("ghp_abcdefghijklmnop");
  });

  test("keeps only the newest turns", async () => {
    const session = SessionMemory.forWorkspace(temp, temp);
    for (let index = 0; index < 12; index += 1) {
      await session.record({
        prompt: `turn ${index}`,
        summary: `summary ${index}`,
        status: "ok",
        steps: 1,
        targets: [],
        scans: [],
        findings: [],
        gaps: [],
        nextSteps: [],
      });
    }
    const turns = await session.load();
    expect(turns).toHaveLength(8);
    expect(turns[0]?.prompt).toBe("turn 4");
    expect(turns[7]?.prompt).toBe("turn 11");
  });
});
