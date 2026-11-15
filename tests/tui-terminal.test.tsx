import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { acceptTerms } from "../src/core/authorization";
import { defaultConfig } from "../src/core/config";
import { detectWsl } from "../src/core/wsl";
import type { ArgusConfig, ScopePolicy } from "../src/core/types";
import { ArgusTui } from "../src/tui/app";

const scope: ScopePolicy = {
  version: 1,
  name: "Terminal test",
  authorizedBy: "Security Team",
  authorizationRef: "TICKET-TERM",
  expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
  allow: [],
  allowActive: true,
  allowIntrusive: false,
  allowExternal: false,
};

let setup: Awaited<ReturnType<typeof testRender>> | undefined;
let temp: string;
let config: ArgusConfig;
let scopePath: string;

beforeEach(async () => {
  temp = await mkdtemp(join(tmpdir(), "argus-tui-term-"));
  scopePath = join(temp, "scope.json");
  await writeFile(scopePath, `${JSON.stringify(scope, null, 2)}\n`, "utf8");
  process.env.ARGUS_CONFIG = join(temp, "argus.config.json");
  process.env.ARGUS_MEMORY = "off";
  config = { ...defaultConfig(), dataDir: temp };
  await acceptTerms(temp, "test suite");
});

afterEach(async () => {
  delete process.env.ARGUS_CONFIG;
  delete process.env.ARGUS_MEMORY;
  if (setup) {
    await setup.dispose();
    setup = undefined;
  }
  await rm(temp, { recursive: true, force: true });
});

async function waitFor(predicate: (frame: string) => boolean, timeoutMs = 15_000): Promise<string> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    await new Promise((resolve) => setTimeout(resolve, 120));
    await setup!.renderOnce();
    const frame = setup!.captureCharFrame();
    if (predicate(frame)) return frame;
  }
  throw new Error(`timed out:\n${setup!.captureCharFrame()}`);
}

describe("embedded terminal panel", () => {
  test("/vim opens a PTY and exiting vim returns to the transcript", async () => {
    const wsl = await detectWsl();
    if (process.platform !== "win32" || !wsl.kali) return;
    setup = await testRender(<ArgusTui config={config} initialScopePath={scopePath} />, {
      width: 100,
      height: 30,
      exitOnCtrlC: false,
    });
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = false;
    await waitFor((frame) => frame.includes("ARGUS"));
    setup.mockInput.typeText("/vim");
    await new Promise((resolve) => setTimeout(resolve, 80));
    await setup.renderOnce();
    setup.mockInput.pressEnter();
    await waitFor((frame) => frame.includes("TERMINAL"), 20_000);
    expect(setup.captureCharFrame()).toContain("exit the program");

    // Vim is focused; leave without saving, which ends the PTY and closes the panel.
    setup.mockInput.typeText(":q!");
    setup.mockInput.pressEnter();
    await waitFor((frame) => !frame.includes("TERMINAL"), 20_000);
    expect(setup.captureCharFrame()).toContain("terminal | exit 0");
  }, 45_000);
});
