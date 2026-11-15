#!/usr/bin/env bun
import { createCliRenderer } from "@opentui/core";
import { createRoot } from "@opentui/react";
import { loadConfig } from "../core/config";
import { resumeBanner, SessionMemory } from "../core/session";
import { ArgusTui } from "./app";
import { hydrateCredentials } from "./credentials";

async function main(): Promise<void> {
  if (!process.stdout.isTTY) {
    process.stderr.write(
      "argus tui needs an interactive terminal.\n" +
        "For non-interactive use, run: argus scan <target>\n",
    );
    process.exit(1);
  }

  const config = await loadConfig();
  await hydrateCredentials(config.dataDir);
  const renderer = await createCliRenderer({
    exitOnCtrlC: false,
    targetFps: 30,
    useMouse: true,
    screenMode: "alternate-screen",
  });
  const root = createRoot(renderer);
  const fallbackSession = SessionMemory.forWorkspace(config.dataDir).id;
  let exiting = false;

  /**
   * Leaves the alternate screen, prints the command that reloads this
   * workspace's session, and returns to the operator's shell. Destroying the
   * renderer alone is not enough: the React tree keeps timers alive, so the
   * process has to exit explicitly.
   */
  const exit = (sessionId: string, code = 0): void => {
    if (exiting) return;
    exiting = true;
    try {
      root.unmount();
    } catch {
      // the tree may already be gone
    }
    try {
      renderer.destroy();
    } catch {
      // renderer may already be destroyed
    }
    const done = () => process.exit(code);
    // Written only after the renderer is gone, so it survives the alternate
    // screen and lands in the operator's shell where it can be copied.
    process.stdout.write(resumeBanner(sessionId || fallbackSession), done);
    // Never hang on a stalled write during teardown.
    setTimeout(done, 500);
  };

  // ctrl+c is handled by the TUI itself, but a signal that arrives while the
  // tree is tearing down must still restore the terminal.
  process.on("SIGINT", () => exit(fallbackSession));
  process.on("SIGTERM", () => exit(fallbackSession));

  root.render(<ArgusTui config={config} onExit={(info) => exit(info.sessionId)} />);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exit(1);
});
