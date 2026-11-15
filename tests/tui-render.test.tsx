import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testRender } from "@opentui/react/test-utils";
import { acceptTerms } from "../src/core/authorization";
import { defaultConfig } from "../src/core/config";
import { RunStore } from "../src/core/store";
import type { ArgusConfig, Finding, RunRecord, ScopePolicy } from "../src/core/types";
import { ArgusTui } from "../src/tui/app";
import { ConnectModal } from "../src/tui/modals";

const scope: ScopePolicy = {
  version: 1,
  name: "Test authorization",
  authorizedBy: "Security Team",
  authorizationRef: "TICKET-42",
  expiresAt: new Date(Date.now() + 5 * 86_400_000).toISOString(),
  allow: ["https://example.com"],
  allowActive: true,
  allowIntrusive: false,
  allowExternal: false,
};

let setup: Awaited<ReturnType<typeof testRender>> | undefined;
let temp: string;
let scopePath: string;
let config: ArgusConfig;

beforeEach(async () => {
  temp = await mkdtemp(join(tmpdir(), "argus-tui-"));
  scopePath = join(temp, "scope.json");
  await writeFile(scopePath, `${JSON.stringify(scope, null, 2)}\n`, "utf8");
  process.env.ARGUS_CONFIG = join(temp, "argus.config.json");
  process.env.ARGUS_MEMORY = "off";
  process.env.ARGUS_CLIPBOARD = "off";
  config = { ...defaultConfig(), dataDir: temp };
  // The suite simulates an operator who has accepted the authorized-use agreement.
  await acceptTerms(temp, "test suite");
});

afterEach(async () => {
  delete process.env.ARGUS_CONFIG;
  delete process.env.ARGUS_MEMORY;
  delete process.env.ARGUS_CLIPBOARD;
  if (setup) {
    await setup.dispose();
    setup = undefined;
  }
  await rm(temp, { recursive: true, force: true });
});

async function type(text: string): Promise<void> {
  await setup!.mockInput.typeText(text);
  await setup!.renderOnce();
}

async function start(
  custom: ArgusConfig = config,
  path: string = scopePath,
  size: { width: number; height: number } = { width: 100, height: 30 },
): Promise<void> {
  setup = await testRender(<ArgusTui config={custom} initialScopePath={path} />, {
    width: size.width,
    height: size.height,
    exitOnCtrlC: false,
  });
  // OpenTUI drives updates from its own render loop, not React DOM.
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = false;
  await setup.waitForFrame((value) => value.includes("ARGUS"));
}

async function settle(ms = 80): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
  await setup!.renderOnce();
}

async function waitForText(text: string, timeoutMs = 20_000): Promise<string> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    await settle(120);
    const frame = setup!.captureCharFrame();
    if (frame.includes(text)) return frame;
  }
  throw new Error(`timed out waiting for "${text}":\n${setup!.captureCharFrame()}`);
}

async function waitForAnyText(labels: string[], timeoutMs = 15_000): Promise<string> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    await settle(120);
    const frame = setup!.captureCharFrame();
    if (labels.some((label) => frame.includes(label))) return frame;
  }
  throw new Error(`timed out waiting for any of ${labels.join(", ")}:\n${setup!.captureCharFrame()}`);
}

/** A tiny local checkout, so an authorized pass stays off the network. */
async function sampleTarget(): Promise<string> {
  const dir = join(temp, "fixtures");
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, "app.js"),
    "export function read(path) { return execSync(`cat ${path}`); }\n",
    "utf8",
  );
  return dir;
}

describe("prompt-driven tui", () => {
  test("starts with a transcript, provider header and scope summary", async () => {
    await start();
    const frame = setup!.captureCharFrame();
    expect(frame).toContain("authorized security assessment");
    expect(frame).toContain("OpenAI");
    expect(frame).toContain("gpt-4.1-mini");

    const withScope = await setup!.waitForFrame((value) => value.includes("Test authorization"));
    expect(withScope).toContain("TICKET-42");
  });

  test("a wide terminal keeps one masthead, status line and prompt column", async () => {
    await start(config, scopePath, { width: 140, height: 34 });
    const frame = setup!.captureCharFrame();
    expect(frame).toContain("▌ ARGUS");
    expect(frame).toContain("security assessment");
    expect(frame).toContain("Test authorization");
    expect(frame).toContain("❯");
    expect(frame).toContain("ready");
    expect(frame).toContain("name a target");
  });

  test("typing slash opens the command menu and enter opens the provider modal", async () => {
    await start();
    await type("/");
    await settle(40);
    let frame = setup!.captureCharFrame();
    expect(frame).toContain("/providers");
    expect(frame).toContain("/models");
    expect(frame).toContain("/connect");
    expect(frame).toContain("/key");
    expect(frame).toContain("/dashboard");

    await type("providers");
    await settle(20);
    setup!.mockInput.pressEnter();
    await settle(60);

    frame = await setup!.waitForFrame((value) => value.includes("Providers"));
    expect(frame).toContain("OpenAI");
    expect(frame).toContain("Ollama (local)");
    expect(frame).toContain("enter use");

    setup!.mockInput.pressEscape();
    await settle(80);
    expect(setup!.captureCharFrame()).not.toContain("Ollama (local)");
  });

  test("models modal lists the endpoint and selects a model", async () => {
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === "/v1/models") return Response.json({ data: [{ id: "alpha" }, { id: "beta" }] });
        return new Response("missing", { status: 404 });
      },
    });
    try {
      await start({
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      });
      await type("/models");
      setup!.mockInput.pressEnter();
      await settle(150);

      const frame = setup!.captureCharFrame();
      expect(frame).toContain("Models");
      expect(frame).toContain("Custom endpoint");
      expect(frame).toContain("beta");

      setup!.mockInput.pressArrow("down");
      await settle(30);
      setup!.mockInput.pressEnter();
      await settle(120);
      const done = setup!.captureCharFrame();
      expect(done).toContain("+ model | beta");
      expect(done).toContain("Custom endpoint · beta");
    } finally {
      server.stop(true);
    }
  });

  test("models modal shows the known catalog when live discovery fails", async () => {
    await start({
      ...config,
      llm: {
        enabled: true,
        providerId: "ollama",
        baseUrl: "http://127.0.0.1:1/v1",
        model: "llama3.2",
        apiKeyEnv: "",
      },
    });
    await type("/models");
    setup!.mockInput.pressEnter();
    const frame = await setup!.waitForFrame((value) => value.includes("Models") && value.includes("llama3.2"));
    expect(frame).toContain("Ollama (local)");
    expect(frame).toContain("qwen2.5-coder");
  });

  test("activating a provider also picks a model it serves", async () => {
    process.env.GROQ_API_KEY = "gsk-test";
    try {
      await start({
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: "http://127.0.0.1:1/v1",
          model: "alpha",
          apiKeyEnv: "",
        },
      });
      await type("/connect");
      setup!.mockInput.pressEnter();
      await setup!.waitForFrame((value) => value.includes("Connections"));
      await type("groq");
      await setup!.waitForFrame((value) => value.includes("provider | Groq"));
      await settle(20);
      setup!.mockInput.pressEnter();
      await settle(200);
      const frame = await setup!.waitForFrame(
        (value) => value.includes("+ provider | Groq") && value.includes("- model | llama-3.3-70b-versatile"),
      );
      expect(frame).toContain("key from GROQ_API_KEY");
    } finally {
      delete process.env.GROQ_API_KEY;
    }
  });

  test("connect modal lists and searches providers, models and MCP servers", async () => {
    await start();
    await type("/connect");
    setup!.mockInput.pressEnter();
    await settle(60);

    const frame = await setup!.waitForFrame((value) => value.includes("Connections"));
    expect(frame).toContain("provider | OpenAI (active)");
    expect(frame).toContain("provider | DeepSeek");
    expect(frame).toContain("no MCP servers configured");
    expect(frame).toContain("enter use/add key");

    await type("deepseek");
    await settle(60);
    const filtered = setup!.captureCharFrame();
    expect(filtered).toContain("provider | DeepSeek");
    expect(filtered).not.toContain("provider | Groq");

    setup!.mockInput.pressEnter();
    await settle(150);
    const detail = await setup!.waitForFrame((value) => value.includes("paste your") && value.includes("deepseek-chat"));
    expect(detail).toContain("DeepSeek");
    expect(detail).toContain("DEEPSEEK_API_KEY");
    expect(detail).toContain("deepseek-reasoner");
  });

  test("/key goes straight to key entry for the named provider", async () => {
    await start();
    await type("/key nvidia");
    setup!.mockInput.pressEnter();
    const frame = await setup!.waitForFrame(
      (value) => value.includes("NVIDIA NIM") && value.includes("NVIDIA_API_KEY") && value.includes("paste your"),
    );
    expect(frame).toContain("enter save & activate");
    expect(frame).toContain("build.nvidia.com");
  });

  test("/key saves an API key and activates the provider in one step", async () => {
    try {
      await start({
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: "http://127.0.0.1:1/v1",
          model: "alpha",
          apiKeyEnv: "ARGUS_TEST_KEY",
        },
      });
      await type("/key");
      setup!.mockInput.pressEnter();
      const detail = await setup!.waitForFrame(
        (value) => value.includes("Custom endpoint") && value.includes("ARGUS_TEST_KEY") && value.includes("paste your"),
      );
      expect(detail).toContain("enter save & activate");

      setup!.mockInput.typeText("sk-test-123");
      await settle(30);
      setup!.mockInput.pressEnter();
      await settle(200);
      const saved = await setup!.waitForFrame(
        (value) => value.includes("key saved") && value.includes("+ provider | Custom endpoint"),
      );
      expect(saved).not.toContain("paste your ARGUS_TEST_KEY");

      const stored = JSON.parse(await readFile(join(temp, "credentials.json"), "utf8")) as Record<string, string>;
      expect(stored.ARGUS_TEST_KEY).toBe("sk-test-123");
      expect(process.env.ARGUS_TEST_KEY).toBe("sk-test-123");
    } finally {
      delete process.env.ARGUS_TEST_KEY;
    }
  });

  test("connect key entry accepts ctrl+v from the clipboard", async () => {
    const custom: ArgusConfig = {
      ...config,
      llm: {
        enabled: true,
        providerId: "custom",
        baseUrl: "http://127.0.0.1:1/v1",
        model: "alpha",
        apiKeyEnv: "ARGUS_TEST_KEY",
      },
    };
    setup = await testRender(
      <ConnectModal
        config={custom}
        initialKeyFor="custom"
        startInKey
        readClipboard={async () => "sk-pasted-456"}
        onApply={() => {}}
        onClose={() => {}}
        onHint={() => {}}
      />,
      { width: 100, height: 30, exitOnCtrlC: false },
    );
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = false;
    const detail = await setup.waitForFrame(
      (value) => value.includes("ARGUS_TEST_KEY") && value.includes("paste your"),
    );
    expect(detail).toContain("ctrl+v");

    setup.mockInput.pressKey("v", { ctrl: true });
    const frame = await waitForText("pasted 13 chars");
    expect(frame).toContain("enter saves");
  });

  test("shows a plain prose model answer instead of dead-ending", async () => {
    const prose =
      "I inspected the target and found no exploitable issues. The response headers are present and no secret is exposed. " +
      "The authentication flow uses signed sessions and rejects malformed input.";
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === "/v1/chat/completions") {
          return Response.json({ choices: [{ message: { content: prose } }] });
        }
        return new Response("missing", { status: 404 });
      },
    });
    try {
      await start({
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      });
      await type("audit https://example.com");
      setup!.mockInput.pressEnter();
      await waitForText("model replied in prose", 5_000);
      const frame = setup!.captureCharFrame();
      expect(frame).toContain("I inspected the target");
      // A text answer with no tool call is normal under native tool calling.
      expect(frame).not.toContain("reply was not agent JSON");
      expect(frame).toContain("model replied in prose");
    } finally {
      server.stop(true);
    }
  }, 20_000);

  test("an assessment sentence that asks for a report still reaches the agent", async () => {
    let calls = 0;
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === "/v1/chat/completions") {
          calls += 1;
          return Response.json({
            choices: [
              {
                message: {
                  role: "assistant",
                  content: "I reviewed https://example.com and found nothing exploitable; the report is above.",
                },
              },
            ],
          });
        }
        return new Response("missing", { status: 404 });
      },
    });
    try {
      await start({
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      });
      await type("audit https://example.com and give me the vuln report here in chat please");
      setup!.mockInput.pressEnter();
      const frame = await waitForText("found nothing exploitable", 10_000);
      expect(calls).toBeGreaterThan(0);
      expect(frame).not.toContain("no model call");
    } finally {
      server.stop(true);
    }
  }, 20_000);

  test("a greeting answers normally without deriving a scope", async () => {
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === "/v1/chat/completions") {
          return Response.json({
            choices: [
              {
                message: {
                  role: "assistant",
                  content: "Hi! I can audit a codebase or a live target - just name one.",
                },
              },
            ],
          });
        }
        return new Response("missing", { status: 404 });
      },
    });
    try {
      await start({
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      });
      await type("Hi");
      setup!.mockInput.pressEnter();
      const frame = await waitForText("just name one", 8_000);
      expect(frame).toContain("Hi! I can audit a codebase");
      expect(frame).not.toContain("reply was not agent JSON");
      expect(frame).not.toContain("scope | derived");
    } finally {
      server.stop(true);
    }
  }, 20_000);

  test("an attack request asks for intrusive authorization before anything is sent", async () => {
    const fixtures = await sampleTarget();
    await start();
    await type(`attack the code base in ${fixtures}`);
    setup!.mockInput.pressEnter();
    const frame = await waitForText("Authorize intrusive testing", 10_000);
    expect(frame).toContain("INTRUSIVE");
    expect(frame).toContain("y authorize intrusive");
    // The gate stops before any scan or model call; the answer is all that happened.
    expect(frame).not.toContain("local scan | no model call");
    expect(frame).not.toContain("agent |");

    setup!.mockInput.pressEscape();
    const cancelled = await waitForText("authorization | cancelled", 10_000);
    expect(cancelled).toContain("nothing was sent");

    const onDisk = JSON.parse(await readFile(scopePath, "utf8")) as ScopePolicy;
    expect(onDisk.allowIntrusive).toBe(false);
    expect(onDisk.authorizationRef).not.toContain("INTERACTIVE-APPROVAL");
  }, 20_000);

  test("approving the authorization prompt widens the scope and re-runs the request", async () => {
    const fixtures = await sampleTarget();
    let prompts = 0;
    const server = Bun.serve({
      port: 0,
      async fetch(request) {
        const url = new URL(request.url);
        if (url.pathname !== "/v1/chat/completions") return new Response("missing", { status: 404 });
        prompts += 1;
        const body = (await request.json()) as { messages?: Array<{ role: string; content: string }> };
        const system = body.messages?.find((message) => message.role === "system")?.content ?? "";
        // The resumed pass must carry the widened scope into its own prompt.
        const widened = system.includes("intrusive=yes");
        return Response.json({
          choices: [
            {
              message: {
                role: "assistant",
                content: widened
                  ? "intrusive approval reached the agent: running the state-changing passes now."
                  : "intrusive approval did not reach the agent.",
              },
            },
          ],
        });
      },
    });
    try {
      await start({
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      });
      await type(`attack the code base in ${fixtures}`);
      setup!.mockInput.pressEnter();
      await waitForText("Authorize intrusive testing", 10_000);
      expect(prompts).toBe(0);

      setup!.mockInput.pressKey("y");
      const approved = await waitForText("intrusive approved", 10_000);
      expect(approved).toContain("active + intrusive on");

      const onDisk = JSON.parse(await readFile(scopePath, "utf8")) as ScopePolicy;
      expect(onDisk.allowActive).toBe(true);
      expect(onDisk.allowIntrusive).toBe(true);
      expect(onDisk.authorizationRef).toContain("INTERACTIVE-APPROVAL");
      expect(onDisk.authorizedBy).toContain("interactive approval");

      const resumed = await waitForText("intrusive approval reached the agent", 20_000);
      expect(resumed).not.toContain("did not reach the agent");
      expect(prompts).toBeGreaterThan(0);
    } finally {
      server.stop(true);
    }
  }, 30_000);

  test("drag-select then ctrl+c copies without exiting", async () => {
    await start();
    setup!.renderer.copyToClipboardOSC52 = () => true;
    // The transcript starts one row below the masthead rule; drag across the
    // boot lines, which are the first rows that actually carry text.
    await setup!.mockMouse.drag(3, 4, 60, 5);
    await setup!.renderOnce();
    expect(setup!.renderer.hasSelection).toBe(true);

    setup!.mockInput.pressCtrlC();
    await settle(200);
    const frame = await setup!.waitForFrame((value) => value.includes("copied selection"));
    expect(frame).toContain("chars");
    expect(frame).toContain("ARGUS");
  });

  test("ctrl+c leaves the workspace session id for the resume command", async () => {
    const exits: Array<{ sessionId: string; reason: string }> = [];
    setup = await testRender(
      <ArgusTui
        config={config}
        initialScopePath={scopePath}
        onExit={(info) => exits.push(info)}
      />,
      { width: 100, height: 30, exitOnCtrlC: false },
    );
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = false;
    await setup.waitForFrame((value) => value.includes("ARGUS"));

    setup.mockInput.pressCtrlC();
    await new Promise((resolve) => setTimeout(resolve, 200));

    expect(exits).toHaveLength(1);
    expect(exits[0]?.reason).toBe("quit");
    expect(exits[0]?.sessionId).toMatch(/^ses-[a-f0-9]{16}$/);
  });

  test("/copy all copies the transcript through the clipboard", async () => {
    await start();
    await type("/help");
    setup!.mockInput.pressEnter();
    await setup!.waitForFrame((value) => value.includes("scan flags:"));

    setup!.renderer.copyToClipboardOSC52 = () => true;
    await type("/copy all");
    setup!.mockInput.pressEnter();
    const frame = await setup!.waitForFrame((value) => value.includes("copied transcript"));
    expect(frame).toContain("chars");
  });

  test("/memory reports the AGENTS.md file", async () => {
    await start();
    await type("/memory");
    setup!.mockInput.pressEnter();
    const frame = await setup!.waitForFrame(
      (value) => value.includes("memory |") && value.includes("AGENTS.md"),
    );
    expect(frame).toContain("memory | AGENTS.md");
  });

  test("free text prompts run the grounded agent and drop fabricated findings", async () => {
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === "/v1/chat/completions") {
          return Response.json({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    final: {
                      summary: "Grounded summary mentioning finding-fake.",
                      findingIds: ["finding-fake"],
                      nextSteps: ["name a target"],
                      gaps: [],
                    },
                  }),
                },
              },
            ],
          });
        }
        return new Response("missing", { status: 404 });
      },
    });
    try {
      await start({
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      });
      await type("find hallucinated bugs");
      setup!.mockInput.pressEnter();
      const frame = await setup!.waitForFrame((value) => value.includes("Grounded summary") && value.includes("anti-hallucination gate"));
      expect(frame).toContain("steps=1");
      expect(frame).toContain("- name a target");
      expect(frame).not.toContain("finding-fake");
    } finally {
      server.stop(true);
    }
  });

  test("clicking a provider row activates it without the keyboard", async () => {
    await start();
    await type("/providers");
    setup!.mockInput.pressEnter();
    await waitForText("Providers");
    const lines = setup!.captureCharFrame().split("\n");
    const row = lines.findIndex((line) => line.includes("Ollama (local)"));
    expect(row).toBeGreaterThan(0);
    const column = lines[row]!.indexOf("Ollama (local)");
    await setup!.mockMouse.click(column + 2, row);
    const frame = await waitForText("+ provider | Ollama (local)");
    expect(frame).toContain("+ provider | Ollama (local)");
  });

  test("clicking the modal close label closes it", async () => {
    await start();
    await type("/providers");
    setup!.mockInput.pressEnter();
    await waitForText("Providers");
    const lines = setup!.captureCharFrame().split("\n");
    const row = lines.findIndex((line) => line.includes("esc to close"));
    expect(row).toBeGreaterThan(0);
    const column = lines[row]!.indexOf("esc to close");
    await setup!.mockMouse.click(column + 2, row);
    await setup!.waitForFrame((value) => !value.includes("esc to close"));
  });

  test("plain English runs deterministic actions without an API key", async () => {
    await start();
    await type("show me the findings");
    setup!.mockInput.pressEnter();
    const frame = await waitForText("no run selected");
    expect(frame).toContain("❯ show me the findings");
    expect(frame).toContain("local action");
  });

  test("plain English starts an authorized local scan without an API key", async () => {
    const targetServer = Bun.serve({
      port: 0,
      fetch() {
        return new Response("<html><head><title>Local target</title></head><body>ok</body></html>", {
          headers: { "content-type": "text/html", "x-frame-options": "DENY" },
        });
      },
    });
    const targetUrl = `http://127.0.0.1:${targetServer.port}/`;
    const localScopePath = join(temp, "local-scope.json");
    await writeFile(localScopePath, `${JSON.stringify({ ...scope, allow: [targetUrl] }, null, 2)}\n`, "utf8");
    const previous = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    try {
      await start(config, localScopePath);
      await type(`check ${targetUrl} and find real bugs`);
      setup!.mockInput.pressEnter();
      const started = await waitForText("local scan");
      expect(started).toContain("local scan | no model call");
      const frame = await waitForText("completed", 25_000);
      expect(frame).toContain("completed");
    } finally {
      if (previous !== undefined) process.env.OPENAI_API_KEY = previous;
      targetServer.stop(true);
    }
  }, 30_000);

  test("a running pass opens the live split view with no command", async () => {
    const targetServer = Bun.serve({
      port: 0,
      async fetch() {
        // Slow responses keep the pass in flight long enough to observe the
        // split view opening by itself, without stretching the whole pass.
        await new Promise((resolve) => setTimeout(resolve, 250));
        return new Response("<html><head><title>Slow target</title></head><body>ok</body></html>", {
          headers: { "content-type": "text/html", "x-frame-options": "DENY" },
        });
      },
    });
    const targetUrl = `http://127.0.0.1:${targetServer.port}/`;
    const localScopePath = join(temp, "live-scope.json");
    await writeFile(localScopePath, `${JSON.stringify({ ...scope, allow: [targetUrl] }, null, 2)}\n`, "utf8");
    const previous = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    try {
      await start(config, localScopePath);
      await type(`check ${targetUrl} and find real bugs`);
      setup!.mockInput.pressEnter();
      const live = await waitForText("LIVE", 25_000);
      expect(live).toContain("TRAFFIC");
      expect(live).toContain("FINDINGS");
      // /stop must land while the pass is running instead of being refused.
      await type("/stop");
      setup!.mockInput.pressEnter();
      await waitForText("aborting assessment", 10_000);
    } finally {
      if (previous !== undefined) process.env.OPENAI_API_KEY = previous;
      targetServer.stop(true);
    }
  }, 40_000);

  test("plain English falls back to a local scan when the model endpoint is down", async () => {
    const targetServer = Bun.serve({
      port: 0,
      fetch() {
        return new Response("<html><head><title>Fallback target</title></head><body>ok</body></html>", {
          headers: { "content-type": "text/html", "x-frame-options": "DENY" },
        });
      },
    });
    const targetUrl = `http://127.0.0.1:${targetServer.port}/`;
    const fallbackScopePath = join(temp, "fallback-scope.json");
    await writeFile(fallbackScopePath, `${JSON.stringify({ ...scope, allow: [targetUrl] }, null, 2)}\n`, "utf8");
    try {
      await start(
        {
          ...config,
          llm: {
            enabled: true,
            providerId: "custom",
            baseUrl: "http://127.0.0.1:1/v1",
            model: "alpha",
            apiKeyEnv: "",
          },
        },
        fallbackScopePath,
      );
      await type(`check ${targetUrl} and find real bugs`);
      setup!.mockInput.pressEnter();
      const frame = await waitForText("model unavailable", 25_000);
      expect(frame).toContain("running the local action instead");
      await waitForText("completed", 25_000);
    } finally {
      targetServer.stop(true);
    }
  }, 35_000);

  test("plain English without a key explains how to enable the model", async () => {
    const previous = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    try {
      await start();
      await type("explain the difference between SSRF and CSRF");
      setup!.mockInput.pressEnter();
      const frame = await waitForText("No API key");
      expect(frame).toContain("/key openai");
      expect(frame).toContain("no-key actions");
    } finally {
      if (previous !== undefined) process.env.OPENAI_API_KEY = previous;
    }
  });

  test("clicking the prompt focuses it for a normal prompt", async () => {
    await start();
    await setup!.mockMouse.click(10, 27);
    await settle(40);
    await type("show me the findings");
    setup!.mockInput.pressEnter();
    const frame = await waitForText("no run selected");
    expect(frame).toContain("❯ show me the findings");
  });

  test("opens the dashboard charts from the slash command", async () => {
    await start();
    await type("/dashboard");
    setup!.mockInput.pressEnter();
    const frame = await setup!.waitForFrame((value) => value.includes("Dashboard"));
    expect(frame).toContain("OVERVIEW");
    expect(frame).toContain("/100");
    expect(frame).toContain("findings      0");
  });

  test("runs /help inside the transcript", async () => {
    await start();
    await type("/help");
    setup!.mockInput.pressEnter();
    const frame = await setup!.waitForFrame((value) => value.includes("scan flags:"));
    expect(frame).toContain("/scan");
    expect(frame).toContain("scope is derived from the target you name");
  });

  test("switches provider from the prompt and updates the header", async () => {
    await start();
    await type("/providers use ollama");
    setup!.mockInput.pressEnter();
    await setup!.waitForFrame((value) => value.includes("+ provider | Ollama (local)"));

    await settle(30);
    const header = setup!.captureCharFrame();
    expect(header).toContain("Ollama (local)");
  });

  test("derives a scope from a plain target", async () => {
    await start();
    await type("/scope example.com");
    setup!.mockInput.pressEnter();
    const frame = await setup!.waitForFrame((value) => value.includes("derived from request"));
    expect(frame).toContain("operator prompt");
  });

  test("dashboard loads the latest stored run when no scan is in the session", async () => {
    const store = new RunStore(temp);
    await store.init();
    const record: RunRecord = {
      id: "run-dash",
      target: { raw: "https://example.com", kind: "web", host: "example.com", scheme: "https", display: "https://example.com/" },
      profile: "deep",
      scope,
      scopePath,
      options: { profile: "deep" },
      status: "completed",
      createdAt: new Date().toISOString(),
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      phaseSummary: [{ id: "audit", label: "Audit", status: "done", durationMs: 12 }],
      dataDir: temp,
    };
    const finding: Finding = {
      id: "finding-dash",
      runId: "run-dash",
      title: "SQL injection in search",
      severity: "critical",
      category: "injection",
      confidence: "confirmed",
      target: "https://example.com/",
      url: "https://example.com/search",
      evidence: "error-based payload reflected",
      description: "Query is concatenated.",
      remediation: "Use parameters.",
      references: [],
      tool: "native",
      timestamp: new Date().toISOString(),
      fingerprint: "fp-dash",
    };
    await store.saveRun(record);
    await store.appendFinding(record.id, finding);

    await start();
    await type("/dashboard");
    setup!.mockInput.pressEnter();
    await settle(150);
    const frame = await setup!.waitForFrame((value) => value.includes("score") && value.includes("run-dash"));
    expect(frame).toContain("SEVERITY");
    expect(frame).toContain("findings      1");
    expect(frame).toContain("35/100");
  });

  test("streams scan phases into the transcript while the agent works", async () => {
    const targetServer = Bun.serve({
      port: 0,
      async fetch() {
        await new Promise((resolve) => setTimeout(resolve, 120));
        return new Response("<html><head><title>Slow target</title></head><body>ok</body></html>", {
          headers: { "content-type": "text/html" },
        });
      },
    });
    const targetUrl = `http://127.0.0.1:${targetServer.port}/`;
    const streamScopePath = join(temp, "stream-scope.json");
    await writeFile(streamScopePath, `${JSON.stringify({ ...scope, allow: [targetUrl] }, null, 2)}\n`, "utf8");
    const llmServer = Bun.serve({
      port: 0,
      async fetch(request) {
        const url = new URL(request.url);
        if (url.pathname !== "/v1/chat/completions") return new Response("missing", { status: 404 });
        const body = (await request.json()) as { messages?: Array<{ role: string; content: string }> };
        const toolMessage = [...(body.messages ?? [])]
          .reverse()
          .find((message) => message.role === "user" && message.content.startsWith("TOOL RESULT scan_target"));
        const content = toolMessage
          ? JSON.stringify({
              final: {
                summary: "Streamed scan finished.",
                findingIds: [],
                nextSteps: [],
                gaps: [],
              },
            })
          : JSON.stringify({
              action: {
                tool: "scan_target",
                args: { target: targetUrl, profile: "quick", retries: 0 },
              },
            });
        return Response.json({ choices: [{ message: { content } }] });
      },
    });
    try {
      await start(
        {
          ...config,
          llm: {
            enabled: true,
            providerId: "custom",
            baseUrl: `http://127.0.0.1:${llmServer.port}/v1`,
            model: "alpha",
            apiKeyEnv: "",
          },
        },
        streamScopePath,
      );
      await type(`audit ${targetUrl}`);
      setup!.mockInput.pressEnter();
      const frame = await waitForAnyText(["Reconnaissance", "Attack Surface", "Audit", "Supply Chain"]);
      expect(frame).toContain("scan_target");
      await waitForText("FIXES", 20_000);
    } finally {
      targetServer.stop(true);
      llmServer.stop(true);
    }
  }, 25_000);

  test("free text can run a real authorized scan through the agent loop", async () => {
    const targetServer = Bun.serve({
      port: 0,
      fetch() {
        return new Response("<html><head><title>Test target</title></head><body>ok</body></html>", {
          headers: { "content-type": "text/html", "x-frame-options": "DENY" },
        });
      },
    });
    const targetUrl = `http://127.0.0.1:${targetServer.port}/`;
    const testScope: ScopePolicy = {
      ...scope,
      allow: [targetUrl],
    };
    const scopedPath = join(temp, "target-scope.json");
    await writeFile(scopedPath, `${JSON.stringify(testScope, null, 2)}\n`, "utf8");
    const llmServer = Bun.serve({
      port: 0,
      async fetch(request) {
        const url = new URL(request.url);
        if (url.pathname !== "/v1/chat/completions") return new Response("missing", { status: 404 });
        const body = (await request.json()) as { messages?: Array<{ role: string; content: string }> };
        const toolMessage = [...(body.messages ?? [])]
          .reverse()
          .find((message) => message.role === "user" && message.content.startsWith("TOOL RESULT scan_target"));
        let content: string;
        if (toolMessage) {
          const json = toolMessage.content.slice(toolMessage.content.indexOf("{"));
          const payload = JSON.parse(json) as { items?: Array<{ id?: string }> };
          const id = payload.items?.[0]?.id;
          content = JSON.stringify({
            final: {
              summary: "The local target returned a confirmed header finding.",
              findingIds: id ? [id] : [],
              nextSteps: ["fix the headers"],
              gaps: [],
            },
          });
        } else {
          content = JSON.stringify({
            action: {
              tool: "scan_target",
              args: { target: targetUrl, profile: "quick", retries: 0 },
            },
          });
        }
        return Response.json({ choices: [{ message: { content } }] });
      },
    });
    try {
      await start(
        {
          ...config,
          llm: {
            enabled: true,
            providerId: "custom",
            baseUrl: `http://127.0.0.1:${llmServer.port}/v1`,
            model: "alpha",
            apiKeyEnv: "",
          },
        },
        scopedPath,
      );
      await type(`can you check ${targetUrl} and tell me if it is safe?`);
      setup!.mockInput.pressEnter();
      const frame = await waitForText("The local target returned a confirmed header finding.");
      expect(frame).toContain("FINDINGS | 1 VERIFIED");
      expect(frame).toContain("scans=1");
      expect(frame).toContain("Content-Security-Policy missing");
      expect(frame).toContain("fix the headers");
    } finally {
      targetServer.stop(true);
      llmServer.stop(true);
    }
  }, 20_000);

  test("/preview opens the read-only panel and esc closes it", async () => {
    await start();
    await type("/preview package.json");
    setup!.mockInput.pressEnter();
    const frame = await waitForText("Preview package.json", 6_000);
    expect(frame).toContain("argus-pentest");
    expect(frame).toContain("lines | showing 1-");
    expect(frame).toContain("esc to close");

    setup!.mockInput.pressEscape();
    await settle(140);
    expect(setup!.captureCharFrame()).not.toContain("Preview package.json");
  }, 20_000);

  test("the agent's preview tool opens the panel for the file it looked at", async () => {
    const server = Bun.serve({
      port: 0,
      async fetch(request) {
        const url = new URL(request.url);
        if (url.pathname !== "/v1/chat/completions") return new Response("missing", { status: 404 });
        const body = (await request.json()) as { messages?: Array<{ role: string }> };
        const usedTool = (body.messages ?? []).some((message) => message.role === "tool");
        if (!usedTool) {
          return Response.json({
            choices: [
              {
                message: {
                  role: "assistant",
                  content: "",
                  tool_calls: [
                    {
                      id: "call_preview",
                      type: "function",
                      function: {
                        name: "preview",
                        arguments: JSON.stringify({ path: "package.json", startLine: 1, endLine: 4 }),
                      },
                    },
                  ],
                },
              },
            ],
          });
        }
        return Response.json({
          choices: [{ message: { role: "assistant", content: "The manifest names the project argus-pentest." } }],
        });
      },
    });
    try {
      await start({
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      });
      await type("preview package.json before changing it");
      setup!.mockInput.pressEnter();
      const frame = await waitForText("Preview package.json", 10_000);
      expect(frame).toContain("argus-pentest");
      expect(frame).toContain("from the agent");
    } finally {
      server.stop(true);
    }
  }, 20_000);
});
