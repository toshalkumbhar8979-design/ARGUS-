import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { defaultConfig } from "../src/core/config";
import { ArgusEngine } from "../src/core/engine";
import { RunStore } from "../src/core/store";
import type { ArgusConfig, Finding, RunRecord, ScopePolicy, Target } from "../src/core/types";
import {
  buildScanRequest,
  COMMANDS,
  matchCommands,
  parseCommandLine,
  runCommand,
  tokenize,
  type CommandDeps,
  type ScanRequest,
} from "../src/tui/commands";
import type { PreviewPayload } from "../src/tui/preview";
import { extractModelIds, listProviderModels, PROVIDERS, resolveProvider, type LlmSettings } from "../src/tui/providers";
import type { TranscriptKind } from "../src/tui/state";

const target: Target = {
  raw: "https://example.com",
  kind: "web",
  host: "example.com",
  scheme: "https",
  url: "https://example.com/",
  display: "https://example.com/",
};

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

const finding: Finding = {
  id: "finding-1",
  runId: "run-1",
  title: "Missing security headers",
  severity: "medium",
  category: "headers",
  confidence: "confirmed",
  target: "https://example.com/",
  url: "https://example.com/",
  evidence: "content-security-policy header is absent",
  description: "No CSP header.",
  remediation: "Send a Content-Security-Policy header.",
  references: [],
  tool: "native",
  timestamp: "2026-10-24T10:00:03.000Z",
  fingerprint: "fp-1",
};

const record: RunRecord = {
  id: "run-1",
  target,
  profile: "web",
  scope,
  scopePath: "scope.json",
  options: { profile: "web" },
  status: "completed",
  createdAt: "2026-10-24T10:00:00.000Z",
  startedAt: "2026-10-24T10:00:00.000Z",
  finishedAt: "2026-10-24T10:00:06.000Z",
  counts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 },
  phaseSummary: [],
  dataDir: "",
};

describe("command parsing", () => {
  test("splits quoted arguments", () => {
    expect(tokenize('/scope "C:\\my scans\\scope.json" https://example.com')).toEqual([
      "/scope",
      "C:\\my scans\\scope.json",
      "https://example.com",
    ]);
  });

  test("parses long, short and boolean flags", () => {
    const parsed = parseCommandLine("/scan https://example.com --profile web -s scope.json --yes-authorized --retries=3");
    expect(parsed).not.toBeNull();
    expect(parsed!.name).toBe("/scan");
    expect(parsed!.args).toEqual(["https://example.com"]);
    expect(parsed!.flags.get("profile")).toBe("web");
    expect(parsed!.flags.get("s")).toBe("scope.json");
    expect(parsed!.flags.get("yes-authorized")).toBe(true);
    expect(parsed!.flags.get("retries")).toBe("3");
  });

  test("ignores input that is not a command", () => {
    expect(parseCommandLine("scan example.com")).toBeNull();
  });

  test("suggests commands by prefix only", () => {
    expect(matchCommands("/")).toHaveLength(COMMANDS.length);
    expect(matchCommands("/mo").map((command) => command.name)).toEqual(["/models"]);
    expect(matchCommands("/scan example.com")).toEqual([]);
    expect(matchCommands("hello")).toEqual([]);
  });

  test("builds a ruthless scan request by default", () => {
    const parsed = parseCommandLine("/scan https://example.com --yes-authorized")!;
    const { request } = buildScanRequest(parsed);
    expect(request).toMatchObject({
      target: "https://example.com",
      profile: "deep",
      retries: 2,
      scopePath: "scope.json",
      passiveOnly: false,
      intrusive: false,
      allowExternal: true,
    });
  });

  test("honours scan overrides and rejects bad profiles", () => {
    const parsed = parseCommandLine(
      "/scan example.com --profile quick --scope scope.json --passive --intrusive --external --retries 5 --formats md,csv",
    )!;
    const { request } = buildScanRequest(parsed);
    expect(request).toMatchObject({
      profile: "quick",
      passiveOnly: true,
      intrusive: true,
      allowExternal: true,
      retries: 5,
      formats: ["markdown", "csv"],
    });
    const bad = buildScanRequest(parseCommandLine("/scan example.com --profile turbo")!);
    expect(bad.error).toContain("unknown profile");
  });
});

describe("providers", () => {
  test("extracts ids from common model payload shapes", () => {
    expect(extractModelIds({ data: [{ id: "b" }, { id: "a" }] })).toEqual(["a", "b"]);
    expect(extractModelIds({ models: [{ name: "llama3" }, "qwen"] })).toEqual(["llama3", "qwen"]);
    expect(extractModelIds({ data: [] })).toEqual([]);
    expect(extractModelIds(null)).toEqual([]);
  });

  test("resolves catalog providers and custom endpoints", () => {
    const ollama: LlmSettings = {
      enabled: true,
      providerId: "ollama",
      baseUrl: "http://127.0.0.1:11434/v1",
      model: "llama3.2",
      apiKeyEnv: "",
    };
    expect(resolveProvider(ollama).id).toBe("ollama");
    expect(resolveProvider(ollama).requiresKey).toBe(false);
    const custom: LlmSettings = { ...ollama, providerId: "house", baseUrl: "https://llm.internal/v1" };
    expect(resolveProvider(custom).id).toBe("custom");
  });

  test("ships a catalog of real model ids for every hosted provider", () => {
    const byId = new Map(PROVIDERS.map((provider) => [provider.id, provider]));
    expect(byId.get("openai")?.models).toContain("gpt-4.1-mini");
    expect(byId.get("openai")?.models).toContain("o4-mini");
    expect(byId.get("openrouter")?.models).toContain("anthropic/claude-sonnet-4");
    expect(byId.get("deepseek")?.models).toEqual(["deepseek-chat", "deepseek-reasoner"]);
    expect(byId.get("ollama")?.models).toContain("llama3.2");
    for (const provider of PROVIDERS) {
      if (provider.id === "custom" || provider.id === "lmstudio") continue;
      expect(provider.models.length).toBeGreaterThan(0);
    }
  });

  test("lists models from an OpenAI-compatible endpoint", async () => {
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === "/v1/models") {
          return Response.json({ data: [{ id: "beta" }, { id: "alpha" }] });
        }
        return new Response("missing", { status: 404 });
      },
    });
    try {
      const llm: LlmSettings = {
        enabled: true,
        providerId: "custom",
        baseUrl: `http://127.0.0.1:${server.port}/v1`,
        model: "alpha",
        apiKeyEnv: "",
      };
      await expect(listProviderModels(llm)).resolves.toEqual(["alpha", "beta"]);
      await expect(listProviderModels({ ...llm, baseUrl: `${llm.baseUrl}/missing` })).rejects.toThrow("HTTP 404");
    } finally {
      server.stop(true);
    }
  });
});

describe("slash commands", () => {
  let temp: string;
  let config: ArgusConfig;
  let engine: ArgusEngine;
  let lines: Array<{ kind: TranscriptKind; text: string }>;
  let scans: ScanRequest[];
  let current: ArgusConfig;

  beforeEach(async () => {
    temp = await mkdtemp(join(tmpdir(), "argus-cmd-"));
    process.env.ARGUS_CONFIG = join(temp, "argus.config.json");
    config = { ...defaultConfig(), dataDir: temp, defaultProfile: "deep" };
    engine = new ArgusEngine(config);
    lines = [];
    scans = [];
    current = config;
    await writeFile(join(temp, "scope.json"), `${JSON.stringify(scope, null, 2)}\n`, "utf8");
  });

  afterEach(async () => {
    delete process.env.ARGUS_CONFIG;
    await rm(temp, { recursive: true, force: true });
  });

  function deps(overrides: Partial<CommandDeps> = {}): CommandDeps {
    return {
      config: current,
      scopePath: join(temp, "scope.json"),
      engine,
      io: {
        write: (kind, text) => lines.push({ kind, text }),
        clear: () => {},
        quit: () => {},
      },
      running: false,
      setConfig: (next) => {
        current = next;
      },
      setScopePath: () => {},
      setLastRunId: () => {},
      startScan: async (request) => {
        scans.push(request);
      },
      ...overrides,
    };
  }

  function text(): string {
    return lines.map((line) => line.text).join("\n");
  }

  test("lists and switches providers, persisting the choice", async () => {
    await runCommand("/providers", deps());
    expect(text()).toContain("openai");
    expect(text()).toContain("active");

    await runCommand("/providers use ollama", deps());
    expect(current.llm?.providerId).toBe("ollama");
    expect(current.llm?.baseUrl).toBe("http://127.0.0.1:11434/v1");
    const saved = JSON.parse(await readFile(join(temp, "argus.config.json"), "utf8")) as ArgusConfig;
    expect(saved.llm?.providerId).toBe("ollama");

    await runCommand("/models llama3.2", deps());
    expect(current.llm?.model).toBe("llama3.2");
  });

  test("reuses provider keys from env names without printing secrets", async () => {
    const previous = process.env.ARGUS_TEST_KEY;
    process.env.ARGUS_TEST_KEY = "super-secret-value";
    try {
      await runCommand("/providers key ARGUS_TEST_KEY", deps());
      expect(current.llm?.apiKeyEnv).toBe("ARGUS_TEST_KEY");
      expect(text()).not.toContain("super-secret-value");
    } finally {
      if (previous === undefined) delete process.env.ARGUS_TEST_KEY;
      else process.env.ARGUS_TEST_KEY = previous;
    }
  });

  test("lists models and verifies connectivity against a live endpoint", async () => {
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === "/v1/models") return Response.json({ data: [{ id: "alpha" }, { id: "beta" }] });
        return new Response("missing", { status: 404 });
      },
    });
    try {
      current = {
        ...current,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      };
      await runCommand("/models", deps());
      expect(text()).toContain("2 models available");
      expect(text()).toContain("alpha");
      expect(text()).toContain("beta");

      lines = [];
      await runCommand("/connect", deps());
      expect(text()).toContain("provider reachable");
    } finally {
      server.stop(true);
    }
  });

  test("falls back to the known catalog when live discovery fails", async () => {
    current = {
      ...current,
      llm: {
        enabled: true,
        providerId: "ollama",
        baseUrl: "http://127.0.0.1:1/v1",
        model: "llama3.2",
        apiKeyEnv: "",
      },
    };
    await runCommand("/models", deps());
    expect(text()).toContain("known Ollama (local) models");
    expect(text()).toContain("llama3.2");
    expect(text()).toContain("qwen2.5-coder");

    lines = [];
    await runCommand("/connect", deps());
    expect(text()).toContain("OpenAI-compatible endpoints");
    expect(text()).toContain("deepseek");
  });

  test("derives a prompt scope without a magic flag", async () => {
    await runCommand("/scan https://example.com", deps());
    expect(scans).toHaveLength(1);
    expect(scans[0]?.target).toBe("https://example.com");
    expect(text()).toContain("authorization derived from the target");
  });

  test("refuses targets outside the scope file", async () => {
    await runCommand(`/scan https://evil.test --scope ${join(temp, "scope.json")}`, deps());
    expect(text()).toContain("outside the authorized scope");
    expect(scans).toHaveLength(0);
  });

  test("auto-creates a workspace-only scope for a local repo scan", async () => {
    const repo = join(temp, "repo");
    await mkdir(repo);
    const autoScope = join(temp, "auto-scope.json");
    await runCommand(`/scan "${repo}" --profile repo --scope "${autoScope}"`, deps());
    expect(scans).toHaveLength(1);
    expect(scans[0]?.target).toBe(repo);
    expect(text()).toContain("+ scope | new prompt scope created");
    const saved = JSON.parse(await readFile(autoScope, "utf8")) as ScopePolicy;
    expect(saved.allow).toEqual([repo]);
    expect(saved.allowActive).toBe(false);
    expect(saved.authorizationRef).toContain("PROMPT");
  });

  test("starts a prompt-scoped scan with ruthless defaults", async () => {
    await runCommand(`/scan https://example.com`, deps());
    expect(scans).toHaveLength(1);
    expect(scans[0]).toMatchObject({
      target: "https://example.com",
      profile: "deep",
      retries: 2,
      scopePath: join(temp, "scope.prompt.json"),
    });
    expect(text()).toContain("ruthless mode");
    expect(text()).toContain("authorization derived from the target");
  });

  test("reads findings from a stored run", async () => {
    const store = new RunStore(temp);
    await store.saveRun({ ...record, dataDir: temp });
    await store.appendFinding(record.id, finding);
    await runCommand(`/findings ${record.id}`, deps());
    expect(text()).toContain("Missing security headers");
    expect(text()).toContain("content-security-policy header is absent");
    expect(text()).toContain("Send a Content-Security-Policy header.");
  });

  test("shows scope validation and reports unknown commands", async () => {
    await runCommand("/scope", deps());
    expect(text()).toContain("valid");
    expect(text()).toContain("TICKET-42");

    lines = [];
    await runCommand("/nope", deps());
    expect(text()).toContain("unknown command");
  });

  test("doctor checks provider, scope, memory and adapters without a chat call", async () => {
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === "/v1/models") return Response.json({ data: [{ id: "alpha" }] });
        return new Response("missing", { status: 404 });
      },
    });
    process.env.ARGUS_MEMORY = "off";
    try {
      current = {
        ...current,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      };
      await runCommand("/doctor", deps());
      const output = text();
      expect(output).toContain("doctor");
      expect(output).toContain("reachable | 1 model(s) listed");
      expect(output).toContain("scope");
      expect(output).toContain("TICKET-42");
      expect(output).toContain("disabled by ARGUS_MEMORY=off");
      expect(output).toContain("adapters");
      expect(output).toContain("doctor  ok=");
      expect(output).not.toContain("chat/completions");
    } finally {
      delete process.env.ARGUS_MEMORY;
      server.stop(true);
    }
  });

  test("doctor reports a missing key without calling the provider", async () => {
    process.env.ARGUS_MEMORY = "off";
    delete process.env.ARGUS_DOCTOR_KEY;
    try {
      current = {
        ...current,
        llm: {
          enabled: true,
          providerId: "openai",
          baseUrl: "https://api.openai.com/v1",
          model: "gpt-4.1-mini",
          apiKeyEnv: "ARGUS_DOCTOR_KEY",
        },
      };
      await runCommand("/doctor", deps());
      const output = text();
      expect(output).toContain("missing ARGUS_DOCTOR_KEY");
      expect(output).toContain("errors=1");
    } finally {
      delete process.env.ARGUS_MEMORY;
    }
  });

  test("analyzes a JWT locally and redacts sensitive claims", async () => {
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({ sub: "u-1", role: "admin", password: "super-secret-value" }),
    ).toString("base64url");
    await runCommand(`/jwt ${header}.${payload}.c2ln`, deps());
    const output = text();
    expect(output).toContain("Unsigned token (alg none)");
    expect(output).toContain("role");
    expect(output).toContain("[redacted 18 chars]");
    expect(output).not.toContain("super-secret-value");
  });

  test("sends one scoped HTTP request from the URL itself", async () => {
    let hits = 0;
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        hits += 1;
        return Response.json(
          { method: request.method, test: request.headers.get("x-test") },
          { status: 201, headers: { "set-cookie": "session=do-not-print" } },
        );
      },
    });
    const url = `http://127.0.0.1:${server.port}/check`;
    await writeFile(
      join(temp, "local-scope.json"),
      `${JSON.stringify({ ...scope, allow: [`http://127.0.0.1:${server.port}`] }, null, 2)}\n`,
      "utf8",
    );
    const scopePath = join(temp, "local-scope.json");
    try {
      await runCommand(`/http ${url} --method POST --json '{"a":1}' --header "x-test: yes" --yes-authorized --scope "${scopePath}"`, deps());
      const output = text();
      expect(hits).toBe(1);
      expect(output).toContain("201");
      expect(output).toContain('"test":"yes"');
      expect(output).toContain('"method":"POST"');
      expect(output).not.toContain("do-not-print");

      lines.length = 0;
      await runCommand(`/http ${url} --scope "${scopePath}"`, deps());
      expect(hits).toBe(2);
      expect(text()).toContain("201");
    } finally {
      server.stop(true);
    }
  });

  test("doctor --chat verifies the chat endpoint with one tiny completion", async () => {
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === "/v1/models") return Response.json({ data: [{ id: "alpha" }] });
        if (url.pathname === "/v1/chat/completions") {
          return Response.json({ choices: [{ message: { content: "OK" } }] });
        }
        return new Response("missing", { status: 404 });
      },
    });
    process.env.ARGUS_MEMORY = "off";
    try {
      current = {
        ...current,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      };
      await runCommand("/doctor --chat", deps());
      const output = text();
      expect(output).toContain("chat test requested");
      expect(output).toContain("endpoint replied | OK");
      expect(output).toContain("doctor  ok=");
    } finally {
      delete process.env.ARGUS_MEMORY;
      server.stop(true);
    }
  });

  test("previews a workspace file read-only and refuses paths outside the roots", async () => {
    const sample = resolve(process.cwd(), "package.json");
    let captured: PreviewPayload | undefined;

    await runCommand(`/preview "${sample}" --start 2 --end 3`, deps({ openPreview: (payload) => (captured = payload) }));
    expect(captured?.mode).toBe("text");
    expect(captured?.path).toBe(sample);
    expect(captured?.start).toBe(2);
    expect(captured?.end).toBe(3);
    expect(captured?.preview ?? "").toContain("2| ");
    expect(text()).toContain("esc closes");

    lines.length = 0;
    captured = undefined;
    await runCommand(`/preview ${join(temp, "outside.ts")}`, deps({ openPreview: (payload) => (captured = payload) }));
    expect(captured).toBeUndefined();
    expect(text()).toContain("outside the workspace and the authorized local roots");

    lines.length = 0;
    await runCommand("/preview", deps());
    expect(text()).toContain("usage: /preview");
  });
});
