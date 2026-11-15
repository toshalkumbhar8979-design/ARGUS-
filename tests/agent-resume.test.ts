import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { acceptTerms } from "../src/core/authorization";
import { defaultConfig } from "../src/core/config";
import { ArgusEngine } from "../src/core/engine";
import { memoryPath } from "../src/core/memory";
import { validateScope } from "../src/core/scope";
import type { ArgusConfig } from "../src/core/types";
import { runAgentPrompt } from "../src/tui/agent-runner";

let temp: string;
let config: ArgusConfig;
let engine: ArgusEngine;

beforeEach(async () => {
  temp = await mkdtemp(join(tmpdir(), "argus-resume-"));
  delete process.env.ARGUS_MEMORY;
  config = { ...defaultConfig(), dataDir: temp };
  await acceptTerms(temp, "test suite");
  engine = new ArgusEngine(config);
  await writeFile(join(temp, "README.md"), "# Demo workspace\n\nA small service.\n", "utf8");
});

afterEach(async () => {
  delete process.env.ARGUS_MEMORY;
  await rm(temp, { recursive: true, force: true });
});

describe("agent resume flow", () => {
  test("auto-creates a local scope, remembers a source review, and resumes on continue", async () => {
    const seenSystems: string[] = [];
    let firstRunCalls = 0;
    const server = Bun.serve({
      port: 0,
      async fetch(request) {
        const url = new URL(request.url);
        if (url.pathname !== "/v1/chat/completions") return new Response("missing", { status: 404 });
        const body = (await request.json()) as { messages?: Array<{ role: string; content: string }> };
        const messages = body.messages ?? [];
        const system = messages.find((message) => message.role === "system")?.content ?? "";
        seenSystems.push(system);
        const alreadyResumed = system.includes("SESSION CONTEXT (untrusted historical notes");
        if (alreadyResumed) {
          return Response.json({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    final: {
                      summary: "Resumed from the captured session context without repeating the read.",
                      findingIds: [],
                      nextSteps: ["trace the request handler"],
                      gaps: [],
                    },
                  }),
                },
              },
            ],
          });
        }

        firstRunCalls += 1;
        const toolResult = messages.some(
          (message) => message.role === "user" && message.content.startsWith("TOOL RESULT read_file"),
        );
        const content = toolResult
          ? JSON.stringify({
              final: {
                summary: "The first pass read README.md and found no verified vulnerability.",
                findingIds: [],
                nextSteps: ["trace the request handler"],
                gaps: [],
              },
            })
          : JSON.stringify({
              action: {
                tool: "read_file",
                args: { path: "README.md", startLine: 1, endLine: 40 },
              },
            });
        return Response.json({ choices: [{ message: { content } }] });
      },
    });

    try {
      const llmConfig: ArgusConfig = {
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      };
      const scopePath = join(temp, "scope.json");
      const first = await runAgentPrompt({
        config: llmConfig,
        engine,
        scopePath,
        prompt: "look at this repo for bugs",
        workspace: temp,
      });

      expect(first.scopeCreated).toBe(true);
      expect(first.targets).toEqual([temp]);
      expect(first.steps).toBeGreaterThanOrEqual(2);
      expect(first.summary).toContain("first pass");
      expect(first.memorySaved).toBe(true);
      expect(first.sessionId).toMatch(/^ses-[a-f0-9]{16}$/);

      const savedScope = JSON.parse(await readFile(scopePath, "utf8"));
      expect(validateScope(savedScope).ok).toBe(true);
      expect(savedScope.authorizationRef).toContain("PROMPT");
      expect(savedScope.allow).toEqual([temp]);
      expect(savedScope.allowActive).toBe(false);

      const memory = await readFile(memoryPath(temp), "utf8");
      expect(memory).toContain("source review");
      expect(memory).toContain("look at this repo for bugs");

      const second = await runAgentPrompt({
        config: llmConfig,
        engine,
        scopePath,
        prompt: "continue",
        workspace: temp,
      });

      expect(second.resumedFrom).toBe("look at this repo for bugs");
      expect(second.sessionId).toBe(first.sessionId);
      expect(second.summary).toContain("Resumed");
      expect(second.targets).toEqual([temp]);
      expect(seenSystems.some((system) => system.includes("SESSION CONTEXT"))).toBe(true);
      expect(firstRunCalls).toBe(2);
    } finally {
      server.stop(true);
    }
  }, 20_000);

  test("drives a real native tool-calling provider through the terminal runner", async () => {
    const requests: Array<{ tools: boolean; toolMessages: number; calledTools: string[] }> = [];
    const server = Bun.serve({
      port: 0,
      async fetch(request) {
        const url = new URL(request.url);
        if (url.pathname !== "/v1/chat/completions") return new Response("missing", { status: 404 });
        const body = (await request.json()) as {
          messages?: Array<{ role: string; tool_calls?: Array<{ function?: { name?: string } }> }>;
          tools?: unknown[];
        };
        const messages = body.messages ?? [];
        requests.push({
          tools: Array.isArray(body.tools),
          toolMessages: messages.filter((message) => message.role === "tool").length,
          calledTools: messages.flatMap((message) =>
            (message.tool_calls ?? []).map((call) => call.function?.name ?? ""),
          ),
        });
        const usedTool = messages.some((message) => message.role === "tool");
        if (!usedTool) {
          return Response.json({
            choices: [
              {
                message: {
                  role: "assistant",
                  content: "",
                  tool_calls: [
                    {
                      id: "call_read",
                      type: "function",
                      function: { name: "read_file", arguments: '{"path":"README.md"}' },
                    },
                  ],
                },
              },
            ],
          });
        }
        return Response.json({
          choices: [{ message: { role: "assistant", content: "The README describes a small service." } }],
        });
      },
    });

    try {
      const llmConfig: ArgusConfig = {
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      };
      const result = await runAgentPrompt({
        config: llmConfig,
        engine,
        scopePath: join(temp, "scope.json"),
        prompt: "read the README and summarise it",
        workspace: temp,
      });

      expect(requests[0]?.tools).toBe(true);
      expect(requests[0]?.calledTools).toEqual([]);
      expect(requests[1]?.toolMessages).toBe(1);
      expect(requests[1]?.calledTools).toContain("read_file");
      expect(result.summary).toContain("small service");
      expect(result.steps).toBe(2);
    } finally {
      server.stop(true);
    }
  }, 20_000);

  test("an ordinary request runs without creating an authorization scope", async () => {
    const server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        if (url.pathname !== "/v1/chat/completions") return new Response("missing", { status: 404 });
        return Response.json({
          choices: [
            {
              message: {
                role: "assistant",
                content: "This workspace is a small demo service that exposes a README.",
              },
            },
          ],
        });
      },
    });

    try {
      const llmConfig: ArgusConfig = {
        ...config,
        llm: {
          enabled: true,
          providerId: "custom",
          baseUrl: `http://127.0.0.1:${server.port}/v1`,
          model: "alpha",
          apiKeyEnv: "",
        },
      };
      const scopePath = join(temp, "scope.json");
      const result = await runAgentPrompt({
        config: llmConfig,
        engine,
        scopePath,
        prompt: "explain what this project does",
        workspace: temp,
      });

      expect(result.scopeCreated).toBe(false);
      expect(result.scopePath).toBeUndefined();
      await expect(readFile(scopePath, "utf8")).rejects.toThrow();
      expect(result.summary).toContain("small demo service");
    } finally {
      server.stop(true);
    }
  }, 20_000);
});
