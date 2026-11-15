import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { acceptTerms } from "../src/core/authorization";
import { defaultConfig } from "../src/core/config";
import { ArgusEngine } from "../src/core/engine";
import { memoryPath } from "../src/core/memory";
import type { ArgusConfig, ScopePolicy } from "../src/core/types";
import { runAgentPrompt } from "../src/tui/agent-runner";

const scope: ScopePolicy = {
  version: 1,
  name: "Memory integration",
  authorizedBy: "Security Team",
  authorizationRef: "TICKET-MEMORY",
  expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
  allow: [],
  allowActive: true,
  allowIntrusive: false,
  allowExternal: false,
};

let temp: string;
let config: ArgusConfig;
let scopePath: string;
let engine: ArgusEngine;

beforeEach(async () => {
  temp = await mkdtemp(join(tmpdir(), "argus-agent-memory-"));
  delete process.env.ARGUS_MEMORY;
  scopePath = join(temp, "scope.json");
  config = { ...defaultConfig(), dataDir: temp };
  await acceptTerms(temp, "test suite");
  engine = new ArgusEngine(config);
});

afterEach(async () => {
  delete process.env.ARGUS_MEMORY;
  await rm(temp, { recursive: true, force: true });
});

describe("agent memory integration", () => {
  test("creates AGENTS.md and records a verified scan", async () => {
    const targetServer = Bun.serve({
      port: 0,
      fetch() {
        return new Response("<html><head><title>Memory target</title></head><body>ok</body></html>", {
          headers: { "content-type": "text/html" },
        });
      },
    });
    const targetUrl = `http://127.0.0.1:${targetServer.port}/`;
    await writeFile(scopePath, `${JSON.stringify({ ...scope, allow: [targetUrl] }, null, 2)}\n`, "utf8");

    const llmServer = Bun.serve({
      port: 0,
      async fetch(request) {
        const url = new URL(request.url);
        if (url.pathname !== "/v1/chat/completions") return new Response("missing", { status: 404 });
        const body = (await request.json()) as { messages?: Array<{ role: string; content: string }> };
        const toolMessage = [...(body.messages ?? [])]
          .reverse()
          .find((message) => message.role === "user" && message.content.startsWith("TOOL RESULT scan_target"));
        if (toolMessage) {
          const json = toolMessage.content.slice(toolMessage.content.indexOf("{"));
          const payload = JSON.parse(json) as { items?: Array<{ id?: string }> };
          const id = payload.items?.[0]?.id;
          return Response.json({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    final: {
                      summary: "The memory target was assessed.",
                      findingIds: id ? [id] : [],
                      nextSteps: ["fix the finding"],
                      gaps: [],
                    },
                  }),
                },
              },
            ],
          });
        }
        return Response.json({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  action: {
                    tool: "scan_target",
                    args: { target: targetUrl, profile: "quick", retries: 0 },
                  },
                }),
              },
            },
          ],
        });
      },
    });

    try {
      const result = await runAgentPrompt({
        config: {
          ...config,
          llm: {
            enabled: true,
            providerId: "custom",
            baseUrl: `http://127.0.0.1:${llmServer.port}/v1`,
            model: "alpha",
            apiKeyEnv: "",
          },
        },
        engine,
        scopePath,
        prompt: `audit ${targetUrl} and find real bugs`,
        workspace: temp,
      });

      expect(result.scans.length).toBe(1);
      expect(result.memorySaved).toBe(true);
      expect(result.memoryPath).toBe(memoryPath(temp));

      const content = await readFile(memoryPath(temp), "utf8");
      expect(content).toContain("## Argus memory");
      expect(content).toContain("- runs:");
      expect(content).toContain("findings:");
      expect(content).toContain("memory target was assessed");
    } finally {
      targetServer.stop(true);
      llmServer.stop(true);
    }
  }, 20_000);
});
