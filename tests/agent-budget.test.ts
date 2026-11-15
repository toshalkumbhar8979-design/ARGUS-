import { describe, expect, test } from "bun:test";
import { GroundedAgent, type AgentBackend, type ChatClient, type ChatMessage } from "../src/core/agent";

function backend(overrides: Partial<AgentBackend> = {}): AgentBackend {
  return {
    workspace: process.cwd(),
    scan: async () => {
      throw new Error("scan is not used in this test");
    },
    listRuns: async () => [],
    loadRun: async () => null,
    readFile: async (path) => ({ path, content: `// ${path}\n`, bytes: 12 }),
    search: async () => [],
    validateTarget: async () => undefined,
    ...overrides,
  };
}

describe("unbounded agent loop", () => {
  test("runs past the old 24-step ceiling when the model keeps making progress", async () => {
    const replies = Array.from({ length: 26 }, (_, index) =>
      JSON.stringify({
        action: { tool: "read_file", args: { path: `src/file-${index}.ts`, startLine: 1, endLine: 1 } },
      }),
    );
    replies.push(
      JSON.stringify({
        final: { summary: "Finished after twenty-six reads.", findingIds: [], nextSteps: [], gaps: [] },
      }),
    );
    let index = 0;
    const chat: ChatClient = {
      async complete(_messages: ChatMessage[]) {
        const reply = replies[index] ?? replies[replies.length - 1]!;
        index += 1;
        return reply;
      },
    };

    const result = await new GroundedAgent(chat, backend(), "inspect the source", "scope ok").run(
      "inspect the source",
    );

    expect(result.steps).toBe(27);
    expect(result.summary).toContain("twenty-six");
    expect(result.gaps).not.toContain("step budget");
  });

  test("stops a repeated identical tool call instead of looping forever", async () => {
    const reply = JSON.stringify({
      action: { tool: "read_file", args: { path: "src/same.ts", startLine: 1, endLine: 1 } },
    });
    const chat: ChatClient = {
      async complete() {
        return reply;
      },
    };

    const result = await new GroundedAgent(chat, backend(), "inspect the source", "scope ok").run(
      "inspect the source",
    );

    expect(result.steps).toBe(3);
    expect(result.gaps.some((gap) => gap.includes("repeated the same tool call"))).toBe(true);
  });

  test("stops an alternating two-tool cycle even though no call repeats twice in a row", async () => {
    let turn = 0;
    const chat: ChatClient = {
      async complete() {
        turn += 1;
        const path = turn % 2 === 0 ? "src/a.ts" : "src/b.ts";
        return JSON.stringify({ action: { tool: "read_file", args: { path, startLine: 1, endLine: 1 } } });
      },
    };

    const result = await new GroundedAgent(chat, backend(), "inspect the source", "scope ok").run(
      "inspect the source",
    );

    expect(result.gaps.some((gap) => gap.includes("between the same two tool calls"))).toBe(true);
  });

  test("subagents have no fixed four-step default either", async () => {
    let childCalls = 0;
    let parentCalls = 0;
    const details: string[] = [];
    const chat: ChatClient = {
      async complete(messages: ChatMessage[]) {
        const system = messages[0]?.content ?? "";
        if (system.includes("You are subagent")) {
          childCalls += 1;
          if (childCalls <= 6) {
            return JSON.stringify({
              action: { tool: "read_file", args: { path: `src/child-${childCalls}.ts`, startLine: 1, endLine: 1 } },
            });
          }
          return JSON.stringify({
            final: { summary: "Child finished after six reads.", findingIds: [], nextSteps: [], gaps: [] },
          });
        }
        parentCalls += 1;
        if (parentCalls === 1) {
          return JSON.stringify({
            action: {
              tool: "spawn_subagents",
              args: { tasks: [{ label: "deep", role: "recon", prompt: "inspect every source file" }] },
            },
          });
        }
        return JSON.stringify({
          final: { summary: "Merged the child report.", findingIds: [], nextSteps: [], gaps: [] },
        });
      },
    };

    const result = await new GroundedAgent(chat, backend(), "inspect the source", "scope ok").run(
      "inspect the source",
      {
        onSubagent: (label, status, detail) => {
          if (status === "done" && detail) details.push(`${label}:${detail}`);
        },
      },
    );

    expect(result.summary).toContain("Merged");
    expect(childCalls).toBe(7);
    expect(details.some((detail) => detail.includes("7 steps"))).toBe(true);
  });
});
