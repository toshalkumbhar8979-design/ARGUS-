import { describe, expect, test } from "bun:test";
import {
  GroundedAgent,
  type AgentApprovalRequest,
  type AgentBackend,
  type ChatClient,
  type ChatMessage,
} from "../src/core/agent";

function backend(overrides: Partial<AgentBackend> = {}): AgentBackend {
  return {
    workspace: process.cwd(),
    scan: async () => {
      throw new Error("scan is not used in this test");
    },
    listRuns: async () => [],
    loadRun: async () => null,
    readFile: async (path) => ({ path, content: "const value = 1;\n", bytes: 17 }),
    search: async () => [],
    validateTarget: async () => undefined,
    ...overrides,
  };
}

function scripted(replies: string[]): ChatClient {
  let index = 0;
  return {
    async complete(_messages: ChatMessage[]) {
      const reply = replies[Math.min(index, replies.length - 1)];
      index += 1;
      return reply ?? "";
    },
  };
}

function nativeClient(turns: Array<{ text: string; toolCalls: Array<{ id: string; name: string; arguments: Record<string, unknown>; raw?: string }> }>): {
  client: ChatClient;
  seen: ChatMessage[][];
} {
  let index = 0;
  const seen: ChatMessage[][] = [];
  return {
    seen,
    client: {
      async complete() {
        throw new Error("the native client should not fall back to plain text");
      },
      async completeWithTools(request) {
        seen.push(request.messages.map((message) => ({ ...message })));
        const turn = turns[Math.min(index, turns.length - 1)];
        index += 1;
        return {
          text: turn?.text ?? "",
          toolCalls: (turn?.toolCalls ?? []).map((call) => ({
            id: call.id,
            name: call.name,
            arguments: call.arguments,
            raw: call.raw ?? JSON.stringify(call.arguments),
          })),
        };
      },
    },
  };
}

function recorded(replies: string[]): { client: ChatClient; transcripts: string[] } {
  let index = 0;
  const transcripts: string[] = [];
  return {
    transcripts,
    client: {
      async complete(messages: ChatMessage[]) {
        transcripts.push(messages.map((message) => message.content).join("\n"));
        const reply = replies[Math.min(index, replies.length - 1)];
        index += 1;
        return reply ?? "";
      },
    },
  };
}

describe("agent workspace tools", () => {
  test("publishes the plan and asks before a destructive command", async () => {
    const commands: string[] = [];
    const approvals: AgentApprovalRequest[] = [];
    const chat = scripted([
      '{"thought":"plan","action":{"tool":"todo_write","args":{"items":[{"task":"inspect the build","status":"done"},{"task":"clean stale output","status":"running"}]}}}',
      '{"thought":"clean","action":{"tool":"run_command","args":{"command":"rm -rf build"}}}',
      '{"final":{"summary":"Cleanup finished without deleting anything.","findingIds":[],"nextSteps":[],"gaps":["operator denied the destructive command"]}}',
    ]);
    const agent = new GroundedAgent(chat, backend({
      runCommand: async (command) => {
        commands.push(command);
        return {
          command,
          cwd: ".",
          exitCode: 0,
          stdout: "",
          stderr: "",
          durationMs: 1,
          timedOut: false,
          truncated: false,
        };
      },
    }), "clean up the build", "workspace scope");

    const result = await agent.run("clean up the build", {
      approve: async (request) => {
        approvals.push(request);
        return false;
      },
    });

    expect(approvals).toHaveLength(1);
    expect(approvals[0]?.kind).toBe("command");
    expect(approvals[0]?.command).toBe("rm -rf build");
    expect(commands).toHaveLength(0);
    expect(result.plan).toEqual([
      { task: "inspect the build", status: "done" },
      { task: "clean stale output", status: "running" },
    ]);
    expect(result.summary).toContain("Cleanup finished");
  });

  test("runs the command after approval and reports the exit status", async () => {
    const commands: string[] = [];
    const chat = scripted([
      '{"thought":"run tests","action":{"tool":"run_command","args":{"command":"npm test"}}}',
      '{"final":{"summary":"Tests passed.","findingIds":[],"nextSteps":[],"gaps":[]}}',
    ]);
    const agent = new GroundedAgent(chat, backend({
      runCommand: async (command) => {
        commands.push(command);
        return {
          command,
          cwd: ".",
          exitCode: 0,
          stdout: "12 passing",
          stderr: "",
          durationMs: 42,
          timedOut: false,
          truncated: false,
        };
      },
    }), "run the tests", "workspace scope");

    const result = await agent.run("run the tests", { approve: async () => true });

    expect(commands).toEqual(["npm test"]);
    expect(result.summary).toContain("Tests passed");
    expect(result.steps).toBeGreaterThanOrEqual(2);
  });

  test("previews a proposed change as a diff and writes nothing", async () => {
    const writes: string[] = [];
    const approvals: string[] = [];
    const chat = recorded([
      '{"thought":"preview the edit","action":{"tool":"preview","args":{"path":"src/a.ts","content":"const value = 2;\\n"}}}',
      '{"final":{"summary":"Previewed the change.","findingIds":[],"nextSteps":[],"gaps":[]}}',
    ]);
    const agent = new GroundedAgent(chat.client, backend({
      readFile: async (path) => ({ path, content: "const value = 1;\n", bytes: 17 }),
      writeFile: async (path) => {
        writes.push(path);
        return { path, bytes: 0, created: false, additions: 0, deletions: 0, diff: "" };
      },
    }), "preview the change", "workspace scope");

    const result = await agent.run("preview the change", {
      approve: async (request) => {
        approvals.push(request.detail);
        return true;
      },
    });

    const transcript = chat.transcripts.join("\n");
    expect(writes).toHaveLength(0);
    expect(approvals).toHaveLength(0);
    expect(transcript).toContain("preview only; nothing was written");
    expect(transcript).toContain('"mode":"write"');
    expect(transcript).toContain("+const value = 2;");
    expect(transcript).toContain("-const value = 1;");
    expect(result.summary).toContain("Previewed");
  });

  test("drives the loop with native tool calls and answers in prose", async () => {
    const reads: string[] = [];
    const statuses: string[] = [];
    const native = nativeClient([
      {
        text: "",
        toolCalls: [
          { id: "call_1", name: "read_file", arguments: { path: "src/a.ts" } },
        ],
      },
      { text: "The file defines a constant value.", toolCalls: [] },
    ]);
    const agent = new GroundedAgent(
      native.client,
      backend({
        readFile: async (path) => {
          reads.push(path);
          return { path, content: "const value = 1;\n", bytes: 17 };
        },
      }),
      "explain src/a.ts",
      "workspace scope",
    );

    const result = await agent.run("explain src/a.ts", {
      onTool: (tool, status) => statuses.push(`${tool}:${status}`),
    });

    expect(reads).toEqual(["src/a.ts"]);
    expect(statuses).toContain("read_file:start");
    expect(statuses).toContain("read_file:done");
    expect(result.summary).toContain("defines a constant value");

    const second = native.seen[1] ?? [];
    const assistant = second.find((message) => message.role === "assistant" && message.tool_calls?.length);
    expect(assistant?.tool_calls?.[0]?.id).toBe("call_1");
    expect(assistant?.tool_calls?.[0]?.function.name).toBe("read_file");
    const toolMessage = second.find((message) => message.role === "tool");
    expect(toolMessage?.tool_call_id).toBe("call_1");
    expect(toolMessage?.content).toContain("const value = 1;");
  });

  test("shows the diff in the write approval prompt", async () => {
    const details: string[] = [];
    const chat = scripted([
      '{"thought":"write the file","action":{"tool":"write_file","args":{"path":"src/a.ts","content":"const value = 2;\\n"}}}',
      '{"final":{"summary":"Wrote the file.","findingIds":[],"nextSteps":[],"gaps":[]}}',
    ]);
    const agent = new GroundedAgent(chat, backend({
      readFile: async (path) => ({ path, content: "const value = 1;\n", bytes: 17 }),
      writeFile: async (path, content) => ({
        path,
        bytes: content.length,
        created: false,
        additions: 1,
        deletions: 1,
        diff: "",
      }),
    }), "write the file", "workspace scope");

    await agent.run("write the file", {
      approve: async (request) => {
        details.push(request.detail);
        return true;
      },
    });

    expect(details).toHaveLength(1);
    expect(details[0]).toContain("Write src/a.ts");
    expect(details[0]).toContain("+const value = 2;");
    expect(details[0]).toContain("-const value = 1;");
  });

  test("blocks privilege escalation and reports the safety rule", async () => {
    const chat = scripted([
      '{"thought":"try elevation","action":{"tool":"run_command","args":{"command":"sudo rm -rf build"}}}',
      '{"final":{"summary":"Could not elevate.","findingIds":[],"nextSteps":[],"gaps":[]}}',
    ]);
    const agent = new GroundedAgent(chat, backend(), "clean the build", "workspace scope");
    const result = await agent.run("clean the build", { approve: async () => true });
    expect(result.summary).toContain("Could not elevate");
  });
});
