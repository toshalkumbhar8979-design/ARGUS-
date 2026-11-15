import { describe, expect, test } from "bun:test";
import {
  GroundedAgent,
  type AgentApprovalRequest,
  type AgentBackend,
  type AgentPackageInstallResult,
  type AgentWriteResult,
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

function writeResult(path: string): AgentWriteResult {
  return {
    path,
    bytes: 20,
    created: false,
    additions: 1,
    deletions: 1,
    diff: "--- a\n+++ b\n",
  };
}

function installResult(): AgentPackageInstallResult {
  return {
    command: "npm install zod",
    cwd: ".",
    exitCode: 0,
    stdout: "added 1 package",
    stderr: "",
    durationMs: 12,
    timedOut: false,
    truncated: false,
    manager: "npm",
    package: "zod",
    packageSpec: "zod",
  };
}

describe("agent permission gates", () => {
  test("refuses a write for a read-only question without touching disk", async () => {
    const writes: string[] = [];
    const chat = scripted([
      '{"action":{"tool":"write_file","args":{"path":"src/a.ts","content":"x"}}}',
      '{"final":{"summary":"Explained the parser without editing it.","findingIds":[],"nextSteps":[],"gaps":[]}}',
    ]);
    const agent = new GroundedAgent(
      chat,
      backend({
        writeFile: async (path) => {
          writes.push(path);
          return writeResult(path);
        },
      }),
      "read-only: what does the parser do?",
      "workspace scope",
    );

    const result = await agent.run("read-only: what does the parser do?");

    expect(writes).toEqual([]);
    expect(result.summary).toContain("without editing");
    expect(result.permissionSummary).toContain("read-only");
    expect(result.permissionSummary).toContain("write=off");
  });

  test("edits and installs without a prompt when the operator asks for it", async () => {
    const approvals: AgentApprovalRequest[] = [];
    const writes: string[] = [];
    const installs: string[] = [];
    const chat = scripted([
      '{"action":{"tool":"write_file","args":{"path":"src/a.ts","content":"export const value = 2;\\n"}}}',
      '{"action":{"tool":"install_package","args":{"name":"zod","cwd":"."}}}',
      '{"final":{"summary":"Updated the parser and installed zod.","findingIds":[],"nextSteps":[],"gaps":[]}}',
    ]);
    const agent = new GroundedAgent(
      chat,
      backend({
        writeFile: async (path) => {
          writes.push(path);
          return writeResult(path);
        },
        installPackage: async (request) => {
          installs.push(request.name);
          return installResult();
        },
      }),
      "just do it without asking: fix the parser and install zod",
      "workspace scope",
    );

    const result = await agent.run("just do it without asking: fix the parser and install zod", {
      approve: async (request) => {
        approvals.push(request);
        return false;
      },
    });

    expect(writes).toEqual(["src/a.ts"]);
    expect(installs).toEqual(["zod"]);
    expect(approvals).toEqual([]);
    expect(result.permissionSummary).toContain("install=auto");
  });

  test("lists adapters and globs files with the new tools", async () => {
    const details: string[] = [];
    const chat = scripted([
      '{"action":{"tool":"glob","args":{"pattern":"**/*.ts","limit":10}}}',
      '{"action":{"tool":"security_tools","args":{}}}',
      '{"final":{"summary":"Mapped the source and tool inventory.","findingIds":[],"nextSteps":[],"gaps":[]}}',
    ]);
    const agent = new GroundedAgent(
      chat,
      backend({
        glob: async (pattern) => ({
          pattern,
          matches: [
            { path: "src/a.ts", type: "file", size: 20 },
            { path: "src/b.ts", type: "file", size: 30 },
          ],
          truncated: false,
        }),
        securityTools: async () => [
          {
            id: "nuclei",
            name: "Nuclei",
            category: "vulnerability",
            installed: true,
            version: "3.3.0",
            install: "go install nuclei",
            description: "template checks",
            intrusive: false,
          },
          {
            id: "nmap",
            name: "Nmap",
            category: "network",
            installed: false,
            install: "winget install Insecure.Nmap",
            description: "service detection",
            intrusive: false,
          },
        ],
      }),
      "fix the parser",
      "workspace scope",
    );

    await agent.run("fix the parser", {
      onTool: (_tool, _status, detail) => {
        if (detail) details.push(detail);
      },
    });

    expect(details.some((detail) => detail.includes("2 match"))).toBe(true);
    expect(details.some((detail) => detail.includes("1/2 adapters installed"))).toBe(true);
  });

  test("forwards a subagent write approval to the parent operator", async () => {
    const approvals: AgentApprovalRequest[] = [];
    const edits: string[] = [];
    let parentCalls = 0;
    const chat: ChatClient = {
      async complete(messages) {
        const system = messages[0]?.content ?? "";
        const lastUser = [...messages].reverse().find((message) => message.role === "user")?.content ?? "";
        if (system.includes("You are subagent")) {
          if (lastUser.startsWith("TOOL RESULT edit_file")) {
            return JSON.stringify({
              final: { summary: "The edit was denied.", findingIds: [], nextSteps: [], gaps: [] },
            });
          }
          return JSON.stringify({
            action: { tool: "edit_file", args: { path: "src/a.ts", oldString: "1", newString: "2" } },
          });
        }
        parentCalls += 1;
        if (parentCalls === 1) {
          return JSON.stringify({
            action: {
              tool: "spawn_subagents",
              args: { tasks: [{ label: "audit", role: "auth", prompt: "inspect the auth handler", maxSteps: 3 }] },
            },
          });
        }
        return JSON.stringify({
          final: { summary: "The child needed approval.", findingIds: [], nextSteps: [], gaps: [] },
        });
      },
    };
    const agent = new GroundedAgent(
      chat,
      backend({
        editFile: async (path) => {
          edits.push(path);
          return writeResult(path);
        },
      }),
      "scan https://example.com for bugs",
      "scope ok",
    );

    const result = await agent.run("scan https://example.com for bugs", {
      approve: async (request) => {
        approvals.push(request);
        return false;
      },
    });

    expect(edits).toEqual([]);
    expect(approvals).toHaveLength(1);
    expect(approvals[0]?.kind).toBe("write");
    expect(approvals[0]?.title).toContain("[audit]");
    expect(approvals[0]?.detail).toContain("Subagent");
    expect(result.summary).toContain("needed approval");
  });
});
