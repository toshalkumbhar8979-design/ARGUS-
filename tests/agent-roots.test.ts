import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createEngineBackend, GroundedAgent, type ChatMessage } from "../src/core/agent";
import { defaultConfig } from "../src/core/config";
import { ArgusEngine } from "../src/core/engine";
import type { ScopePolicy } from "../src/core/types";

let cleanups: string[] = [];

afterEach(async () => {
  for (const path of cleanups) await rm(path, { recursive: true, force: true });
  cleanups = [];
});

async function dir(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  cleanups.push(path);
  return path;
}

describe("agent local roots", () => {
  test("reads and searches a prompt-authorized root outside the workspace", async () => {
    const workspace = await dir("argus-agent-ws-");
    const repo = await dir("argus-agent-repo-");
    await writeFile(join(repo, "note.ts"), "export const apiSecret = 'do-not-leak';\n", "utf8");

    const scope: ScopePolicy = {
      version: 1,
      name: "Prompt root test",
      authorizedBy: "operator prompt",
      authorizationRef: "PROMPT test",
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      allow: [workspace, repo],
      deny: [],
      allowActive: false,
      allowExternal: false,
    };
    const scopePath = join(workspace, "scope.json");
    await writeFile(scopePath, `${JSON.stringify(scope, null, 2)}\n`, "utf8");
    const config = { ...defaultConfig(), dataDir: workspace };
    const backend = createEngineBackend(new ArgusEngine(config), config, scopePath, workspace, [repo]);

    const file = await backend.readFile("note.ts");
    expect(file.content).toContain("do-not-leak");
    expect(file.path).toBe(join(repo, "note.ts").replace(/\\/g, "/"));

    const hits = await backend.search("apiSecret", true);
    expect(hits.some((hit) => hit.path.replace(/\\/g, "/").endsWith("/note.ts"))).toBe(true);
  });

  test("previews a real change against a real file and writes nothing", async () => {
    const workspace = await dir("argus-agent-ws-");
    const repo = await dir("argus-agent-preview-");
    const target = join(repo, "app.ts");
    await writeFile(target, "const port = 3000;\n", "utf8");
    const scope: ScopePolicy = {
      version: 1,
      name: "Preview test",
      authorizedBy: "operator prompt",
      authorizationRef: "PROMPT test",
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      allow: [workspace, repo],
      deny: [],
      allowActive: false,
      allowExternal: false,
    };
    const scopePath = join(workspace, "scope.json");
    await writeFile(scopePath, `${JSON.stringify(scope, null, 2)}\n`, "utf8");
    const config = { ...defaultConfig(), dataDir: workspace };
    const backend = createEngineBackend(new ArgusEngine(config), config, scopePath, workspace, [repo]);

    const replies = [
      '{"thought":"preview","action":{"tool":"preview","args":{"path":"app.ts","content":"const port = 4000;\\n"}}}',
      '{"final":{"summary":"Previewed without writing.","findingIds":[],"nextSteps":[],"gaps":[]}}',
    ];
    const transcripts: string[] = [];
    let index = 0;
    const chat = {
      async complete(messages: ChatMessage[]) {
        transcripts.push(messages.map((message) => message.content).join("\n"));
        const reply = replies[Math.min(index, replies.length - 1)];
        index += 1;
        return reply ?? "";
      },
    };
    const agent = new GroundedAgent(chat, backend, "preview the change", "workspace scope");
    let approvals = 0;

    await agent.run("preview the change", {
      approve: async () => {
        approvals += 1;
        return true;
      },
    });

    expect(approvals).toBe(0);
    expect(transcripts.join("\n")).toContain("+const port = 4000;");
    expect(await readFile(target, "utf8")).toBe("const port = 3000;\n");
  });

  test("rejects a file outside every authorized root", async () => {
    const workspace = await dir("argus-agent-ws-");
    const repo = await dir("argus-agent-repo-");
    const outside = await dir("argus-agent-outside-");
    await writeFile(join(outside, "secret.ts"), "const nope = 1;\n", "utf8");
    const config = { ...defaultConfig(), dataDir: workspace };
    const scopePath = join(workspace, "scope.json");
    await writeFile(scopePath, "{}\n", "utf8");
    const backend = createEngineBackend(new ArgusEngine(config), config, scopePath, workspace, [repo]);

    await expect(backend.readFile(join(outside, "secret.ts"))).rejects.toThrow(/outside the authorized local roots/);
  });
});
