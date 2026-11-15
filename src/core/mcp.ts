import { Client } from "@modelcontextprotocol/sdk/client";
// Explicit .js subpaths: Bun 1.3 cannot resolve extensionless wildcard exports
// inside a globally installed package.
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { resolve } from "node:path";
import type { ArgusConfig, JsonRpcToolInfo, McpServerConfig, ProfileId } from "./types";
import { loadScopeFile } from "./config";
import { ensurePromptScope } from "./prompt-scope";
import { ScopeGuard, validateScope } from "./scope";
import { ArgusEngine } from "./engine";
import { generateReport, writeReports } from "./report";
import type { EventBus } from "./events";
import type { ReportFormat } from "./types";

const PROFILES = ["quick", "recon", "web", "api", "network", "deep", "repo"] as const;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const FORMATS = ["markdown", "json", "sarif", "csv", "html", "research"] as const;

interface Connection {
  config: McpServerConfig;
  client: Client;
  tools: JsonRpcToolInfo[];
}

export class McpManager {
  private connections = new Map<string, Connection>();
  private readonly bus?: EventBus;

  constructor(bus?: EventBus) {
    this.bus = bus;
  }

  async connectAll(servers: Record<string, McpServerConfig>): Promise<JsonRpcToolInfo[]> {
    const tools: JsonRpcToolInfo[] = [];
    for (const [name, config] of Object.entries(servers)) {
      if (config.enabled === false) continue;
      try {
        const connection = await this.connect(name, config);
        tools.push(...connection.tools);
        this.bus?.emit({ type: "mcp:status", server: name, status: "connected", message: `${connection.tools.length} tools` });
      } catch (error) {
        this.bus?.emit({
          type: "mcp:status",
          server: name,
          status: "error",
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return tools;
  }

  async connect(name: string, config: McpServerConfig): Promise<Connection> {
    await this.disconnect(name);
    let transport;
    if (config.transport === "stdio") {
      if (!config.command) throw new Error(`MCP server ${name} has no command.`);
      const env = Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
      transport = new StdioClientTransport({
        command: config.command,
        args: config.args ?? [],
        cwd: config.cwd,
        env: { ...env, ...(config.env ?? {}) },
        stderr: "pipe",
      });
    } else {
      if (!config.url) throw new Error(`MCP server ${name} has no URL.`);
      transport = new StreamableHTTPClientTransport(new URL(config.url), {
        requestInit: config.headers ? { headers: config.headers } : undefined,
      });
    }
    const client = new Client({ name: "argus", version: "0.1.0" }, { capabilities: {} });
    await client.connect(transport);
    const listed = await client.listTools();
    const tools: JsonRpcToolInfo[] = listed.tools.map((tool) => ({
      server: name,
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
    }));
    const connection: Connection = { config, client, tools };
    this.connections.set(name, connection);
    return connection;
  }

  listTools(): JsonRpcToolInfo[] {
    return [...this.connections.values()].flatMap((connection) => connection.tools);
  }

  servers(): string[] {
    return [...this.connections.keys()];
  }

  async call(server: string, tool: string, args: Record<string, unknown> = {}): Promise<unknown> {
    const connection = this.connections.get(server);
    if (!connection) throw new Error(`MCP server ${server} is not connected.`);
    const result = await connection.client.callTool({ name: tool, arguments: args });
    if (result.structuredContent && Object.keys(result.structuredContent).length > 0) return result.structuredContent;
    const content = Array.isArray(result.content) ? result.content : [];
    const text = content
      .filter((item): item is { type: "text"; text: string } => typeof item === "object" && item !== null && (item as { type?: string }).type === "text")
      .map((item) => item.text)
      .join("\n");
    if (text) {
      try {
        return JSON.parse(text) as unknown;
      } catch {
        return text;
      }
    }
    return result;
  }

  async disconnect(name?: string): Promise<void> {
    const targets = name ? [name] : [...this.connections.keys()];
    for (const target of targets) {
      const connection = this.connections.get(target);
      if (!connection) continue;
      try {
        await connection.client.close();
      } catch {
        // connection may already be gone
      }
      this.connections.delete(target);
      this.bus?.emit({ type: "mcp:status", server: target, status: "disconnected" });
    }
  }
}

export async function runMcpServer(config: ArgusConfig): Promise<void> {
  const engine = new ArgusEngine(config);
  const server = new McpServer({ name: "argus", version: "0.1.0" });

  server.registerTool(
    "argus_scan",
    {
      title: "Run authorized ARGUS assessment",
      description: "Run a security assessment. Scope is derived from the target unless a manual scopePath is supplied.",
      inputSchema: {
        target: z.string().describe("Authorized URL, host, CIDR or repository path."),
        scopePath: z.string().optional().describe("Optional manual scope JSON file; never overwritten."),
        profile: z.enum(PROFILES).optional(),
        authorized: z.boolean().optional().describe("Legacy compatibility flag; the named target is the authorization."),
        intrusive: z.boolean().optional(),
        passive: z.boolean().optional(),
        allowExternal: z.boolean().optional(),
        formats: z.array(z.enum(FORMATS)).optional(),
      },
      annotations: { destructiveHint: false, openWorldHint: true },
    },
    async (args) => {
      try {
        const profile = (args.profile ?? config.defaultProfile) as ProfileId;
        let scopePath = args.scopePath ?? resolve("scope.json");
        if (!args.scopePath) {
          const ensured = await ensurePromptScope(scopePath, args.target, {
            workspace: process.cwd(),
            targets: [args.target],
            profile,
            passive: Boolean(args.passive),
            intrusive: Boolean(args.intrusive),
            external: args.allowExternal ?? true,
            override: true,
            maxRps: config.maxRps,
          });
          scopePath = ensured.path;
        }
        const handle = await engine.run(
          {
            target: args.target,
            scopePath,
            options: {
              profile,
              intrusive: Boolean(args.intrusive),
              passiveOnly: Boolean(args.passive),
              allowExternal: args.allowExternal,
              exportFormats: (args.formats ?? ["markdown", "json", "sarif"]) as ReportFormat[],
            },
          },
          { onEvent: () => {} },
        );
        return toolJson({
          runId: handle.record.id,
          status: handle.record.status,
          target: handle.record.target.display,
          counts: handle.record.counts,
          findings: handle.findings.slice(0, 100).map(summaryFinding),
          truncated: handle.findings.length > 100,
        });
      } catch (error) {
        return toolError(error instanceof Error ? error.message : String(error));
      }
    },
  );

  server.registerTool(
    "argus_findings",
    {
      title: "Read ARGUS findings",
      description: "Load persisted findings for a run.",
      inputSchema: {
        runId: z.string(),
        severity: z.enum(SEVERITIES).optional(),
        limit: z.number().int().min(1).max(1000).optional(),
      },
    },
    async (args) => {
      const handle = await engine.store.load(args.runId);
      if (!handle) return toolError(`Run not found: ${args.runId}`);
      const filtered = args.severity ? handle.findings.filter((finding) => finding.severity === args.severity) : handle.findings;
      return toolJson({
        runId: args.runId,
        counts: handle.record.counts,
        findings: filtered.slice(0, args.limit ?? 200),
        truncated: filtered.length > (args.limit ?? 200),
      });
    },
  );

  server.registerTool(
    "argus_report",
    {
      title: "Generate ARGUS reports",
      description: "Regenerate reports for a persisted run.",
      inputSchema: {
        runId: z.string(),
        formats: z.array(z.enum(FORMATS)).optional(),
      },
    },
    async (args) => {
      const handle = await engine.store.load(args.runId);
      if (!handle) return toolError(`Run not found: ${args.runId}`);
      const formats = (args.formats ?? ["markdown", "json", "sarif"]) as ReportFormat[];
      const paths = await writeReports(engine.store, handle, formats);
      return toolJson({ runId: args.runId, paths });
    },
  );

  server.registerTool(
    "argus_tools",
    {
      title: "Detect external tools",
      description: "List optional external scanner adapters and installation hints.",
      inputSchema: {},
    },
    async () => {
      const tools = await engine.tools(true);
      return toolJson(tools);
    },
  );

  server.registerTool(
    "argus_scope_check",
    {
      title: "Validate authorization and scope",
      description: "Validate the active scope and check whether a target is authorized.",
      inputSchema: {
        scopePath: z.string().optional().describe("Optional manual scope file; omit to derive one from the target."),
        target: z.string(),
        profile: z.enum(PROFILES).optional(),
      },
    },
    async (args) => {
      try {
        const profile = (args.profile ?? config.defaultProfile) as ProfileId;
        const scope = args.scopePath
          ? await loadScopeFile(args.scopePath)
          : (await ensurePromptScope(resolve("scope.json"), args.target, {
              workspace: process.cwd(),
              targets: [args.target],
              profile,
              override: true,
              maxRps: config.maxRps,
            })).scope;
        const validation = validateScope(scope);
        if (!validation.ok) return toolJson({ allowed: false, validation });
        const guard = new ScopeGuard(scope);
        const target = guard.resolveTarget(args.target, profile);
        return toolJson({ allowed: true, validation, target });
      } catch (error) {
        return toolJson({ allowed: false, error: error instanceof Error ? error.message : String(error) });
      }
    },
  );

  server.registerTool(
    "argus_runs",
    {
      title: "List ARGUS runs",
      description: "List recent assessment runs.",
      inputSchema: { limit: z.number().int().min(1).max(100).optional() },
    },
    async (args) => toolJson(await engine.store.list(args.limit ?? 20)),
  );

  server.registerTool(
    "argus_preview",
    {
      title: "Preview ARGUS report",
      description: "Render a report without writing it to disk.",
      inputSchema: {
        runId: z.string(),
        format: z.enum(FORMATS).optional(),
      },
    },
    async (args) => {
      const handle = await engine.store.load(args.runId);
      if (!handle) return toolError(`Run not found: ${args.runId}`);
      return { content: [{ type: "text", text: generateReport(handle, (args.format ?? "markdown") as ReportFormat) }] };
    },
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

function summarizeFinding(finding: import("./types").Finding): Record<string, unknown> {
  return {
    id: finding.id,
    severity: finding.severity,
    confidence: finding.confidence,
    title: finding.title,
    category: finding.category,
    target: finding.target,
    url: finding.url,
    cwe: finding.cwe,
    tool: finding.tool,
  };
}

function summaryFinding(finding: import("./types").Finding): Record<string, unknown> {
  return summarizeFinding(finding);
}

function toolJson(value: unknown): { content: Array<{ type: "text"; text: string }> } {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

function toolError(message: string): { content: Array<{ type: "text"; text: string }>; isError: true } {
  return { content: [{ type: "text", text: message }], isError: true };
}
