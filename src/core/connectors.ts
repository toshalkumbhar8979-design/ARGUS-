import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { createHmac } from "node:crypto";
import type { ConnectorConfig, Finding, RunHandle } from "./types";
import type { EventBus } from "./events";
import { SEVERITY_RANK } from "./types";
import { truncate } from "./util";

export interface ConnectorResult {
  id: string;
  type: ConnectorConfig["type"];
  status: "sent" | "failed" | "skipped";
  message?: string;
}

export async function runConnectors(configs: ConnectorConfig[], run: RunHandle, bus?: EventBus): Promise<ConnectorResult[]> {
  const results: ConnectorResult[] = [];
  for (const config of configs) {
    if (!config.enabled) continue;
    const threshold = config.minSeverity ? SEVERITY_RANK[config.minSeverity] : SEVERITY_RANK.info;
    const selected = run.findings.filter((finding) => SEVERITY_RANK[finding.severity] <= threshold);
    if (selected.length === 0) {
      const result: ConnectorResult = { id: config.id, type: config.type, status: "skipped", message: "No findings met the severity threshold." };
      results.push(result);
      bus?.emit({ type: "connector:status", connector: config.id, status: "skipped", message: result.message });
      continue;
    }
    try {
      await send(config, { ...run, findings: selected });
      const result: ConnectorResult = { id: config.id, type: config.type, status: "sent", message: `${selected.length} findings` };
      results.push(result);
      bus?.emit({ type: "connector:status", connector: config.id, status: "sent", message: result.message });
    } catch (error) {
      const result: ConnectorResult = {
        id: config.id,
        type: config.type,
        status: "failed",
        message: error instanceof Error ? error.message : String(error),
      };
      results.push(result);
      bus?.emit({ type: "connector:status", connector: config.id, status: "failed", message: result.message });
    }
  }
  return results;
}

async function send(config: ConnectorConfig, run: RunHandle): Promise<void> {
  switch (config.type) {
    case "webhook":
      return sendWebhook(config, run);
    case "slack":
      return sendSlack(config, run);
    case "discord":
      return sendDiscord(config, run);
    case "github":
      return sendGithub(config, run);
    case "jira":
      return sendJira(config, run);
    case "file":
      return sendFile(config, run);
  }
}

async function sendWebhook(config: ConnectorConfig, run: RunHandle): Promise<void> {
  const url = stringOption(config, "url");
  if (!url) throw new Error("Webhook connector requires options.url.");
  const body = JSON.stringify(payload(run));
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "user-agent": "Argus/0.1",
    ...parseHeaders(stringOption(config, "headers")),
  };
  const token = stringOption(config, "token");
  if (token) headers.authorization = token.startsWith("Bearer ") ? token : `Bearer ${token}`;
  const secret = stringOption(config, "secret");
  if (secret) headers["x-argus-signature"] = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
  await postJson(url, body, headers);
}

async function sendSlack(config: ConnectorConfig, run: RunHandle): Promise<void> {
  const url = stringOption(config, "webhookUrl") ?? stringOption(config, "url");
  if (!url) throw new Error("Slack connector requires options.webhookUrl.");
  const lines = [
    `*ARGUS ${run.record.status.toUpperCase()}* — ${run.record.target.display}`,
    `Scope: ${run.record.scope.name} | Run: \`${run.record.id}\``,
    `Critical ${run.record.counts.critical} | High ${run.record.counts.high} | Medium ${run.record.counts.medium} | Low ${run.record.counts.low} | Info ${run.record.counts.info}`,
    "",
    ...run.findings.slice(0, 15).map((finding) => `• [${finding.severity.toUpperCase()}] ${truncate(finding.title, 180)}`),
    run.findings.length > 15 ? `…and ${run.findings.length - 15} more` : "",
  ].filter(Boolean);
  await postJson(url, JSON.stringify({ text: lines.join("\n") }), { "content-type": "application/json" });
}

async function sendDiscord(config: ConnectorConfig, run: RunHandle): Promise<void> {
  const url = stringOption(config, "webhookUrl") ?? stringOption(config, "url");
  if (!url) throw new Error("Discord connector requires options.webhookUrl.");
  const lines = [
    `**ARGUS ${run.record.status.toUpperCase()}** — ${run.record.target.display}`,
    `Run \`${run.record.id}\` | Scope: ${run.record.scope.name}`,
    `C:${run.record.counts.critical} H:${run.record.counts.high} M:${run.record.counts.medium} L:${run.record.counts.low}`,
    "",
    ...run.findings.slice(0, 12).map((finding) => `• **[${finding.severity.toUpperCase()}]** ${truncate(finding.title, 160)}`),
  ];
  await postJson(url, JSON.stringify({ content: truncate(lines.join("\n"), 1900) }), { "content-type": "application/json" });
}

async function sendGithub(config: ConnectorConfig, run: RunHandle): Promise<void> {
  const token = stringOption(config, "token");
  const owner = stringOption(config, "owner");
  const repo = stringOption(config, "repo");
  if (!token || !owner || !repo) throw new Error("GitHub connector requires options.token, options.owner and options.repo.");
  const api = stringOption(config, "apiUrl") ?? "https://api.github.com";
  const labels = stringOption(config, "labels")?.split(",").map((label) => label.trim()).filter(Boolean) ?? ["security", "argus"];
  const body = {
    title: `[ARGUS] ${run.record.target.display} — ${run.record.counts.critical} critical, ${run.record.counts.high} high`,
    body: markdownSummary(run),
    labels,
  };
  await postJson(`${api.replace(/\/$/, "")}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues`, JSON.stringify(body), {
    "content-type": "application/json",
    authorization: `Bearer ${token}`,
    accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28",
    "user-agent": "Argus/0.1",
  });
}

async function sendJira(config: ConnectorConfig, run: RunHandle): Promise<void> {
  const baseUrl = stringOption(config, "baseUrl");
  const email = stringOption(config, "email");
  const token = stringOption(config, "token");
  const projectKey = stringOption(config, "projectKey");
  if (!baseUrl || !email || !token || !projectKey) {
    throw new Error("Jira connector requires options.baseUrl, options.email, options.token and options.projectKey.");
  }
  const issueType = stringOption(config, "issueType") ?? "Task";
  const auth = Buffer.from(`${email}:${token}`).toString("base64");
  const body = {
    fields: {
      project: { key: projectKey },
      summary: `[ARGUS] ${run.record.target.display} — ${run.record.counts.critical} critical / ${run.record.counts.high} high`,
      description: markdownSummary(run),
      issuetype: { name: issueType },
      labels: ["argus", "security"],
    },
  };
  await postJson(`${baseUrl.replace(/\/$/, "")}/rest/api/2/issue`, JSON.stringify(body), {
    "content-type": "application/json",
    authorization: `Basic ${auth}`,
    accept: "application/json",
  });
}

async function sendFile(config: ConnectorConfig, run: RunHandle): Promise<void> {
  const path = stringOption(config, "path");
  if (!path) throw new Error("File connector requires options.path.");
  const format = stringOption(config, "format") ?? "jsonl";
  await mkdir(dirname(path), { recursive: true });
  const content =
    format === "markdown"
      ? `${markdownSummary(run)}\n`
      : `${JSON.stringify({ run: run.record, findings: run.findings })}\n`;
  if (format === "markdown") {
    await appendFile(path, content, "utf8");
  } else {
    await appendFile(path, content, "utf8");
  }
}

function payload(run: RunHandle): Record<string, unknown> {
  return {
    source: "argus",
    version: "0.1.0",
    run: run.record,
    findings: run.findings.map(compactFinding),
  };
}

function compactFinding(finding: Finding): Record<string, unknown> {
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
    evidence: finding.evidence,
    remediation: finding.remediation,
    fingerprint: finding.fingerprint,
  };
}

function markdownSummary(run: RunHandle): string {
  const lines = [
    `# ARGUS assessment — ${run.record.target.display}`,
    "",
    `- Run: \`${run.record.id}\``,
    `- Status: ${run.record.status}`,
    `- Profile: ${run.record.profile}`,
    `- Scope: ${run.record.scope.name}`,
    `- Authorized by: ${run.record.scope.authorizedBy}`,
    `- Authorization: ${run.record.scope.authorizationRef}`,
    "",
    "## Counts",
    "",
    `Critical: ${run.record.counts.critical} | High: ${run.record.counts.high} | Medium: ${run.record.counts.medium} | Low: ${run.record.counts.low} | Info: ${run.record.counts.info}`,
    "",
    "## Findings",
    "",
  ];
  for (const finding of run.findings.slice(0, 100)) {
    lines.push(`### [${finding.severity.toUpperCase()}] ${finding.title}`);
    lines.push(`- Target: ${finding.target}`);
    if (finding.url) lines.push(`- URL: ${finding.url}`);
    lines.push(`- Tool: ${finding.tool} | Confidence: ${finding.confidence}`);
    lines.push(`- Evidence: ${truncate(finding.evidence.replace(/\s+/g, " "), 500)}`);
    lines.push(`- Remediation: ${finding.remediation}`);
    lines.push("");
  }
  if (run.findings.length > 100) lines.push(`…and ${run.findings.length - 100} more findings in the ARGUS report.`);
  return lines.join("\n");
}

async function postJson(url: string, body: string, headers: Record<string, string>): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Connector URL is invalid.");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error("Connector URL must use HTTP or HTTPS.");
  const response = await fetch(parsed, {
    method: "POST",
    headers,
    body,
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Connector responded HTTP ${response.status}: ${truncate(text, 300)}`);
  }
}

function stringOption(config: ConnectorConfig, key: string): string | undefined {
  const value = config.options[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function parseHeaders(value: string | undefined): Record<string, string> {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    return Object.fromEntries(Object.entries(parsed).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
  } catch {
    return {};
  }
}
