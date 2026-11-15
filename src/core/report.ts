import { join } from "node:path";
import type { Finding, ReportFormat, RunHandle, Severity } from "./types";
import { buildPipeline, renderPipelineHtml, renderPipelineMarkdown } from "./pipeline";
import { buildFixPlan } from "./remediation";
import { formatDuration, oneLine, sortFindings } from "./util";
import type { RunStore } from "./store";

const FORMAT_EXT: Record<ReportFormat, string> = {
  markdown: "md",
  json: "json",
  sarif: "sarif",
  csv: "csv",
  html: "html",
  research: "research.md",
};

export function generateReport(run: RunHandle, format: ReportFormat, extra: { journal?: string } = {}): string {
  switch (format) {
    case "markdown":
      return renderMarkdown(run);
    case "json":
      return `${JSON.stringify(run, null, 2)}\n`;
    case "sarif":
      return `${JSON.stringify(renderSarif(run), null, 2)}\n`;
    case "csv":
      return renderCsv(run);
    case "html":
      return renderHtml(run);
    case "research":
      return renderResearch(run, extra.journal);
  }
}

export async function writeReports(
  store: RunStore,
  run: RunHandle,
  formats: ReportFormat[],
  extra: { journal?: string } = {},
): Promise<string[]> {
  const output: string[] = [];
  for (const format of formats) {
    const content = generateReport(run, format, extra);
    const path = await store.writeArtifact(run.record.id, `report.${FORMAT_EXT[format]}`, content);
    output.push(path);
  }
  return output;
}

export function reportFilename(runId: string, format: ReportFormat): string {
  return join("exports", `${runId}.${FORMAT_EXT[format]}`);
}

function renderMarkdown(run: RunHandle): string {
  const { record, findings } = run;
  const sorted = sortFindings(findings);
  const lines: string[] = [];
  lines.push(`# ARGUS Security Assessment — ${escapeMd(record.target.display)}`);
  lines.push("");
  lines.push(`- **Run ID:** \`${record.id}\``);
  lines.push(`- **Profile:** ${record.profile}`);
  lines.push(`- **Status:** ${record.status}`);
  lines.push(`- **Target:** ${escapeMd(record.target.display)}`);
  lines.push(`- **Created:** ${record.createdAt}`);
  if (record.finishedAt) lines.push(`- **Finished:** ${record.finishedAt}`);
  if (record.startedAt && record.finishedAt) lines.push(`- **Duration:** ${formatDuration(Date.parse(record.finishedAt) - Date.parse(record.startedAt))}`);
  lines.push(`- **Authorization:** ${escapeMd(record.scope.authorizedBy)} (${escapeMd(record.scope.authorizationRef)})`);
  lines.push(`- **Scope:** ${escapeMd(record.scope.name)} — expires ${record.scope.expiresAt}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("| --- | ---: |");
  for (const severity of ["critical", "high", "medium", "low", "info"] as const) {
    lines.push(`| ${severity.toUpperCase()} | ${record.counts[severity] ?? 0} |`);
  }
  lines.push(`| **Total** | **${findings.length}** |`);
  lines.push("");
  lines.push(...renderPipelineMarkdown(buildPipeline(findings)));
  const plan = buildFixPlan(findings, 8);
  if (plan.length > 0) {
    lines.push("## Fix plan");
    lines.push("");
    for (const [index, action] of plan.entries()) {
      lines.push(`${index + 1}. **${action.priority} / ${action.severity.toUpperCase()}** — ${escapeMd(action.remediation)}`);
      if (action.count > 1) lines.push(`   - Applies to ${action.count} findings: ${escapeMd(action.examples.join("; "))}`);
    }
    lines.push("");
  }
  if (record.dependencies) {
    const graph = record.dependencies.summary;
    lines.push("## Dependency graph");
    lines.push("");
    lines.push(`- **Package manager:** ${graph.packageManager}`);
    lines.push(`- **Graph:** ${graph.nodes} nodes, ${graph.direct} direct, ${graph.transitive} transitive, ${graph.edges} edges`);
    lines.push(`- **Outdated direct dependencies:** ${graph.outdated} (${graph.latestCheck === "registry" ? "npm registry checked" : "latest check skipped"})`);
    lines.push("");
  }
  lines.push("## Findings");
  if (sorted.length === 0) {
    lines.push("");
    lines.push("No findings were recorded.");
  }
  for (const [index, finding] of sorted.entries()) {
    lines.push("");
    lines.push(`### ${index + 1}. [${finding.severity.toUpperCase()}] ${escapeMd(finding.title)}`);
    lines.push("");
    lines.push(`- **Category:** ${finding.category}`);
    lines.push(`- **Confidence:** ${finding.confidence}`);
    lines.push(`- **Tool:** ${finding.tool}`);
    lines.push(`- **Target:** ${escapeMd(finding.target)}`);
    if (finding.url) lines.push(`- **URL:** ${finding.url}`);
    if (finding.cwe) lines.push(`- **CWE:** ${finding.cwe}`);
    if (finding.owasp) lines.push(`- **OWASP:** ${finding.owasp}`);
    if (finding.cvss) {
      lines.push(`- **CVSS:** ${finding.cvss.score.toFixed(1)} (${finding.cvss.vector})`);
    }
    lines.push(`- **Fingerprint:** \`${finding.fingerprint}\``);
    lines.push("");
    lines.push("**Description**");
    lines.push("");
    lines.push(finding.description || "No description.");
    lines.push("");
    lines.push("**Evidence**");
    lines.push("");
    lines.push("```text");
    lines.push(finding.evidence || "No evidence captured.");
    lines.push("```");
    lines.push("");
    lines.push("**Remediation**");
    lines.push("");
    lines.push(finding.remediation || "No remediation guidance.");
    if (finding.references.length > 0) {
      lines.push("");
      lines.push("**References**");
      for (const reference of finding.references) lines.push(`- ${reference}`);
    }
  }
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("Generated by ARGUS. Validate all findings before remediation or disclosure.");
  lines.push("");
  return lines.join("\n");
}

/**
 * Research report: the narrative deliverable a human reads end to end. It is
 * built from stored evidence only - pipeline state, findings, CVSS and the
 * dependency graph - and never adds a vulnerability the tools did not record.
 */
function renderResearch(run: RunHandle, journal?: string): string {
  const { record, findings } = run;
  const sorted = sortFindings(findings);
  const confirmed = findings.filter((finding) => finding.confidence === "confirmed").length;
  const actionable = findings.filter((finding) => ["critical", "high", "medium"].includes(finding.severity)).length;
  const critical = findings.filter((finding) => finding.severity === "critical").length;
  const high = findings.filter((finding) => finding.severity === "high").length;
  const lines: string[] = [];
  lines.push(`# Research report: ${escapeMd(record.target.display)}`);
  lines.push("");
  lines.push(
    `Authorized assessment of \`${escapeMd(record.target.display)}\` (${record.profile} profile), run \`${record.id}\`, ` +
      `under ${escapeMd(record.scope.authorizedBy)} / ${escapeMd(record.scope.authorizationRef)}.`,
  );
  lines.push("");
  lines.push("## Executive summary");
  lines.push("");
  lines.push(
    `${findings.length} finding(s) were recorded by real tool runs: ${critical} critical, ${high} high, ` +
      `${actionable} actionable at medium or above, ${confirmed} confirmed by reproduction.`,
  );
  if (sorted[0]) {
    lines.push("");
    lines.push(`The most severe observation is **${sorted[0].severity.toUpperCase()} - ${escapeMd(sorted[0].title)}** (${escapeMd(sorted[0].target)}).`);
  }
  lines.push("");
  lines.push("## Engagement facts");
  lines.push("");
  lines.push(`- **Run:** \`${record.id}\``);
  lines.push(`- **Profile:** ${record.profile}`);
  lines.push(`- **Status:** ${record.status}`);
  lines.push(`- **Created:** ${record.createdAt}`);
  if (record.startedAt && record.finishedAt) {
    lines.push(`- **Duration:** ${formatDuration(Date.parse(record.finishedAt) - Date.parse(record.startedAt))}`);
  }
  lines.push(`- **Scope:** ${escapeMd(record.scope.name)} — expires ${record.scope.expiresAt}`);
  lines.push(`- **Authorization reference:** ${escapeMd(record.scope.authorizationRef)}`);
  lines.push("");
  lines.push("## Method and validation state");
  lines.push("");
  lines.push(...renderPipelineMarkdown(buildPipeline(findings)));
  if (record.dependencies) {
    const graph = record.dependencies.summary;
    lines.push("## Supply chain");
    lines.push("");
    lines.push(`- Package manager: ${graph.packageManager}`);
    lines.push(`- Graph: ${graph.nodes} nodes (${graph.direct} direct, ${graph.transitive} transitive), ${graph.edges} edges`);
    lines.push(`- Outdated direct dependencies: ${graph.outdated}`);
    lines.push("");
  }
  lines.push("## Findings");
  lines.push("");
  if (sorted.length === 0) {
    lines.push("No findings were recorded. That is a coverage statement, not proof of safety.");
    lines.push("");
  }
  for (const [index, finding] of sorted.entries()) {
    lines.push(`### ${index + 1}. [${finding.severity.toUpperCase()}] ${escapeMd(finding.title)}`);
    lines.push("");
    const facts = [
      `Category: ${finding.category}`,
      `Confidence: ${finding.confidence}`,
      `Target: ${oneLine(finding.target, 200)}`,
      ...(finding.url ? [`Endpoint: ${oneLine(finding.url, 300)}`] : []),
      ...(finding.cwe ? [`CWE: ${finding.cwe}`] : []),
      ...(finding.owasp ? [`OWASP: ${finding.owasp}`] : []),
      ...(finding.cvss ? [`CVSS: ${finding.cvss.score.toFixed(1)} (${finding.cvss.vector})`] : []),
      `Recorded by: ${finding.tool}`,
    ];
    for (const fact of facts) lines.push(`- ${fact}`);
    lines.push("");
    lines.push("**What was observed**");
    lines.push("");
    lines.push(finding.description || "No description recorded.");
    lines.push("");
    lines.push("**Evidence**");
    lines.push("");
    lines.push("```text");
    lines.push(finding.evidence || "No evidence captured.");
    lines.push("```");
    lines.push("");
    lines.push("**Remediation**");
    lines.push("");
    lines.push(finding.remediation || "No remediation recorded.");
    if (finding.references.length > 0) {
      lines.push("");
      lines.push("**References**");
      lines.push("");
      for (const reference of finding.references.slice(0, 10)) lines.push(`- ${reference}`);
    }
    lines.push("");
  }
  lines.push("## Coverage and next steps");
  lines.push("");
  const unvalidated = findings.length - confirmed;
  lines.push(
    `- Confirmed findings: ${confirmed}. Unconfirmed observations kept as likely/possible: ${unvalidated}.`,
  );
  if (unvalidated > 0) {
    lines.push("- Reproduce the unconfirmed observations before treating them as vulnerabilities.");
  }
  lines.push("- Re-test after remediation with the same requests or source trace that produced each finding.");
  lines.push("- This report contains only tool-observed evidence; absence of a finding is not absence of a vulnerability.");
  lines.push("");
  if (journal?.trim()) {
    lines.push(journal.trim());
    lines.push("");
  }
  lines.push("## Appendix: finding index");
  lines.push("");
  lines.push("| # | Severity | Confidence | CVSS | Title | Target |");
  lines.push("| ---: | --- | --- | ---: | --- | --- |");
  for (const [index, finding] of sorted.entries()) {
    lines.push(
      `| ${index + 1} | ${finding.severity.toUpperCase()} | ${finding.confidence} | ${finding.cvss?.score.toFixed(1) ?? "—"} | ${escapeMd(finding.title)} | ${escapeMd(finding.target)} |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

function renderHtml(run: RunHandle): string {
  const { record, findings } = run;
  const sorted = sortFindings(findings);
  const cards = sorted
    .map(
      (finding, index) => `
      <article class="finding sev-${finding.severity}">
        <header>
          <span class="badge">${escapeHtml(finding.severity.toUpperCase())}</span>
          <h3>${index + 1}. ${escapeHtml(finding.title)}</h3>
        </header>
        <dl>
          <dt>Category</dt><dd>${escapeHtml(finding.category)}</dd>
          <dt>Confidence</dt><dd>${escapeHtml(finding.confidence)}</dd>
          <dt>Tool</dt><dd>${escapeHtml(finding.tool)}</dd>
          <dt>Target</dt><dd>${escapeHtml(finding.target)}</dd>
          ${finding.url ? `<dt>URL</dt><dd>${escapeHtml(finding.url)}</dd>` : ""}
          ${finding.cwe ? `<dt>CWE</dt><dd>${escapeHtml(finding.cwe)}</dd>` : ""}
          ${finding.cvss ? `<dt>CVSS</dt><dd>${escapeHtml(finding.cvss.score.toFixed(1))} (${escapeHtml(finding.cvss.vector)})</dd>` : ""}
        </dl>
        <h4>Description</h4><p>${escapeHtml(finding.description || "No description.")}</p>
        <h4>Evidence</h4><pre>${escapeHtml(finding.evidence || "No evidence captured.")}</pre>
        <h4>Remediation</h4><p>${escapeHtml(finding.remediation || "No remediation guidance.")}</p>
        ${finding.references.length ? `<h4>References</h4><ul>${finding.references.map((ref) => `<li>${escapeHtml(ref)}</li>`).join("")}</ul>` : ""}
      </article>`,
    )
    .join("");
  const rows = (["critical", "high", "medium", "low", "info"] as const)
    .map((severity) => `<tr><td><span class="badge">${severity.toUpperCase()}</span></td><td>${record.counts[severity] ?? 0}</td></tr>`)
    .join("");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARGUS — ${escapeHtml(record.target.display)}</title>
<style>
:root{color-scheme:dark;--bg:#0b0f14;--panel:#121821;--line:#273241;--text:#d9e2ec;--muted:#8b9bb0;--crit:#ff4d6d;--high:#ff7a45;--med:#ffc857;--low:#4dabf7;--info:#8b9bb0}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace}
main{max-width:1120px;margin:0 auto;padding:40px 24px 80px}h1{font-size:26px;margin:0 0 8px}h2{margin-top:40px;border-bottom:1px solid var(--line);padding-bottom:8px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px;margin:24px 0}.meta div{background:var(--panel);border:1px solid var(--line);padding:12px 14px;border-radius:8px}
.meta b{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
table{border-collapse:collapse;width:100%;max-width:420px}td{border-bottom:1px solid var(--line);padding:6px 8px}
table th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em;padding:6px 8px;border-bottom:1px solid var(--line)}
.stage{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 18px;margin:12px 0}.stage h3{margin:0 0 6px;font-size:14px}.stage p{margin:0 0 8px;color:var(--muted)}.stage ul{margin:0;padding-left:18px}
.stage-blocked{border-left:4px solid var(--high)}.stage-partial{border-left:4px solid var(--med)}.stage-done{border-left:4px solid #3fb950}.stage-awaiting{border-left:4px solid var(--low)}
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;padding:18px 20px;margin:16px 0}
.finding.sev-critical{border-left-color:var(--crit)}.finding.sev-high{border-left-color:var(--high)}.finding.sev-medium{border-left-color:var(--med)}.finding.sev-low{border-left-color:var(--low)}
.finding header{display:flex;gap:10px;align-items:flex-start}.finding h3{margin:0 0 12px;font-size:16px}
.badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.08em;border:1px solid var(--line);padding:2px 7px;border-radius:999px;white-space:nowrap}
dl{display:grid;grid-template-columns:120px 1fr;gap:4px 12px;margin:0 0 12px}dt{color:var(--muted)}dd{margin:0;word-break:break-word}
pre{background:#0a0e13;border:1px solid var(--line);padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-word}
h4{margin:14px 0 4px;color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.08em}
footer{margin-top:48px;color:var(--muted);font-size:12px}
</style>
</head>
<body><main>
<h1>ARGUS Security Assessment</h1>
<p>${escapeHtml(record.target.display)}</p>
<section class="meta">
<div><b>Run ID</b>${escapeHtml(record.id)}</div>
<div><b>Profile</b>${escapeHtml(record.profile)}</div>
<div><b>Status</b>${escapeHtml(record.status)}</div>
<div><b>Authorization</b>${escapeHtml(record.scope.authorizedBy)}<br>${escapeHtml(record.scope.authorizationRef)}</div>
<div><b>Scope expires</b>${escapeHtml(record.scope.expiresAt)}</div>
<div><b>Findings</b>${findings.length}</div>
</section>
<h2>Summary</h2><table>${rows}</table>
${renderPipelineHtml(buildPipeline(findings))}
<h2>Findings</h2>${cards || "<p>No findings were recorded.</p>"}
<footer>Generated by ARGUS. Validate findings before remediation or disclosure.</footer>
</main></body></html>
`;
}

function renderCsv(run: RunHandle): string {
  const header = ["id", "severity", "confidence", "category", "title", "target", "url", "tool", "cwe", "owasp", "description", "evidence", "remediation", "references", "fingerprint"];
  const rows = sortFindings(run.findings).map((finding) =>
    [
      finding.id,
      finding.severity,
      finding.confidence,
      finding.category,
      finding.title,
      finding.target,
      finding.url ?? "",
      finding.tool,
      finding.cwe ?? "",
      finding.owasp ?? "",
      finding.description,
      finding.evidence,
      finding.remediation,
      finding.references.join(" "),
      finding.fingerprint,
    ]
      .map(csvCell)
      .join(","),
  );
  return `${header.join(",")}\n${rows.join("\n")}\n`;
}

function renderSarif(run: RunHandle): Record<string, unknown> {
  const { record, findings } = run;
  const rules = new Map<string, Record<string, unknown>>();
  const results = findings.map((finding) => {
    const ruleId = finding.cwe || finding.fingerprint;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: finding.title.slice(0, 120),
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: { text: finding.remediation },
        properties: { category: finding.category, cwe: finding.cwe, tags: [finding.category, finding.cwe].filter(Boolean) },
      });
    }
    return {
      ruleId,
      level: sarifLevel(finding.severity),
      message: { text: finding.title },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.url ?? finding.target },
            region: { startLine: 1 },
          },
        },
      ],
      partialFingerprints: { argusFingerprint: finding.fingerprint },
      properties: {
        severity: finding.severity,
        confidence: finding.confidence,
        category: finding.category,
        tool: finding.tool,
        evidence: finding.evidence,
        remediation: finding.remediation,
      },
    };
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "ARGUS",
            version: "0.1.0",
            informationUri: "https://github.com/anomalyco/opencode",
            rules: [...rules.values()],
          },
        },
        invocations: [
          {
            executionSuccessful: record.status === "completed",
            startTimeUtc: record.startedAt ?? record.createdAt,
            endTimeUtc: record.finishedAt ?? record.createdAt,
            properties: { profile: record.profile, scope: record.scope.name },
          },
        ],
        results,
      },
    ],
  };
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function csvCell(value: string): string {
  const text = oneLine(value);
  return `"${text.replace(/"/g, '""')}"`;
}

function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function escapeMd(value: string): string {
  const text = value.replace(/\r?\n/g, " ");
  const escaped = text.replace(/([\\`*_{}[\]()#+!|>])/g, "\\$1");
  return /^[-+=]/.test(escaped) ? `\\${escaped}` : escaped;
}

export function findingLine(finding: Finding): string {
  return `[${finding.severity.toUpperCase()}] ${finding.title} (${finding.target})`;
}

export async function saveRunArtifact(store: RunStore, runId: string, filename: string, content: string): Promise<string> {
  return store.writeArtifact(runId, filename, content);
}
