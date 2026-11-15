import { patchFilesFor, type CandidatePatchFile } from "./patches";
import { buildFixPlan } from "./remediation";
import type { Finding, Severity } from "./types";

/**
 * The assessment pipeline Argus reports against:
 *
 *   vulnerability discovery -> candidate findings
 *     -> dynamic validation  -> validated reports
 *       -> exploitability    -> confirmed impact (and LPEs when the surface is local)
 *         -> patch generation -> candidate patches
 *           -> human researchers
 *
 * Probes only produce candidates. A finding becomes a report when triage
 * confirms it is real and triggerable, and only validated reports are allowed
 * to receive an exploitability judgement or a candidate patch. Nothing here
 * applies a patch; the last gate is a human.
 */

export type PipelineStageId = "discovery" | "validation" | "exploitability" | "patch" | "review";

export interface PipelineItem {
  findingId: string;
  title: string;
  severity: Severity;
  detail: string;
  /** Exact unified diff for a candidate patch, when one was drafted. */
  diff?: string;
}

export interface CandidatePatch {
  id: string;
  priority: string;
  severity: Severity;
  remediation: string;
  findingIds: string[];
  targets: string[];
  /** Exact file, line and change for validated repo findings. */
  files: CandidatePatchFile[];
}

export type PipelineStageStatus = "done" | "partial" | "blocked" | "empty" | "awaiting";

export interface PipelineStage {
  id: PipelineStageId;
  label: string;
  description: string;
  /** Items that reached this stage. */
  count: number;
  status: PipelineStageStatus;
  items: PipelineItem[];
  notes: string[];
}

export interface PipelineAssessment {
  stages: PipelineStage[];
  /** Candidate patches that carry an exact unified diff. */
  concretePatches: number;
  review: { label: string; status: PipelineStageStatus; note: string };
}

const MAX_ITEMS = 8;

/** Categories where a confirmed finding is an exploitable primitive, not just noise. */
const EXPLOIT_CATEGORIES = new Set([
  "access-control",
  "authentication",
  "code",
  "cryptography",
  "deserialization",
  "injection",
  "secrets",
  "session",
  "ssrf",
  "takeover",
  "xxe",
]);

const LPE_PATTERN = /\b(lpe|local privilege|privilege[-\s]?escalat\w*|setuid|kernel\s+(?:bug|exploit)|root access)\b/i;

function category(finding: Finding): string {
  return finding.category.trim().toLowerCase();
}

/**
 * A validated (dynamic-validation) report: triage saw evidence and the probe
 * did not leave it at "possible". Info-level inventory rows are discovery
 * output, not reports.
 */
export function isValidated(finding: Finding): boolean {
  return finding.severity !== "info" && finding.confidence !== "possible" && finding.evidence.trim().length > 0;
}

/** A validated finding in an attack category that could be turned into an exploit. */
export function isExploitable(finding: Finding): boolean {
  if (!isValidated(finding)) return false;
  if (finding.confidence !== "confirmed") return false;
  if (finding.severity === "critical" || finding.severity === "high") return true;
  return EXPLOIT_CATEGORIES.has(category(finding));
}

/** A confirmed exploit that reaches local privilege escalation. */
export function isConfirmedLpe(finding: Finding): boolean {
  if (!isExploitable(finding)) return false;
  return LPE_PATTERN.test([finding.category, finding.title, finding.description].join(" "));
}

function item(finding: Finding, detail: string): PipelineItem {
  return { findingId: finding.id, title: finding.title, severity: finding.severity, detail };
}

function stage(
  id: PipelineStageId,
  label: string,
  description: string,
  count: number,
  status: PipelineStageStatus,
  items: PipelineItem[] = [],
  notes: string[] = [],
): PipelineStage {
  return { id, label, description, count, status, items: items.slice(0, MAX_ITEMS), notes };
}

/** Deterministic pipeline state for a set of findings. */
export function buildPipeline(findings: Finding[]): PipelineAssessment {
  const validated = findings.filter(isValidated);
  const exploitable = validated.filter(isExploitable);
  const lpes = exploitable.filter(isConfirmedLpe);
  const plan = buildFixPlan(validated, 20);

  const patches: CandidatePatch[] = plan.map((action, index) => {
    const covered = validated.filter((finding) => finding.remediation.trim() === action.remediation.trim());
    const files = patchFilesFor(covered);
    return {
      id: `patch-${index + 1}`,
      priority: action.priority,
      severity: action.severity,
      remediation: action.remediation,
      findingIds: covered.map((finding) => finding.id),
      targets: [...new Set(covered.map((finding) => finding.url ?? finding.target))].slice(0, 5),
      files,
    };
  });
  const concretePatches = patches.filter((patch) => patch.files.some((file) => file.diff));

  const discoveryStage = stage(
    "discovery",
    "Vulnerability discovery",
    "Identify security-sensitive audit targets and analyse them to find potential vulnerabilities.",
    findings.length,
    findings.length > 0 ? "done" : "empty",
    findings.map((finding) => item(finding, `${category(finding) || "uncategorized"} · ${finding.tool}`)),
    findings.length > 0 ? [`${findings.length} candidate finding(s) collected by probes and tool runs.`] : ["No candidates were produced."],
  );

  const validationStage = stage(
    "validation",
    "Dynamic validation",
    "Triage and validate candidate findings so they are real, triggerable, and impactful.",
    validated.length,
    validated.length === 0 ? (findings.length === 0 ? "empty" : "blocked") : validated.length === findings.length ? "done" : "partial",
    validated.map((finding) => item(finding, finding.evidence.replace(/\s+/g, " ").trim().slice(0, 160))),
    validated.length === 0
      ? ["No candidate reached validation: findings need evidence and confirmed/likely confidence."]
      : [
          `${validated.length}/${findings.length} candidate(s) validated.`,
          `${findings.length - validated.length} candidate(s) remain unvalidated and must not be reported as confirmed.`,
        ],
  );

  const exploitableNotes = exploitable.length > 0
    ? [`${exploitable.length} validated finding(s) reached confirmed exploitation.`]
    : validated.length > 0
      ? ["Validated findings were assessed, but none has a confirmed exploit path; this stage is not done."]
      : ["Nothing is validated, so exploitability cannot be assessed."];
  if (validated.length > 0) {
    exploitableNotes.push(
      lpes.length > 0
        ? `${lpes.length} confirmed local privilege-escalation path(s).`
        : "No local privilege-escalation surface; the LPE gate stays empty rather than simulated.",
    );
  }

  const exploitabilityStage = stage(
    "exploitability",
    "Exploitability assessment",
    "Develop and refine exploits for validated vulnerabilities to achieve LPE.",
    exploitable.length,
    exploitable.length > 0 ? "done" : validated.length > 0 ? "partial" : findings.length === 0 ? "empty" : "blocked",
    exploitable.map((finding) => item(finding, `${finding.severity} · ${category(finding)}`)),
    exploitableNotes,
  );

  const patchStage = stage(
    "patch",
    "Patch generation",
    "Generate candidate patches for validated vulnerabilities. Use prompts to improve patch quality.",
    patches.length,
    patches.length > 0 ? "done" : validated.length > 0 ? "blocked" : "empty",
    patches.flatMap((patch): PipelineItem[] => {
      if (patch.files.length === 0) {
        return [
          {
            findingId: patch.findingIds[0] ?? patch.id,
            title: patch.remediation,
            severity: patch.severity,
            detail: `${patch.priority} · ${patch.findingIds.length} finding(s) · ${patch.targets.join(", ")}`,
          },
        ];
      }
      return patch.files.map((file) => ({
        findingId: patch.findingIds[0] ?? patch.id,
        title: `${file.path}:${file.line}`,
        severity: patch.severity,
        detail: `${patch.priority}${file.diff ? "" : " manual"} · ${file.change}`,
        diff: file.diff,
      }));
    }),
    patches.length > 0
      ? [
          `${patches.length} candidate patch(es) drafted; none applied.`,
          `${concretePatches.length} patch(es) carry an exact diff for a validated repository finding; ${patches.length - concretePatches.length} need a manual change.`,
        ]
      : validated.length > 0
        ? ["Validated findings exist but none carried remediation text to turn into a patch."]
        : ["Patch generation starts after validation."],
  );

  const reviewStage = stage(
    "review",
    "Human researchers",
    "Review root-cause analysis, reproductions, exploits, candidate patches, and severity before reporting to maintainers.",
    validated.length,
    validated.length > 0 ? "awaiting" : "empty",
    validated.map((finding) => item(finding, `${finding.confidence} · ${finding.severity}`)),
    ["Final gate: a human signs off the report, exploits and candidate patches before disclosure."],
  );

  return {
    stages: [discoveryStage, validationStage, exploitabilityStage, patchStage, reviewStage],
    concretePatches: concretePatches.length,
    review: {
      label: "Human researchers",
      status: validated.length > 0 ? "awaiting" : "empty",
      note: validated.length > 0 ? `${validated.length} validated report(s) awaiting human review.` : "Nothing is waiting for review.",
    },
  };
}

/** Compact form for tool payloads and logs. */
export function summarizePipeline(assessment: PipelineAssessment): Record<string, unknown> {
  return {
    stages: assessment.stages.map((stage) => ({
      id: stage.id,
      label: stage.label,
      status: stage.status,
      count: stage.count,
    })),
    concretePatches: assessment.concretePatches,
    review: assessment.review.status,
  };
}

/** Markdown block used by the report and by anything that renders text. */
export function renderPipelineMarkdown(assessment: PipelineAssessment): string[] {
  const lines: string[] = [];
  lines.push("## Assessment pipeline");
  lines.push("");
  lines.push("| Stage | State | Items |");
  lines.push("| --- | --- | ---: |");
  for (const stage of assessment.stages) {
    lines.push(`| ${stage.label} | ${stage.status} | ${stage.count} |`);
  }
  lines.push("");

  for (const stage of assessment.stages) {
    lines.push(`### ${stage.label} — ${stage.status} (${stage.count})`);
    lines.push("");
    lines.push(stage.description);
    for (const note of stage.notes) lines.push(`- ${note}`);
    for (const entry of stage.items.slice(0, 5)) {
      lines.push(`- [${entry.severity.toUpperCase()}] ${entry.title} — ${entry.detail}`);
      if (entry.diff) {
        lines.push("");
        lines.push("```diff");
        lines.push(entry.diff);
        lines.push("```");
      }
    }
    lines.push("");
  }
  return lines;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** HTML fragment with the same content as the markdown section. */
export function renderPipelineHtml(assessment: PipelineAssessment): string {
  const rows = assessment.stages
    .map((stage) => `<tr><td>${stage.label}</td><td>${stage.status}</td><td>${stage.count}</td></tr>`)
    .join("");
  const details = assessment.stages
    .map(
      (stage) => `
    <article class="stage stage-${stage.status}">
      <h3>${stage.label} <span class="badge">${stage.status}</span></h3>
      <p>${stage.description}</p>
      <ul>${stage.notes.map((note) => `<li>${note}</li>`).join("")}</ul>
      <ul>${stage.items
        .map(
          (entry) =>
            `<li>[${entry.severity.toUpperCase()}] ${escapeHtml(entry.title)} — ${escapeHtml(entry.detail)}${entry.diff ? `<pre>${escapeHtml(entry.diff)}</pre>` : ""}</li>`,
        )
        .join("")}</ul>
    </article>`,
    )
    .join("");
  return `<h2>Assessment pipeline</h2>
<table><thead><tr><th>Stage</th><th>State</th><th>Items</th></tr></thead><tbody>${rows}</tbody></table>
${details}`;
}
