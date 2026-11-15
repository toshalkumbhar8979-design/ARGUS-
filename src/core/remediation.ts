import type { Finding, Severity } from "./types";

export type FixPriority = "P1" | "P2" | "P3";

export interface FixAction {
  priority: FixPriority;
  severity: Severity;
  remediation: string;
  count: number;
  examples: string[];
}

const PRIORITY: Record<Severity, FixPriority> = {
  critical: "P1",
  high: "P1",
  medium: "P2",
  low: "P3",
  info: "P3",
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function actionable(finding: Finding): boolean {
  if (!finding.remediation.trim()) return false;
  return !(
    finding.severity === "info" &&
    /inventory collected|no known dependency|no dependency manifests|lookup failed|no matching advisories/i.test(finding.title)
  );
}

/**
 * Collapse findings that share remediation into a short, ordered plan.
 * This is what the agent and dashboard show after a pass, so a user sees what
 * to change rather than a wall of individual findings.
 */
export function buildFixPlan(findings: Finding[], limit = 6): FixAction[] {
  const grouped = new Map<string, FixAction>();
  for (const finding of findings) {
    if (!actionable(finding)) continue;
    const key = finding.remediation.trim().toLowerCase();
    const current = grouped.get(key);
    if (current) {
      current.count += 1;
      if (current.examples.length < 3 && !current.examples.includes(finding.title)) current.examples.push(finding.title);
      if (SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[current.severity]) current.severity = finding.severity;
      continue;
    }
    grouped.set(key, {
      priority: PRIORITY[finding.severity],
      severity: finding.severity,
      remediation: finding.remediation.trim(),
      count: 1,
      examples: [finding.title],
    });
  }
  return [...grouped.values()]
    .sort(
      (a, b) =>
        a.priority.localeCompare(b.priority) ||
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        b.count - a.count ||
        a.remediation.localeCompare(b.remediation),
    )
    .slice(0, Math.max(1, limit));
}
