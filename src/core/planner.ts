import type { PhaseTask, ProfileId, RunOptions, ScopePolicy, Target, ToolAvailability } from "./types";
import { networkTasks } from "./probes/network";
import { repoTasks } from "./probes/repo";
import { reconTasks, webProbeTasks, webTasks } from "./probes/web";
import { buildToolTasks, discoverTools } from "./tools";

export interface PlanPhase {
  id: string;
  label: string;
  description: string;
  tasks: PhaseTask[];
}

export interface ScanPlan {
  phases: PlanPhase[];
  tools: ToolAvailability[];
  notes: string[];
  taskCount: number;
}

const PHASE_META: Record<string, { label: string; description: string }> = {
  recon: { label: "Reconnaissance", description: "DNS, certificate and target intelligence." },
  surface: { label: "Attack Surface", description: "Ports, services and reachable endpoints." },
  audit: { label: "Audit", description: "Misconfigurations, exposures and vulnerability checks." },
  supply: { label: "Supply Chain", description: "Secrets, dependencies, IaC and source patterns." },
};

const PHASE_ORDER = ["recon", "surface", "audit", "supply"];

export async function createPlan(
  target: Target,
  profile: ProfileId,
  scope: ScopePolicy,
  options: RunOptions,
  tools?: ToolAvailability[],
): Promise<ScanPlan> {
  const notes: string[] = [];
  const detectedTools = tools ?? (await discoverTools());
  const availableTools = detectedTools.filter((tool) => tool.installed);
  if (availableTools.length === 0) {
    notes.push("No external tools detected; ARGUS native probes will be used.");
  } else {
    notes.push(`${availableTools.length}/${detectedTools.length} external tools detected.`);
  }

  const native = selectNativeTasks(target, profile, notes);
  const effectiveProfile = target.kind === "repo" ? (profile === "deep" ? "deep" : "repo") : target.kind === "network" ? (profile === "deep" ? "deep" : "network") : profile;
  const external = buildToolTasks(detectedTools, effectiveProfile, target.kind);
  if (external.length === 0) notes.push("No matching external tool adapters are available for this profile and target.");

  const activeAllowed = Boolean(scope.allowActive) && !options.passiveOnly;
  const intrusiveAllowed = Boolean(scope.allowIntrusive) && Boolean(options.intrusive) && activeAllowed && !options.passiveOnly;
  if (!activeAllowed) notes.push("Active checks are disabled by scope or passive mode.");
  if (!intrusiveAllowed) notes.push("Intrusive checks are locked; deep confirmation adapters will not run.");

  const tasks = [...native, ...external].filter((task) => {
    if (task.requiresActive && !activeAllowed) return false;
    if (task.requiresIntrusive && !intrusiveAllowed) return false;
    return true;
  });

  // Profiles assemble native and probe tasks from overlapping lists; run each
  // probe once so the pass does not spend its request budget twice on them.
  const unique = new Map<string, PhaseTask>();
  for (const task of tasks) if (!unique.has(task.id)) unique.set(task.id, task);

  const grouped = new Map<string, PhaseTask[]>();
  for (const task of unique.values()) {
    const list = grouped.get(task.phase) ?? [];
    list.push(task);
    grouped.set(task.phase, list);
  }

  const phases: PlanPhase[] = [];
  for (const id of PHASE_ORDER) {
    const list = grouped.get(id);
    if (!list?.length) continue;
    const meta = PHASE_META[id] ?? { label: id, description: "" };
    phases.push({ id, label: meta.label, description: meta.description, tasks: list });
  }
  for (const [id, list] of grouped) {
    if (PHASE_ORDER.includes(id)) continue;
    phases.push({ id, label: id, description: "", tasks: list });
  }

  return { phases, tools: detectedTools, notes, taskCount: unique.size };
}

export async function detectTools(): Promise<ToolAvailability[]> {
  return discoverTools();
}

function selectNativeTasks(target: Target, profile: ProfileId, notes: string[]): PhaseTask[] {
  const tasks: PhaseTask[] = [];
  if (target.kind === "repo") {
    tasks.push(...repoTasks);
    if (profile !== "repo" && profile !== "deep") notes.push("Repository target detected; repository probes are enabled.");
    return tasks;
  }
  if (target.kind === "network") {
    tasks.push(...networkTasks);
    if (profile === "quick") notes.push("Network targets always receive a bounded port scan.");
    return tasks;
  }

  if (profile === "quick") {
    const ids = new Set(["web-baseline", "web-headers", "web-cookies"]);
    tasks.push(...webTasks.filter((task) => ids.has(task.id)));
    return tasks;
  }

  if (profile === "recon") {
    const ids = new Set(["dns", "subdomains", "web-baseline", "web-content", "web-tls", "well-known"]);
    tasks.push(...reconTasks, ...webTasks.filter((task) => ids.has(task.id)), ...webProbeTasks().filter((task) => ids.has(task.id)));
    return tasks;
  }

  if (profile === "api") {
    const ids = new Set([
      "dns",
      "web-baseline",
      "web-headers",
      "cors",
      "methods",
      "exposures",
      "graphql",
      "reflection",
      "js-bundles",
      "path-traversal",
      "sqli",
      "command-injection",
      "ssrf",
      "header-injection",
      "auth-form",
      "auth-defaults",
    ]);
    tasks.push(...reconTasks.filter((task) => task.id === "dns"));
    tasks.push(...webTasks.filter((task) => ids.has(task.id)));
    tasks.push(...webProbeTasks().filter((task) => ids.has(task.id)));
    return tasks;
  }

  tasks.push(...reconTasks, ...webTasks, ...webProbeTasks());
  if (profile === "deep") {
    tasks.push(...networkTasks);
    notes.push("Deep mode adds a bounded TCP scan of the web host.");
  }
  return tasks;
}
