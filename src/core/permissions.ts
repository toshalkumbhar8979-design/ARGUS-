export const PERMISSION_ACTIONS = ["write", "shell", "install", "network", "memory", "subagents"] as const;

export type PermissionAction = (typeof PERMISSION_ACTIONS)[number];
export type PermissionMode = "allow" | "ask" | "deny";
/** How the current turn's policy was chosen. */
export type PermissionSource = "default" | "read-only" | "auto";

export interface PermissionPolicy {
  source: PermissionSource;
  reason: string;
  write: PermissionMode;
  shell: PermissionMode;
  install: PermissionMode;
  network: PermissionMode;
  memory: PermissionMode;
  subagents: PermissionMode;
}

export interface PermissionContext {
  /** Retained for callers; scope, not prompt keywords, decides network access. */
  hasTarget?: boolean;
  /** True once the operator has accepted the authorized-use agreement. */
  authorizedOperator?: boolean;
}

const READ_ONLY =
  /\b(?:read[- ]only|don'?t\s+(?:change|modify|edit|write|touch)\s+(?:anything|the\s+\w+|files?)?|do\s+not\s+(?:change|modify|edit|write|touch)\s+(?:anything|the\s+\w+|files?)?|no\s+changes?|without\s+changing|explain\s+only|answer\s+only)\b/i;

const NO_CONFIRMATIONS =
  /\b(?:just\s+do\s+it|do\s+it\s+without\s+asking|without\s+asking(?:\s+me)?|don'?t\s+ask(?:\s+me)?|do\s+not\s+ask(?:\s+me)?|no\s+questions|no\s+confirmations?|no\s+need\s+to\s+ask|full\s+auto|yolo|you\s+have\s+(?:my\s+)?(?:permission|authorization)|i\s+(?:authorize|approve|pre-?approve)|pre-?approved|(?:full|free)\s+hands|give\s+(?:it|them|the\s+agent)\s+(?:full\s+)?hands|ruthless(?:ly)?|unrestricted|no\s+limits?|do\s+anything|anything\s+you\s+need|whatever\s+it\s+takes|use\s+(?:any|all)\s+tools?|take\s+the\s+wheel)\b/i;

function policy(
  source: PermissionSource,
  reason: string,
  modes: Omit<PermissionPolicy, "source" | "reason">,
): PermissionPolicy {
  return { source, reason, ...modes };
}

/**
 * The default posture does not depend on the wording of the prompt. Network
 * work is already bounded by the scope derived from the named target, so scans
 * and manual requests can proceed. Anything that changes the local machine
 * asks once and the operator can grant it for the rest of the run.
 */
export function defaultPermissionPolicy(): PermissionPolicy {
  return policy("default", "local changes need approval; scoped network work follows the authorization", {
    write: "ask",
    shell: "ask",
    install: "ask",
    network: "allow",
    memory: "allow",
    subagents: "allow",
  });
}

/**
 * Only two explicit operator directives alter the default: read-only and
 * no-confirmations. "Fix", "scan", "review" and similar words are deliberately
 * not classified here; the agent decides what to do and the approval layer
 * decides whether it may.
 */
export function inferPermissionPolicy(prompt: string, context: PermissionContext = {}): PermissionPolicy {
  const text = prompt.replace(/\s+/g, " ").trim();

  if (READ_ONLY.test(text)) {
    return policy("read-only", "the operator explicitly asked for no changes", {
      write: "deny",
      shell: "deny",
      install: "deny",
      network: "allow",
      memory: "allow",
      subagents: "allow",
    });
  }

  // The operator has signed the authorized-use agreement once; a later "attack
  // this" should execute, not re-negotiate. Scope still bounds every target.
  if (context.authorizedOperator) {
    return policy("auto", "the operator accepted the authorized-use agreement; scope still bounds every action", {
      write: "allow",
      shell: "allow",
      install: "allow",
      network: "allow",
      memory: "allow",
      subagents: "allow",
    });
  }

  if (NO_CONFIRMATIONS.test(text)) {
    return policy("auto", "the operator explicitly removed confirmation prompts", {
      write: "allow",
      shell: "allow",
      install: "allow",
      network: "allow",
      memory: "allow",
      subagents: "allow",
    });
  }

  return defaultPermissionPolicy();
}

function modeLabel(mode: PermissionMode): string {
  if (mode === "allow") return "auto";
  if (mode === "deny") return "off";
  return "ask";
}

/** Compact one-line policy shown in the terminal and fed back to the model. */
export function permissionSummary(policy: PermissionPolicy): string {
  return [
    policy.source,
    `write=${modeLabel(policy.write)}`,
    `shell=${modeLabel(policy.shell)}`,
    `install=${modeLabel(policy.install)}`,
    `network=${modeLabel(policy.network)}`,
    `agents=${modeLabel(policy.subagents)}`,
  ].join(" | ");
}

/** Human-readable explanation used when a tool is refused. */
export function permissionDenial(action: PermissionAction, policy: PermissionPolicy): string {
  return `${action} is "${policy[action]}" under the ${policy.source} permission policy (${policy.reason}). Ask the operator to request that action explicitly instead of trying another route.`;
}

/** Detects package-manager invocations that should use the install permission. */
export function isPackageInstallCommand(command: string): boolean {
  return /\b(?:(?:npm|pnpm|yarn|bun)\s+(?:install|i|add)|pip3?\s+install|python3?\s+-m\s+pip\s+install|pipx\s+install|uv\s+(?:add|pip\s+install)|cargo\s+add|go\s+(?:get|install)|composer\s+require|bundle\s+add|gem\s+install|winget\s+install|brew\s+install|choco\s+install|apt(?:-get)?\s+install|dnf\s+install|pacman\s+-S)\b/i.test(
    command,
  );
}
