import { existsSync } from "node:fs";
import { inferAllowedTargets } from "../core/agent";
import type { ProfileId } from "../core/types";
import { PROVIDERS } from "./providers";

export type LocalIntent =
  | { kind: "command"; line: string }
  | { kind: "scan"; line: string; target: string }
  | { kind: "modal"; modal: "providers" | "models" | "dashboard" }
  | { kind: "connect"; keyFor?: string; startInKey?: boolean };

export interface LocalIntentOptions {
  workspace?: string;
  scopeTargets?: string[];
}

const SCAN_INTENT =
  /\b(scan|audit|pentest|penetration|assess|probe|hack|attack|pwn|compromise|exploit|brute[- ]?force|test|check|review|inspect|examine|analy[sz]e|security|harden|stress[- ]?test|rank|find\s+(?:bugs|issues|vulns|vulnerabilities|problems|flaws|risks)|is\s+.*\s+(?:safe|secure)|look\s+(?:at|into|for))\b/i;

const REPO_INTENT =
  /\b(repo|repository|code\s*base|codebase|source\s+code|source\s+tree|my code|this code|our code|the code\s*base|this project|my project|our project|this workspace|the workspace|local project|local repo|local code|this app|my app|our app|this application|my application|our application|this folder|this directory|current directory|project files|the files here|whole code\s*base|entire code\s*base)\b/i;

function quote(value: string): string {
  return `"${value.replace(/"/g, "'")}"`;
}

function hostKey(value: string): string {
  try {
    if (/^https?:\/\//i.test(value)) return new URL(value).host.toLowerCase();
  } catch {
    // fall through to the literal comparison
  }
  return value.replace(/^\/+|\/+$/g, "").toLowerCase();
}

/** `extractTargets` can return a URL and its host as two entries; collapse that. */
function oneTarget(targets: string[]): string | undefined {
  if (targets.length <= 1) return targets[0];
  if (new Set(targets.map(hostKey)).size !== 1) return undefined;
  return targets.find((target) => /^https?:\/\//i.test(target)) ?? targets[0];
}

function providerFor(text: string): string | undefined {
  const needle = text.toLowerCase();
  const provider = PROVIDERS.find(
    (entry) =>
      needle.includes(entry.id.toLowerCase()) ||
      needle.includes(entry.label.toLowerCase()) ||
      (entry.id === "nvidia" && /\bnvidia\b|\bnim\b/.test(needle)),
  );
  return provider?.id;
}

/**
 * Maps unambiguous natural-language requests to existing deterministic
 * actions. Anything that needs reasoning is left to the model; this only
 * handles the common operator shortcuts so they work without an API key and
 * never trigger a provider round-trip.
 */
export function interpretLocalPrompt(prompt: string, options: LocalIntentOptions = {}): LocalIntent | undefined {
  const text = prompt.trim();
  if (!text || text.startsWith("/")) return undefined;
  const lower = text.toLowerCase();

  // A token comes before the generic "key/token" UI branch.
  const jwt = text.match(/^(?:jwt|decode\s+jwt|analy[sz]e\s+jwt)\s+(.+)$/i);
  if (jwt?.[1] && jwt[1].includes(".")) return { kind: "command", line: `/jwt ${jwt[1]}` };

  const web = text.match(/^(?:web\s+search|search\s+(?:the\s+)?web|look\s+(?:it\s+)?up|google)\s+(.+)$/i);
  if (web?.[1]) return { kind: "command", line: `/web ${web[1].replace(/^for\s+/i, "")}` };

  const http = text.match(/^(?:http|request|send\s+request)\s+(https?:\/\/\S+)(?:\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS))?/i);
  if (http?.[1]) {
    const method = http[2]?.toUpperCase() ?? "GET";
    return { kind: "command", line: `/http ${quote(http[1])} --method ${method}` };
  }

  // A real assessment sentence resolves to a scan before the keyword shortcuts
  // below, so a word like "report" inside the request can never hijack it into a
  // local action that ignores what the operator actually asked for.
  const repoRequest = REPO_INTENT.test(text);
  const assessment = SCAN_INTENT.test(text);
  const target =
    oneTarget(inferAllowedTargets(text, options)) ?? (repoRequest ? options.workspace : undefined);
  if (assessment && target) {
    const profile: ProfileId = existsSync(target) && repoRequest ? "repo" : "deep";
    return { kind: "scan", target, line: `/scan ${quote(target)} --profile ${profile}` };
  }

  // Everything below is a UI convenience, so it only answers short,
  // single-purpose prompts. Longer text belongs to the model.
  if (assessment || text.split(/\s+/).filter(Boolean).length > 6) return undefined;

  if (/\b(dashboard|charts?|graphs?|visuali[sz]e|show\s+me\s+the\s+picture)\b/i.test(text)) {
    return { kind: "modal", modal: "dashboard" };
  }
  if (/^(help|commands?|what\s+can\s+you\s+do|how\s+do\s+i\s+use)\b/i.test(text)) {
    return { kind: "command", line: "/help" };
  }
  if (/\b(doctor|diagnos\w*|setup\s+check|why\s+(?:is|isn'?t|does)\b.*\b(?:not\s+working|broken|fail))\b/i.test(text)) {
    return { kind: "command", line: "/doctor" };
  }
  if (/\b(findings?|what\s+did\s+you\s+find|results?|bugs\s+found|show\s+me\s+the\s+issues)\b/i.test(text)) {
    return { kind: "command", line: "/findings" };
  }
  if (/\b(runs?|history|past\s+(?:scans?|assessments?))\b/i.test(text)) {
    return { kind: "command", line: "/runs" };
  }
  if (/\b(memory|agents\.md|what\s+do\s+you\s+remember)\b/i.test(text)) {
    return { kind: "command", line: "/memory" };
  }
  if (/\b(tools?|adapters?|subfinder|nuclei)\b/i.test(text)) {
    return { kind: "command", line: "/tools" };
  }
  if (/\b(scope|authorization|authorisation|permissions?|am\s+i\s+authorized)\b/i.test(text)) {
    return { kind: "command", line: "/scope" };
  }
  if (/\b(config|configuration|settings)\b/i.test(text)) {
    return { kind: "command", line: "/config" };
  }
  if (/\b(report|export|write\s+up)\b/i.test(text)) {
    return { kind: "command", line: "/report" };
  }
  const preview = text.match(
    /^(?:preview|view|cat|display|show|open)\s+(?:me\s+|us\s+)?(?:the\s+)?(?:this\s+)?(?:file\s+)?(.+)$/i,
  );
  if (preview?.[1] && /[\\/]|\.\w{1,8}$/.test(preview[1].trim())) {
    return { kind: "command", line: `/preview ${quote(preview[1].trim())}` };
  }
  if (/^(clear|reset)(?:\s+(?:the\s+)?transcript)?$/i.test(lower)) {
    return { kind: "command", line: "/clear" };
  }
  if (/^(quit|exit|bye)$/i.test(lower)) return { kind: "command", line: "/quit" };

  if (/\b(providers?|endpoints?|which\s+provider|switch\s+provider)\b/i.test(text)) {
    return { kind: "modal", modal: "providers" };
  }
  if (/\b(models?|which\s+model|switch\s+model)\b/i.test(text)) {
    return { kind: "modal", modal: "models" };
  }
  if (/\b(api\s*key|add\s+key|set\s+key|paste\s+key|credential|connect)\b/i.test(text)) {
    const keyFor = providerFor(text);
    const wantsKeyEntry = /\b(api\s*key|add\s+key|set\s+key|paste\s+key|credential)\b/i.test(text) || Boolean(keyFor);
    return { kind: "connect", keyFor, startInKey: wantsKeyEntry };
  }

  return undefined;
}

/**
 * True when the prompt reads as an assessment request for a resolvable target.
 * Those prompts stay on the model path even when a keyword shortcut matches, so
 * "audit example.com and report here" can never be reduced to a local /report.
 */
export function isAssessmentPrompt(prompt: string, options: LocalIntentOptions = {}): boolean {
  const text = prompt.trim();
  if (!text || text.startsWith("/")) return false;
  if (!SCAN_INTENT.test(text)) return false;
  const target =
    oneTarget(inferAllowedTargets(text, options)) ?? (REPO_INTENT.test(text) ? options.workspace : undefined);
  return Boolean(target);
}
