import type { Severity } from "../core/types";

/**
 * Argus console palette.
 *
 * The interface runs on a quiet slate ramp: one cyan accent for the brand,
 * focus and the prompt marker, and colour that only lights up for real state —
 * findings, passes and failures. Nothing else competes for attention.
 */
export const palette = {
  /** headings and emphasised values */
  strong: "#f1f5f9",
  /** body text */
  text: "#dbe3ee",
  /** secondary text and labels */
  muted: "#93a1b5",
  /** hints and inactive chrome */
  faint: "#64748b",
  /** rules and disabled chrome */
  ghost: "#3d4a5c",
  /** the single accent: brand, focus, prompt marker, links */
  accent: "#7dd3fc",
  accentDeep: "#38bdf8",
  ok: "#4ade80",
  warn: "#fbbf24",
  error: "#f87171",
  critical: "#fb7185",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#60a5fa",
  info: "#8b9bb4",
  /** selected list row */
  selection: "#1d2836",
  /** modal fill */
  panel: "#0c131c",
  panelSoft: "#111a25",
  chip: "#17202c",
  /** hairlines inside panels */
  rule: "#26313f",
  border: "#2a3644",
  borderFocus: "#7dd3fc",
  /** readable ink on a coloured chip */
  chipInk: "#0a0f16",
} as const;

export const severityColor: Record<Severity, string> = {
  critical: palette.critical,
  high: palette.high,
  medium: palette.medium,
  low: palette.low,
  info: palette.info,
};

/** Four-character severity chips so columns stay aligned without a Nerd Font. */
export const severityTag: Record<Severity, string> = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED ",
  low: "LOW ",
  info: "INFO",
};

/**
 * Terminal-native markers. These are the glyphs a shell already uses, so the
 * transcript reads like command output: no bracketed tags, no emoji, nothing
 * that needs a Nerd Font.
 */
export const GLYPH = {
  /** brand mark in the masthead */
  brand: "▌",
  /** prompt and operator lines */
  prompt: "❯",
  /** a step or subagent starting */
  run: "›",
  /** a step counter or quiet note */
  step: "·",
  /** a command the operator can paste into a shell */
  shell: "$",
  /** completed */
  done: "+",
  /** failed, denied or refused */
  fail: "!",
  /** neutral note */
  note: "-",
  /** hairline */
  rule: "─",
  /** selected row marker */
  bar: "▌",
} as const;

/** Back-compat aliases used by command and dashboard output. */
export const MARK = {
  run: GLYPH.run,
  step: GLYPH.step,
  shell: GLYPH.shell,
  done: GLYPH.done,
  fail: GLYPH.fail,
  note: GLYPH.note,
} as const;

/** Braille spinner; degrades to a plain dot cycle in terminals without them. */
export const SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"] as const;

export function spinnerFrame(tick: number): string {
  return SPINNER[tick % SPINNER.length] ?? "·";
}

export function ruleLine(width: number): string {
  return GLYPH.rule.repeat(Math.max(0, Math.floor(width)));
}

/**
 * Strips a leading status mark from a message. Commands predate the shared
 * prefix, and a line that reads "+ + scope | ..." is just noise.
 */
export function stripMark(text: string): string {
  const marks = new Set<string>([MARK.run, MARK.done, MARK.fail, MARK.shell, MARK.step]);
  const match = /^(\S{1,2})\s+([\s\S]*)$/.exec(text);
  if (match && marks.has(match[1]!)) return match[2]!;
  return text;
}
