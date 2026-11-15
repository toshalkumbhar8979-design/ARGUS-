/**
 * A dedicated folder for the agent's own scripts, wordlists and generated
 * artifacts, so an assessment does not leave scratch files at the project root.
 *
 * The folder lives inside the project on purpose: it is already under the
 * authorized workspace root, so reads and writes need no extra permission, and
 * the operator can inspect or delete it like any other project directory.
 */
import { mkdir } from "node:fs/promises";
import { resolve, sep } from "node:path";

export const SCRATCH_DIR_NAME = process.env.ARGUS_SCRATCH_DIR?.trim() || "argus-workspace";

export function scratchPath(workspace: string): string {
  return resolve(workspace, SCRATCH_DIR_NAME);
}

export async function ensureScratch(workspace: string): Promise<string> {
  const dir = scratchPath(workspace);
  await mkdir(dir, { recursive: true });
  return dir;
}

/** True when `target` is the scratch folder or something inside it. */
export function isScratchPath(workspace: string, target: string): boolean {
  const root = scratchPath(workspace);
  const abs = resolve(target);
  return abs === root || abs.startsWith(`${root}${sep}`);
}
