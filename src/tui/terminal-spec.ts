/**
 * Command builders for the embedded terminal. Pure so the argv contract is
 * testable without spawning a PTY or loading the renderer.
 */
import { basename, resolve } from "node:path";
import { shellQuote } from "../core/wsl";

export interface TerminalSpec {
  title: string;
  argv: string[];
  cwd: string;
}

/** C:\Users\me\x -> /mnt/c/Users/me/x; already-Linux paths pass through. */
export function toWslPath(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  const drive = /^([A-Za-z]):\/(.*)$/.exec(normalized);
  if (!drive) return normalized;
  return `/mnt/${drive[1]!.toLowerCase()}/${drive[2]}`;
}

export function buildVimSpec(
  input: string | undefined,
  workspace: string,
  options: { distro?: string } = {},
): TerminalSpec {
  const wanted = input?.trim() || ".";
  const abs = resolve(workspace, wanted);
  const title = `vim ${wanted === "." ? basename(abs) || "." : wanted}`;
  if (options.distro) {
    return {
      title,
      cwd: workspace,
      argv: [
        "wsl.exe",
        "-d",
        options.distro,
        "--",
        "bash",
        "-lc",
        `vim ${shellQuote(toWslPath(abs))}`,
      ],
    };
  }
  return {
    title,
    cwd: workspace,
    argv: ["bash", "-lc", `vim ${shellQuote(abs)}`],
  };
}

export function buildTerminalSpec(command: string | undefined, workspace: string): TerminalSpec {
  const wanted = command?.trim();
  return {
    title: wanted ? `sh ${wanted}` : "shell",
    cwd: workspace,
    argv: ["bash", "-lc", wanted || "bash -l"],
  };
}
