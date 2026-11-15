import { existsSync } from "node:fs";
import { resolve } from "node:path";

export const PACKAGE_MANAGERS = [
  "auto",
  "bun",
  "npm",
  "pnpm",
  "yarn",
  "pip",
  "uv",
  "cargo",
  "go",
  "composer",
  "gem",
] as const;

export type PackageManager = (typeof PACKAGE_MANAGERS)[number];
export type ResolvedPackageManager = Exclude<PackageManager, "auto">;

export interface PackageInstallRequest {
  name: string;
  version?: string;
  manager?: PackageManager;
  dev?: boolean;
  cwd: string;
}

export interface PackageInstallPlan {
  manager: ResolvedPackageManager;
  argv: string[];
  display: string;
  packageSpec: string;
}

export interface PackagePlanOptions {
  which?: (binary: string) => string | null;
}

const NAME_PATTERN = /^[A-Za-z0-9@][A-Za-z0-9@._:/+~-]*$/;
const VERSION_PATTERN = /^[A-Za-z0-9^~<>=*._+-]+$/;

export class PackageInputError extends Error {}

export function validatePackageName(name: string): string {
  const value = name.trim();
  if (!value) throw new PackageInputError("package name is empty");
  if (value.length > 214) throw new PackageInputError("package name is too long");
  if (value.startsWith("-") || value.includes("..") || !NAME_PATTERN.test(value)) {
    throw new PackageInputError(`invalid package name: ${name}`);
  }
  return value;
}

export function validatePackageVersion(version: string | undefined): string | undefined {
  if (version === undefined) return undefined;
  const value = version.trim().replace(/^@/, "");
  if (!value) return undefined;
  if (value.length > 64 || !VERSION_PATTERN.test(value)) {
    throw new PackageInputError(`invalid package version: ${version}`);
  }
  return value;
}

function exists(root: string, name: string): boolean {
  return existsSync(resolve(root, name));
}

/** Chooses the package manager the checkout already uses, without guessing wildly. */
export function detectPackageManager(cwd: string, requested: PackageManager = "auto"): ResolvedPackageManager {
  if (requested !== "auto") {
    if (requested === "pip" || requested === "uv" || requested === "bun" || requested === "npm" ||
        requested === "pnpm" || requested === "yarn" || requested === "cargo" || requested === "go" ||
        requested === "composer" || requested === "gem") {
      return requested;
    }
  }
  if (exists(cwd, "bun.lock") || exists(cwd, "bun.lockb")) return "bun";
  if (exists(cwd, "pnpm-lock.yaml")) return "pnpm";
  if (exists(cwd, "yarn.lock")) return "yarn";
  if (exists(cwd, "package-lock.json")) return "npm";
  if (exists(cwd, "package.json")) return "npm";
  if (exists(cwd, "uv.lock")) return "uv";
  if (exists(cwd, "pyproject.toml") || exists(cwd, "requirements.txt")) return "pip";
  if (exists(cwd, "Cargo.toml")) return "cargo";
  if (exists(cwd, "go.mod")) return "go";
  if (exists(cwd, "composer.json")) return "composer";
  if (exists(cwd, "Gemfile")) return "gem";
  throw new PackageInputError("could not detect a package manager in this directory; pass manager explicitly");
}

function pythonBinary(options: PackagePlanOptions): string {
  const which = options.which ?? ((binary) => Bun.which(binary) ?? null);
  if (which("python")) return "python";
  if (which("python3")) return "python3";
  return "python";
}

function npmSpec(name: string, version?: string): string {
  return version ? `${name}@${version}` : name;
}

export function buildPackageInstallPlan(
  request: PackageInstallRequest,
  options: PackagePlanOptions = {},
): PackageInstallPlan {
  const name = validatePackageName(request.name);
  const version = validatePackageVersion(request.version);
  const manager = detectPackageManager(request.cwd, request.manager ?? "auto");
  let argv: string[];
  let packageSpec = name;

  switch (manager) {
    case "bun":
      packageSpec = npmSpec(name, version);
      argv = ["bun", "add", ...(request.dev ? ["-d"] : []), packageSpec];
      break;
    case "npm":
      packageSpec = npmSpec(name, version);
      argv = ["npm", "install", ...(request.dev ? ["--save-dev"] : []), packageSpec];
      break;
    case "pnpm":
      packageSpec = npmSpec(name, version);
      argv = ["pnpm", "add", ...(request.dev ? ["-D"] : []), packageSpec];
      break;
    case "yarn":
      packageSpec = npmSpec(name, version);
      argv = ["yarn", "add", ...(request.dev ? ["--dev"] : []), packageSpec];
      break;
    case "pip": {
      if (request.dev) throw new PackageInputError("pip has no development-dependency flag for project installs");
      packageSpec = version ? `${name}==${version}` : name;
      argv = [pythonBinary(options), "-m", "pip", "install", packageSpec];
      break;
    }
    case "uv":
      packageSpec = version ? `${name}==${version}` : name;
      argv = ["uv", "add", ...(request.dev ? ["--dev"] : []), packageSpec];
      break;
    case "cargo":
      packageSpec = version ? `${name}@${version}` : name;
      argv = ["cargo", "add", ...(request.dev ? ["--dev"] : []), packageSpec];
      break;
    case "go":
      if (request.dev) throw new PackageInputError("go has no development-dependency flag");
      packageSpec = version ? `${name}@${version}` : name;
      argv = ["go", "get", packageSpec];
      break;
    case "composer":
      packageSpec = version ? `${name}:${version}` : name;
      argv = ["composer", "require", ...(request.dev ? ["--dev"] : []), packageSpec];
      break;
    case "gem":
      packageSpec = name;
      argv = exists(request.cwd, "Gemfile")
        ? [
            "bundle",
            "add",
            name,
            ...(version ? ["--version", version] : []),
            ...(request.dev ? ["--group", "development"] : []),
          ]
        : ["gem", "install", name, ...(version ? ["-v", version] : [])];
      break;
  }

  return { manager, argv, display: argv.join(" "), packageSpec };
}
