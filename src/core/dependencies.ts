import type {
  DependencyEdge,
  DependencyGraphSnapshot,
  DependencyNode,
  DependencySummary,
} from "./types";

export interface DependencySource {
  relative: string;
  content: string;
}

interface Builder {
  nodes: Map<string, DependencyNode>;
  edges: Map<string, DependencyEdge>;
  directRanges: Map<string, string>;
  manifests: Set<string>;
  lockfiles: Set<string>;
  ecosystems: Set<string>;
  notes: Set<string>;
}

function parseJsonc(content: string): unknown {
  try {
    return JSON.parse(content);
  } catch {
    const stripped = content
      .replace(/^\s*\/\/.*$/gm, "")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/,\s*([}\]])/g, "$1");
    return JSON.parse(stripped);
  }
}

function builder(): Builder {
  return {
    nodes: new Map(),
    edges: new Map(),
    directRanges: new Map(),
    manifests: new Set(),
    lockfiles: new Set(),
    ecosystems: new Set(),
    notes: new Set(),
  };
}

function keyOf(ecosystem: string, name: string, version: string): string {
  return `${ecosystem}:${name}@${version}`;
}

function addNode(
  state: Builder,
  input: { name: string; version: string; ecosystem: string; direct?: boolean; range?: string },
): DependencyNode {
  const version = input.version.trim() || "unknown";
  const key = keyOf(input.ecosystem, input.name, version);
  const existing = state.nodes.get(key);
  if (existing) {
    existing.direct = existing.direct || Boolean(input.direct);
    existing.range = existing.range ?? input.range;
    return existing;
  }
  const node: DependencyNode = {
    key,
    name: input.name,
    version,
    ecosystem: input.ecosystem,
    direct: Boolean(input.direct),
    range: input.range,
  };
  state.nodes.set(key, node);
  state.ecosystems.add(input.ecosystem);
  return node;
}

function addEdge(state: Builder, from: string, to: string): void {
  if (!from || !to || from === to) return;
  state.edges.set(`${from}->${to}`, { from, to });
}

function directLookup(state: Builder): Map<string, DependencyNode[]> {
  const lookup = new Map<string, DependencyNode[]>();
  for (const node of state.nodes.values()) {
    const list = lookup.get(node.name) ?? [];
    list.push(node);
    lookup.set(node.name, list);
  }
  return lookup;
}

function resolveNode(lookup: Map<string, DependencyNode[]>, name: string, preferred?: string): DependencyNode | undefined {
  const candidates = lookup.get(name);
  if (!candidates || candidates.length === 0) return undefined;
  return candidates.find((node) => node.version === preferred) ?? candidates.find((node) => node.direct) ?? candidates[0];
}

function markDirect(state: Builder, name: string, range: string, lookup: Map<string, DependencyNode[]>): DependencyNode | undefined {
  const pinned = pinVersion(range);
  const candidate =
    resolveNode(lookup, name, pinned) ??
    (pinned ? addNode(state, { name, version: pinned, ecosystem: "npm", direct: true, range }) : undefined);
  if (!candidate) return undefined;
  candidate.direct = true;
  candidate.range = range;
  addEdge(state, "root", candidate.key);
  return candidate;
}

function packageJson(state: Builder, file: DependencySource): void {
  const pkg = parseJsonc(file.content) as {
    name?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
  };
  state.manifests.add(file.relative);
  const groups = [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies, pkg.peerDependencies];
  for (const group of groups) {
    for (const [name, range] of Object.entries(group ?? {})) {
      state.directRanges.set(name, range);
    }
  }
}

function packageLock(state: Builder, file: DependencySource): void {
  const lock = parseJsonc(file.content) as {
    lockfileVersion?: number;
    packages?: Record<string, {
      version?: string;
      dependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      dev?: boolean;
    }>;
  };
  state.lockfiles.add(file.relative);
  const root = lock.packages?.[""];
  for (const [name, range] of Object.entries(root?.dependencies ?? {})) state.directRanges.set(name, range);
  const pathToKey = new Map<string, string>();
  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    if (!path || !meta.version) continue;
    const name = path.split("node_modules/").pop();
    if (!name) continue;
    const resolved = addNode(state, {
      name,
      version: meta.version,
      ecosystem: "npm",
      direct: path === `node_modules/${name}`,
    });
    pathToKey.set(path, resolved.key);
    if (path === `node_modules/${name}`) {
      resolved.direct = true;
      addEdge(state, "root", resolved.key);
    }
  }
  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    const parentKey = pathToKey.get(path);
    if (!parentKey) continue;
    for (const name of Object.keys({ ...(meta.dependencies ?? {}), ...(meta.optionalDependencies ?? {}) })) {
      const childPath = path ? `${path}/node_modules/${name}` : `node_modules/${name}`;
      const childKey = pathToKey.get(childPath) ?? pathToKey.get(`node_modules/${name}`);
      if (childKey) addEdge(state, parentKey, childKey);
    }
  }
}

function bunLock(state: Builder, file: DependencySource): void {
  const lock = parseJsonc(file.content) as {
    workspaces?: Record<string, {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    }>;
    packages?: Record<string, [string, string, Record<string, unknown>?]>;
  };
  state.lockfiles.add(file.relative);
  const root = lock.workspaces?.[""];
  for (const group of [root?.dependencies, root?.devDependencies, root?.optionalDependencies, root?.peerDependencies]) {
    for (const [name, range] of Object.entries(group ?? {})) state.directRanges.set(name, range);
  }
  for (const [name, entry] of Object.entries(lock.packages ?? {})) {
    const id = entry?.[0];
    if (!id) continue;
    const at = id.lastIndexOf("@");
    if (at <= 0) continue;
    const version = id.slice(at + 1);
    const meta = entry[2] ?? {};
    addNode(state, {
      name: entry[0].slice(0, at) || name,
      version,
      ecosystem: "npm",
      direct: false,
    });
  }
  const lookup = directLookup(state);
  for (const [name, range] of state.directRanges) markDirect(state, name, range, lookup);
  for (const [name, entry] of Object.entries(lock.packages ?? {})) {
    const meta = entry?.[2] ?? {};
    const own = resolveNode(lookup, name);
    if (!own) continue;
    for (const group of [meta.dependencies, meta.optionalDependencies, meta.peerDependencies]) {
      for (const dep of Object.keys((group as Record<string, string> | undefined) ?? {})) {
        const child = resolveNode(lookup, dep);
        if (child) addEdge(state, own.key, child.key);
      }
    }
  }
}

function requirements(state: Builder, file: DependencySource): void {
  state.manifests.add(file.relative);
  for (const line of file.content.split(/\r?\n/)) {
    const match = /^\s*([A-Za-z0-9_.-]+)\s*==\s*([0-9][^\s;#]*)/.exec(line);
    if (!match) continue;
    addNode(state, { name: match[1]!, version: match[2]!, ecosystem: "PyPI", direct: true });
  }
}

function goMod(state: Builder, file: DependencySource): void {
  state.manifests.add(file.relative);
  for (const match of file.content.matchAll(/^\s*(?:require\s+)?([a-zA-Z0-9._/-]+\.[a-zA-Z]{2,}\/[a-zA-Z0-9._/-]+)\s+(v[0-9][^\s]+)(\s+\/\/\s*indirect)?/gm)) {
    addNode(state, {
      name: match[1]!,
      version: match[2]!,
      ecosystem: "Go",
      direct: !match[3],
    });
  }
}

function cargoToml(state: Builder, file: DependencySource): void {
  state.manifests.add(file.relative);
  let inDependencies = false;
  for (const line of file.content.split(/\r?\n/)) {
    if (/^\s*\[.*dependencies.*\]/.test(line)) {
      inDependencies = true;
      continue;
    }
    if (/^\s*\[/.test(line)) inDependencies = false;
    if (!inDependencies) continue;
    const match = /^\s*([A-Za-z0-9_-]+)\s*=\s*["']([0-9][^"']*)["']/.exec(line);
    if (match) addNode(state, { name: match[1]!, version: pinVersion(match[2]!) ?? match[2]!, ecosystem: "crates.io", direct: true });
  }
}

function maven(state: Builder, file: DependencySource): void {
  state.manifests.add(file.relative);
  for (const match of file.content.matchAll(/<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>[\s\S]*?<\/dependency>/g)) {
    const version = match[3]!.replace(/^\$\{[^}]+\}$/, "");
    if (/^[0-9]/.test(version)) addNode(state, { name: `${match[1]}:${match[2]}`, version, ecosystem: "Maven", direct: true });
  }
}

function gradle(state: Builder, file: DependencySource): void {
  state.manifests.add(file.relative);
  for (const match of file.content.matchAll(/(?:implementation|api|compile|runtimeOnly)\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]/g)) {
    addNode(state, { name: `${match[1]}:${match[2]}`, version: match[3]!, ecosystem: "Maven", direct: true });
  }
}

/** Parse the manifests and lockfiles Argus indexed, without touching node_modules. */
export function buildDependencyGraph(files: DependencySource[]): DependencyGraphSnapshot {
  const state = builder();
  for (const file of files) {
    const name = file.relative.split(/[\\/]/).pop()?.toLowerCase() ?? "";
    try {
      if (name === "package.json") packageJson(state, file);
      else if (name === "package-lock.json" || name === "npm-shrinkwrap.json") packageLock(state, file);
      else if (name === "bun.lock") bunLock(state, file);
      else if (name === "requirements.txt" || name === "requirements-dev.txt") requirements(state, file);
      else if (name === "go.mod") goMod(state, file);
      else if (name === "cargo.toml") cargoToml(state, file);
      else if (name === "pom.xml") maven(state, file);
      else if (name === "build.gradle" || name === "build.gradle.kts") gradle(state, file);
      else if (name === "pnpm-lock.yaml" || name === "yarn.lock") {
        state.lockfiles.add(file.relative);
        state.notes.add(`${name} is present; edges are inferred from package.json only.`);
      }
    } catch {
      state.notes.add(`Could not parse ${file.relative}.`);
    }
  }
  const lookup = directLookup(state);
  for (const [name, range] of state.directRanges) markDirect(state, name, range, lookup);
  const lockNames = [...state.lockfiles].map((file) => file.split(/[\\/]/).pop() ?? file);
  const packageManager = lockNames.some((file) => file === "bun.lock")
    ? "bun"
    : lockNames.some((file) => file === "package-lock.json" || file === "npm-shrinkwrap.json")
      ? "npm"
      : lockNames.some((file) => file === "pnpm-lock.yaml")
        ? "pnpm"
        : lockNames.some((file) => file === "yarn.lock")
          ? "yarn"
          : "unknown";
  return snapshot(state, packageManager);
}

function snapshot(state: Builder, packageManager: string): DependencyGraphSnapshot {
  const nodes = [...state.nodes.values()].sort((a, b) => {
    if (a.direct !== b.direct) return a.direct ? -1 : 1;
    return a.name.localeCompare(b.name) || a.version.localeCompare(b.version);
  });
  const edges = [...state.edges.values()];
  const summary: DependencySummary = {
    nodes: nodes.length,
    direct: nodes.filter((node) => node.direct).length,
    transitive: nodes.filter((node) => !node.direct).length,
    edges: edges.length,
    outdated: nodes.filter((node) => node.outdated).length,
    ecosystems: [...state.ecosystems].sort(),
    packageManager,
    latestCheck: "skipped",
  };
  return {
    manifests: [...state.manifests].sort(),
    lockfiles: [...state.lockfiles].sort(),
    nodes,
    edges,
    summary,
    notes: [...state.notes].sort(),
  };
}

function refreshSummary(snapshotValue: DependencyGraphSnapshot): void {
  snapshotValue.summary.outdated = snapshotValue.nodes.filter((node) => node.outdated).length;
  snapshotValue.summary.direct = snapshotValue.nodes.filter((node) => node.direct).length;
  snapshotValue.summary.transitive = snapshotValue.nodes.filter((node) => !node.direct).length;
  snapshotValue.summary.nodes = snapshotValue.nodes.length;
  snapshotValue.summary.edges = snapshotValue.edges.length;
}

export function compareVersions(left: string, right: string): number {
  const normalize = (value: string) => {
    const clean = value.trim().replace(/^[=v]+/, "");
    const [core = "", pre] = clean.split("-", 2);
    return { core: core.split(".").map((part) => Number.parseInt(part, 10) || 0), pre };
  };
  const a = normalize(left);
  const b = normalize(right);
  for (let index = 0; index < Math.max(a.core.length, b.core.length); index += 1) {
    const delta = (a.core[index] ?? 0) - (b.core[index] ?? 0);
    if (delta !== 0) return delta < 0 ? -1 : 1;
  }
  if (a.pre && !b.pre) return -1;
  if (!a.pre && b.pre) return 1;
  if (a.pre && b.pre && a.pre !== b.pre) return a.pre.localeCompare(b.pre) < 0 ? -1 : 1;
  return 0;
}

/** Apply registry results without making the parser itself do any network I/O. */
export function applyLatestVersions(snapshotValue: DependencyGraphSnapshot, latest: Map<string, string>): void {
  for (const node of snapshotValue.nodes) {
    if (node.ecosystem !== "npm" || !node.direct) continue;
    const next = latest.get(node.name);
    if (!next) continue;
    node.latest = next;
    node.outdated = compareVersions(next, node.version) > 0;
  }
  refreshSummary(snapshotValue);
}

export async function checkLatestVersions(
  snapshotValue: DependencyGraphSnapshot,
  options: { allowExternal: boolean; signal?: AbortSignal; timeoutMs?: number } = { allowExternal: false },
): Promise<DependencyGraphSnapshot> {
  const direct = snapshotValue.nodes.filter((node) => node.direct && node.ecosystem === "npm").slice(0, 30);
  if (direct.length === 0) {
    snapshotValue.summary.latestCheck = "skipped";
    return snapshotValue;
  }
  if (!options.allowExternal) {
    snapshotValue.summary.latestCheck = "skipped";
    snapshotValue.notes = [...new Set([...snapshotValue.notes, "Latest versions were not queried because scope.allowExternal is false."])];
    return snapshotValue;
  }
  const latest = new Map<string, string>();
  let failures = 0;
  let cursor = 0;
  const workers = Array.from({ length: Math.min(6, direct.length) }, async () => {
    for (;;) {
      if (options.signal?.aborted) return;
      const node = direct[cursor];
      cursor += 1;
      if (!node) return;
      try {
        const response = await fetch(`https://registry.npmjs.org/${node.name.replace(/^@/, "%40").replace("/", "%2F")}`, {
          headers: { accept: "application/json", "user-agent": "Argus/0.1 (authorized dependency review)" },
          signal: AbortSignal.timeout(options.timeoutMs ?? 6_000),
        });
        if (!response.ok) {
          failures += 1;
          continue;
        }
        const data = (await response.json()) as { "dist-tags"?: { latest?: string } };
        const version = data["dist-tags"]?.latest;
        if (version) latest.set(node.name, version);
      } catch {
        failures += 1;
      }
    }
  });
  await Promise.all(workers);
  applyLatestVersions(snapshotValue, latest);
  snapshotValue.summary.latestCheck = latest.size > 0 ? "registry" : "failed";
  if (failures > 0) {
    snapshotValue.notes = [...new Set([...snapshotValue.notes, `${failures} npm registry lookup(s) failed.`])];
  }
  return snapshotValue;
}

function pinVersion(range: string): string | undefined {
  const direct = /^[=v]?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.-]+)?)$/.exec(range.trim());
  if (direct) return direct[1];
  const operator = /^[~^>=<]+\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/.exec(range.trim());
  return operator?.[1];
}
