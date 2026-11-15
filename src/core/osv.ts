/**
 * Package and toolchain vulnerability research through OSV.dev.
 *
 * OSV aggregates GitHub Security Advisories, PyPA, RustSec, Go, OSS-Fuzz and
 * friends behind one query API, so an agent auditing a lockfile or a vendored
 * dependency gets real advisories and fixed versions instead of guessing from a
 * model's memory. The API is public and needs no key.
 *
 * Nothing here executes or downloads the package; it only asks what is known
 * about a name and version.
 */
export const OSV_ECOSYSTEMS = [
  "npm",
  "PyPI",
  "crates.io",
  "Go",
  "Maven",
  "NuGet",
  "Packagist",
  "RubyGems",
  "Hex",
  "Pub",
  "SwiftURL",
] as const;

export type OsvEcosystem = (typeof OSV_ECOSYSTEMS)[number];

export interface OsvAdvisory {
  id: string;
  aliases: string[];
  summary: string;
  severity?: string;
  cvss?: string;
  published?: string;
  modified?: string;
  fixedVersions: string[];
  references: Array<{ type?: string; url: string }>;
}

export interface OsvQuery {
  package: string;
  version?: string;
  ecosystem?: OsvEcosystem;
}

export interface OsvResult {
  package: string;
  version?: string;
  ecosystem: OsvEcosystem;
  advisories: OsvAdvisory[];
  source: "osv.dev";
  note?: string;
}

interface OsvVulnerability {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  severity?: Array<{ type?: string; score?: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type?: string; events?: Array<{ fixed?: string; introduced?: string }> }>;
  }>;
  references?: Array<{ type?: string; url?: string }>;
}

/** Splits `name@version` and infers the ecosystem from the package shape. */
export function parsePackageSpec(input: string): { package: string; version?: string } {
  const trimmed = input.trim();
  const at = trimmed.lastIndexOf("@");
  if (at > 0) {
    const name = trimmed.slice(0, at);
    const version = trimmed.slice(at + 1).trim();
    if (version && !version.includes("/")) return { package: name, version };
  }
  return { package: trimmed };
}

export function inferEcosystem(packageName: string): OsvEcosystem {
  if (packageName.startsWith("@")) return "npm";
  if (/^[a-z0-9_.-]+$/i.test(packageName) && /[A-Z]/.test(packageName)) return "NuGet";
  return "npm";
}

function collectFixed(vulnerability: OsvVulnerability): string[] {
  const fixed = new Set<string>();
  for (const affected of vulnerability.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixed.add(event.fixed);
      }
    }
  }
  return [...fixed];
}

function toAdvisory(vulnerability: OsvVulnerability): OsvAdvisory | undefined {
  if (!vulnerability.id) return undefined;
  const severity = vulnerability.severity?.find((entry) => entry.score)?.score;
  const isVector = severity?.startsWith("CVSS:");
  return {
    id: vulnerability.id,
    aliases: vulnerability.aliases ?? [],
    summary: (vulnerability.summary ?? vulnerability.details ?? "No summary published.").replace(/\s+/g, " ").slice(0, 600),
    ...(severity ? (isVector ? { cvss: severity } : { severity }) : {}),
    ...(vulnerability.published ? { published: vulnerability.published } : {}),
    ...(vulnerability.modified ? { modified: vulnerability.modified } : {}),
    fixedVersions: collectFixed(vulnerability),
    references: (vulnerability.references ?? [])
      .map((reference) => ({ ...(reference.type ? { type: reference.type } : {}), url: reference.url ?? "" }))
      .filter((reference) => reference.url)
      .slice(0, 8),
  };
}

/**
 * Queries OSV for advisories affecting one package version. `fetchImpl` is
 * injectable so tests never touch the network.
 */
export async function lookupPackageVulns(
  query: OsvQuery,
  options: { fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<OsvResult> {
  const name = query.package.trim();
  if (!name) throw new Error("package name is required");
  const ecosystem = query.ecosystem ?? inferEcosystem(name);
  if (!OSV_ECOSYSTEMS.includes(ecosystem)) {
    throw new Error(`unsupported ecosystem: ${ecosystem}. Use one of ${OSV_ECOSYSTEMS.join(", ")}.`);
  }
  const body: Record<string, unknown> = { package: { name, ecosystem } };
  if (query.version) body.version = query.version;

  const fetchImpl = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 15_000);
  let response: Response;
  try {
    response = await fetchImpl("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (error) {
    throw new Error(`OSV lookup failed: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) {
    throw new Error(`OSV lookup failed: HTTP ${response.status}`);
  }
  const payload = (await response.json()) as { vulns?: OsvVulnerability[] };
  const advisories = (payload.vulns ?? [])
    .map(toAdvisory)
    .filter((advisory): advisory is OsvAdvisory => Boolean(advisory))
    .sort((a, b) => (b.published ?? "").localeCompare(a.published ?? ""));

  return {
    package: name,
    ...(query.version ? { version: query.version } : {}),
    ecosystem,
    advisories,
    source: "osv.dev",
    ...(query.version
      ? {}
      : { note: "No version was given, so OSV returned advisories for every affected version of this package." }),
  };
}

/** Extracts package@version pairs from a lockfile-ish text for batch research. */
export function packagesFromLockfile(text: string, ecosystem: OsvEcosystem = "npm"): Array<{ package: string; version: string }> {
  const found: Array<{ package: string; version: string }> = [];
  const seen = new Set<string>();
  const add = (name: string, version: string) => {
    const key = `${name}@${version}`;
    if (!name || !version || seen.has(key)) return;
    seen.add(key);
    found.push({ package: name, version });
  };
  if (ecosystem === "npm") {
    for (const match of text.matchAll(/"([^"]+)"\s*:\s*\{[^{}]*?"version"\s*:\s*"([^"]+)"/g)) {
      const rawName = match[1]!;
      if (["packages", "dependencies", "devDependencies", "peerDependencies", "optionalDependencies"].includes(rawName)) {
        continue;
      }
      add(rawName.replace(/^.*node_modules\//, ""), match[2]!);
    }
  } else {
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      const npm = trimmed.match(/^([a-z0-9@._/-]+)@(\d+[^\s:]*)$/i);
      if (npm) add(npm[1]!, npm[2]!);
      const requirement = trimmed.match(/^([A-Za-z0-9_.-]+)==([^\s;]+)$/);
      if (requirement) add(requirement[1]!, requirement[2]!);
    }
  }
  return found.slice(0, 200);
}
