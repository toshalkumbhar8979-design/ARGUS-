import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, extname, basename } from "node:path";
import type { FindingDraft, PhaseTask, ProbeContext, Severity } from "../types";
import { buildDependencyGraph, checkLatestVersions } from "../dependencies";
import { queryOsv, scanTextForSecrets, type OsvVulnerability } from "../recon-utils";
import { truncate } from "../util";

interface ScannedFile {
  path: string;
  relative: string;
  content: string;
  bytes: number;
}

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".svn", ".hg", "dist", "build", "out", "coverage", ".next", ".nuxt", ".svelte-kit",
  "target", "vendor", "bin", "obj", ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache",
  ".idea", ".vscode", ".turbo", ".cache", "tmp", "temp", "logs",
]);
const TEXT_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".php", ".java", ".go", ".cs", ".rs", ".kt", ".scala",
  ".sh", ".bash", ".ps1", ".bat", ".sql", ".html", ".htm", ".css", ".scss", ".vue", ".svelte", ".astro", ".json",
  ".yml", ".yaml", ".toml", ".ini", ".conf", ".cfg", ".xml", ".gradle", ".tf", ".tfvars", ".properties", ".env",
  ".md", ".txt", ".lock", ".mod", ".sum", ".dockerfile", ".gitignore", ".npmrc", ".pypirc", ".netrc", ".gemrc",
]);
const RAISED_ENV = /(^|[\\/])\.env(\.|$)|(^|[\\/])(credentials|secrets?|id_rsa|id_ed25519|id_dsa|\.netrc|\.npmrc|\.pypirc|kubeconfig)$/i;

export const repoTasks: PhaseTask[] = [
  {
    id: "repo-secrets",
    label: "Repository secret scan",
    phase: "supply",
    run: async (ctx) => {
      const files = await scanWorkspace(ctx);
      const findings: FindingDraft[] = [];
      const seen = new Set<string>();
      let envReported = 0;
      for (const file of files) {
        if (ctx.signal.aborted) break;
        if (RAISED_ENV.test(file.relative) && envReported < 10) {
          envReported += 1;
          findings.push({
            title: `Secret-bearing file in repository: ${file.relative}`,
            severity: "high",
            category: "secrets",
            confidence: "likely",
            tool: "argus-repo",
            target: file.relative,
            evidence: `${file.relative} is present in the working tree and may contain credentials.`,
            description: "Environment or credential files should not be committed to source control.",
            remediation: "Remove the file from the repository, rotate any exposed credentials, and add it to .gitignore.",
            references: ["https://cwe.mitre.org/data/definitions/798.html"],
            cwe: "CWE-798",
            dedupeKey: `repo-env-${file.relative}`,
          });
        }
        const hits = scanTextForSecrets(file.content, { limit: 20, source: file.relative });
        for (const hit of hits) {
          const key = `${hit.id}:${hit.match}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            title: `${hit.name} in ${file.relative}`,
            severity: hit.severity,
            category: "secrets",
            confidence: hit.confidence,
            tool: "argus-repo",
            target: file.relative,
            evidence: `${file.relative}:${hit.line}\n${hit.context}\nmatch: ${hit.masked}`,
            description: hit.description,
            remediation: "Move the secret to a secure secret manager, rotate it, and purge it from history.",
            metadata: { path: file.relative, line: hit.line, rule: hit.id },
            references: ["https://cwe.mitre.org/data/definitions/798.html"],
            cwe: "CWE-798",
            dedupeKey: `repo-secret-${hit.id}-${hit.masked}`,
          });
          if (findings.length >= 120) break;
        }
        if (findings.length >= 120) break;
      }
      ctx.log("info", `Scanned ${files.length} files; ${findings.length} secret findings`, "repo");
      return findings;
    },
  },
  {
    id: "repo-dependencies",
    label: "Dependency graph, outdated packages & OSV lookup",
    phase: "supply",
    requiresActive: false,
    run: async (ctx) => {
      const files = await scanWorkspace(ctx);
      const external = Boolean(ctx.options.allowExternal && ctx.scope.allowExternal);
      const graph = await checkLatestVersions(buildDependencyGraph(files), {
        allowExternal: external,
        signal: ctx.signal,
      });
      ctx.state.set("repo:dependencies", graph);
      const packages = [...new Map(
        graph.nodes.map((node) => [
          `${node.ecosystem}:${node.name}@${node.version}`,
          { name: node.name, version: node.version, ecosystem: node.ecosystem },
        ]),
      ).values()].slice(0, 300);
      ctx.log(
        "info",
        `Dependency graph: ${graph.summary.nodes} nodes | ${graph.summary.direct} direct | ${graph.summary.edges} edges | ${graph.summary.outdated} outdated | latest=${graph.summary.latestCheck}`,
        "supply",
      );
      const findings: FindingDraft[] = [];
      const direct = graph.nodes.filter((node) => node.direct).slice(0, 60);
      for (const node of direct) {
        if (!node.outdated || !node.latest) continue;
        const [currentMajor = 0, currentMinor = 0] = node.version.split(".").map((part) => Number.parseInt(part, 10) || 0);
        const [latestMajor = 0, latestMinor = 0] = node.latest.split(".").map((part) => Number.parseInt(part, 10) || 0);
        const major = latestMajor > currentMajor || (currentMajor === 0 && latestMinor > currentMinor);
        findings.push({
          title: `Outdated dependency: ${node.name} ${node.version} -> ${node.latest}`,
          severity: major ? "low" : "info",
          category: "supply-chain",
          confidence: "confirmed",
          tool: "argus-deps",
          target: ctx.target.path ?? node.name,
          evidence: `${node.name} resolves to ${node.version}${node.range ? ` (declared ${node.range})` : ""}; the npm registry reports ${node.latest} as latest.`,
          description: "A direct dependency is behind its published release. Old releases miss security patches, compatibility fixes and support.",
          remediation: `Upgrade ${node.name} from ${node.version} to ${node.latest}, then run the project test suite${major ? ". This is a major-version jump: read the migration notes first" : ""}.`,
          references: [`https://www.npmjs.com/package/${node.name}/v/${node.latest}`],
          cwe: "CWE-1104",
          metadata: { package: node.name, version: node.version, latest: node.latest, range: node.range, major },
          dedupeKey: `outdated-${node.name}-${node.latest}`,
        });
        if (findings.length >= 40) break;
      }
      if (packages.length === 0) {
        if (graph.summary.nodes === 0) {
          findings.push({
            title: "No dependency manifests found",
            severity: "info",
            category: "supply-chain",
            confidence: "confirmed",
            tool: "argus-deps",
            target: ctx.target.path,
            evidence: "No supported manifest or lockfile was indexed in this workspace.",
            description: "Dependency risk could not be assessed because no manifest was found.",
            remediation: "Add a package manifest or point the scan at the repository root that contains it.",
            references: [],
            dedupeKey: "deps-no-manifest",
          });
        }
        return findings;
      }
      if (!external) {
        findings.push({
          title: "Dependency inventory collected (external lookup skipped)",
          severity: "info",
          category: "supply-chain",
          confidence: "confirmed",
          tool: "argus-deps",
          target: ctx.target.path,
          evidence: `${graph.summary.nodes} packages | ${graph.summary.direct} direct | ${graph.summary.transitive} transitive | ${graph.summary.edges} graph edges. External OSV and latest-version lookup requires scope.allowExternal=true.`,
          description: "Dependency versions and the dependency graph were inventoried locally, but latest releases and advisories were not queried.",
          remediation: "Enable external intelligence for this authorized scope or run osv-scanner/trivy and your package manager's outdated command locally.",
          references: ["https://osv.dev/"],
          metadata: { packages: packages.slice(0, 100), graph: graph.summary },
          dedupeKey: "deps-inventory-only",
        });
        return findings;
      }
      try {
        const results = await queryOsv(packages.slice(0, 250));
        let count = 0;
        for (const result of results) {
          for (const vuln of result.vulns) {
            const severity = mapOsvSeverity(vuln);
            count += 1;
            findings.push({
              title: `Vulnerable dependency: ${result.name} (${vuln.id})`,
              severity,
              category: "supply-chain",
              confidence: "likely",
              tool: "argus-osv",
              target: ctx.target.path,
              evidence: `${result.name} ${result.version ?? ""} (${result.ecosystem ?? "unknown"})\n${vuln.id}${vuln.aliases?.length ? ` / ${vuln.aliases.join(", ")}` : ""}\n${vuln.summary ?? "No summary provided."}`,
              description: "A known vulnerability affects this pinned dependency version according to OSV.",
              remediation: "Upgrade to a patched version, remove the dependency, or apply mitigations from the advisory.",
              references: [`https://osv.dev/vulnerability/${vuln.id}`],
              cwe: "CWE-1104",
              metadata: { package: result.name, version: result.version, ecosystem: result.ecosystem, advisory: vuln.id, aliases: vuln.aliases, details: truncate(vuln.details ?? "", 2000) },
              dedupeKey: `osv-${result.name}-${vuln.id}`,
            });
            if (count >= 100) break;
          }
          if (count >= 100) break;
        }
        if (count === 0) {
          findings.push({
            title: "No known dependency vulnerabilities in OSV",
            severity: "info",
            category: "supply-chain",
            confidence: "possible",
            tool: "argus-osv",
            target: ctx.target.path,
            evidence: `${packages.length} packages checked against OSV. ${graph.summary.nodes} graph nodes | ${graph.summary.direct} direct | ${graph.summary.transitive} transitive | ${graph.summary.outdated} outdated.`,
            description: "No matching advisories were returned for the resolved dependency versions.",
            remediation: "Keep dependencies patched and monitor advisories continuously.",
            references: ["https://osv.dev/"],
            metadata: { graph: graph.summary },
            dedupeKey: "deps-clean",
          });
        }
      } catch (error) {
        findings.push({
          title: "OSV dependency lookup failed",
          severity: "info",
          category: "supply-chain",
          confidence: "possible",
          tool: "argus-osv",
          target: ctx.target.path,
          evidence: error instanceof Error ? error.message : String(error),
          description: "The external vulnerability lookup did not complete.",
          remediation: "Retry with network access or run osv-scanner locally.",
          references: [],
          dedupeKey: "deps-osv-error",
        });
      }
      return findings;
    },
  },
  {
    id: "repo-iac",
    label: "Infrastructure-as-code audit",
    phase: "supply",
    requiresActive: false,
    run: async (ctx) => {
      const files = await scanWorkspace(ctx);
      const findings: FindingDraft[] = [];
      for (const file of files) {
        if (ctx.signal.aborted) break;
        const name = basename(file.relative).toLowerCase();
        const ext = extname(name);
        if (/^dockerfile|\.dockerfile$/i.test(name)) findings.push(...checkDockerfile(file));
        if (/^(docker-)?compose.*\.ya?ml$/i.test(name)) findings.push(...checkCompose(file));
        if (file.relative.includes(".github/workflows/") && (ext === ".yml" || ext === ".yaml")) findings.push(...checkWorkflow(file));
        if (ext === ".tf") findings.push(...checkTerraform(file));
        if ((ext === ".yml" || ext === ".yaml") && /^\s*apiVersion\s*:/m.test(file.content) && /^\s*kind\s*:/m.test(file.content)) {
          findings.push(...checkKubernetes(file));
        }
      }
      ctx.log("info", `IaC audit produced ${findings.length} findings`, "supply");
      return findings;
    },
  },
  {
    id: "repo-code",
    label: "Source code risk patterns",
    phase: "supply",
    requiresActive: false,
    run: async (ctx) => {
      const files = await scanWorkspace(ctx);
      const patterns: Array<{ id: string; title: string; severity: Severity; pattern: RegExp; description: string; remediation: string; extensions: RegExp }> = [
        { id: "tls-verify-off", title: "TLS certificate verification disabled", severity: "medium", pattern: /(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*false)/, description: "Certificate verification is disabled, enabling man-in-the-middle attacks.", remediation: "Enable certificate verification and trust a managed CA bundle.", extensions: /\.(js|ts|py|php|rb|go|cs|java)$/ },
        { id: "eval-input", title: "Dynamic code evaluation", severity: "medium", pattern: /\beval\s*\(|\bnew Function\s*\(/, description: "Dynamic evaluation can become code injection if input is untrusted.", remediation: "Remove eval and use a safe parser or allowlist.", extensions: /\.(js|jsx|ts|tsx|mjs|cjs)$/ },
        { id: "shell-exec", title: "Shell execution with interpolation", severity: "medium", pattern: /(execSync|exec|spawnSync|system)\s*\(\s*[`"'][^`"']*\$\{|(subprocess\.(call|run|Popen)|os\.system)\([^)]*(shell\s*=\s*True|f["'])/, description: "Shell commands built from dynamic values can enable command injection.", remediation: "Use argument arrays, avoid shell=True, and validate allowlisted inputs.", extensions: /\.(js|ts|py|rb|php|go)$/ },
        { id: "sql-concat", title: "SQL query assembled by concatenation", severity: "medium", pattern: /(?:SELECT|INSERT|UPDATE|DELETE)[^;\n]{0,120}(?:\+\s*[A-Za-z_$]|`\$\{)/i, description: "String-built queries can enable SQL injection.", remediation: "Use parameterized queries or an ORM.", extensions: /\.(js|ts|py|rb|php|java|go|cs)$/ },
        { id: "django-debug", title: "Framework debug mode enabled", severity: "medium", pattern: /(^\s*DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)/m, description: "Debug mode can expose stack traces, settings and interactive consoles.", remediation: "Disable debug mode in production configuration.", extensions: /\.(py|js|ts)$/ },
        { id: "cors-open", title: "Permissive CORS configuration", severity: "medium", pattern: /(origin\s*:\s*true|origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"])/, description: "Wildcard CORS may allow arbitrary sites to read responses.", remediation: "Use an explicit origin allowlist.", extensions: /\.(js|ts|py|rb|php|java|go|cs)$/ },
        { id: "yaml-load", title: "Unsafe YAML deserialization", severity: "medium", pattern: /yaml\.load\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)/, description: "Unsafe YAML loading can instantiate arbitrary Python objects.", remediation: "Use yaml.safe_load or SafeLoader.", extensions: /\.py$/ },
        { id: "pickle-loads", title: "Unsafe pickle deserialization", severity: "medium", pattern: /pickle\.loads?\s*\(/, description: "Pickle can execute arbitrary code when loading untrusted data.", remediation: "Use JSON or another safe serialization format.", extensions: /\.py$/ },
        { id: "weak-hash", title: "Weak hash algorithm", severity: "low", pattern: /\b(md5|sha1)\s*\(/i, description: "MD5 and SHA-1 are not collision-resistant and should not protect passwords or integrity.", remediation: "Use SHA-256 or stronger; use a password KDF for credentials.", extensions: /\.(js|ts|py|rb|php|java|go|cs)$/ },
        { id: "innerhtml", title: "Raw HTML sink", severity: "low", pattern: /(innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\()/, description: "Raw HTML sinks can lead to DOM XSS if fed untrusted data.", remediation: "Sanitize with a vetted library and prefer textContent.", extensions: /\.(js|jsx|ts|tsx|vue|svelte)$/ },
      ];
      const findings: FindingDraft[] = [];
      const seen = new Set<string>();
      for (const file of files) {
        if (ctx.signal.aborted) break;
        const ext = extname(file.relative);
        if (!TEXT_EXTENSIONS.has(ext) && !file.relative.endsWith(".env")) continue;
        for (const rule of patterns) {
          if (!rule.extensions.test(ext)) continue;
          const regex = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`);
          let match: RegExpExecArray | null;
          let guard = 0;
          while ((match = regex.exec(file.content)) !== null && guard < 5) {
            guard += 1;
            const key = `${rule.id}:${file.relative}:${match.index}`;
            if (seen.has(key)) continue;
            seen.add(key);
            const line = file.content.slice(0, match.index).split(/\r?\n/).length;
            const lineStart = file.content.lastIndexOf("\n", match.index) + 1;
            const lineEnd = file.content.indexOf("\n", match.index);
            const sourceLine = file.content.slice(lineStart, lineEnd === -1 ? file.content.length : lineEnd).replace(/\r$/, "");
            const snippet = sourceLine.trim();
            findings.push({
              title: `${rule.title} in ${file.relative}`,
              severity: rule.severity,
              category: "code",
              confidence: "possible",
              tool: "argus-code",
              target: file.relative,
              evidence: `${file.relative}:${line}\n${truncate(snippet, 500)}`,
              description: rule.description,
              remediation: rule.remediation,
              references: ["https://owasp.org/www-project-top-ten/"],
              // Concrete patch drafting needs the exact line, not a summary.
              metadata: { path: file.relative, line, rule: rule.id, source: sourceLine },
              dedupeKey: `code-${rule.id}-${file.relative}-${line}`,
            });
            if (findings.length >= 100) return findings;
          }
        }
      }
      return findings;
    },
  },
];

async function scanWorkspace(ctx: ProbeContext): Promise<ScannedFile[]> {
  const cached = ctx.state.get("repo:files") as ScannedFile[] | undefined;
  if (cached) return cached;
  const root = ctx.target.path!;
  const files: ScannedFile[] = [];
  let totalBytes = 0;
  const maxFiles = 5000;
  const maxBytes = 150_000_000;
  const maxFileBytes = 2_000_000;
  const queue = [root];
  while (queue.length > 0 && files.length < maxFiles && totalBytes < maxBytes) {
    const current = queue.shift()!;
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (ctx.signal.aborted) break;
      if (entry.isSymbolicLink()) continue;
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name.toLowerCase())) continue;
        queue.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = extname(entry.name).toLowerCase();
      const name = entry.name.toLowerCase();
      if (!TEXT_EXTENSIONS.has(ext) && !name.startsWith(".env") && !RAISED_ENV.test(entry.name) && !/^(dockerfile|makefile|procfile|gemfile|podfile)$/i.test(name)) continue;
      let info;
      try {
        info = await stat(full);
      } catch {
        continue;
      }
      if (info.size > maxFileBytes) continue;
      let buffer;
      try {
        buffer = await readFile(full);
      } catch {
        continue;
      }
      if (buffer.subarray(0, 8192).includes(0)) continue;
      const content = buffer.toString("utf8");
      files.push({ path: full, relative: relative(root, full) || entry.name, content, bytes: buffer.length });
      totalBytes += buffer.length;
    }
  }
  files.sort((a, b) => a.relative.localeCompare(b.relative));
  ctx.state.set("repo:files", files);
  ctx.log("info", `Repository scan indexed ${files.length} text files (${(totalBytes / 1024 / 1024).toFixed(1)} MB)`, "repo");
  return files;
}

function checkDockerfile(file: ScannedFile): FindingDraft[] {
  const findings: FindingDraft[] = [];
  const lines = file.content.split(/\r?\n/);
  const userLines = lines.filter((line) => /^\s*USER\s+/i.test(line));
  const lastUser = userLines.at(-1)?.replace(/^\s*USER\s+/i, "").trim();
  if (!lastUser || /^root$/i.test(lastUser) || /^0$/.test(lastUser)) {
    findings.push(iacFinding(file, "container-root", undefined, "Container runs as root", "medium", lastUser ? `Final USER is ${lastUser}.` : "No USER instruction; the container defaults to root.", "Set a dedicated non-root USER in the final build stage.", "CWE-250"));
  }
  for (const [index, line] of lines.entries()) {
    if (/^\s*FROM\s+[^\s:]+:latest\b/i.test(line)) {
      findings.push(iacFinding(file, "latest", index + 1, "Mutable :latest base image", "low", line.trim(), "Pin base images by digest or immutable version.", "CWE-1104"));
    }
    if (/^\s*(ENV|ARG)\s+.*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=/i.test(line)) {
      findings.push(iacFinding(file, "docker-secret", index + 1, "Secret embedded in Dockerfile", "high", line.trim(), "Use BuildKit secrets or runtime secret injection.", "CWE-798"));
    }
    if (/^\s*ADD\s+https?:\/\//i.test(line)) {
      findings.push(iacFinding(file, "add-url", index + 1, "ADD fetches remote content", "low", line.trim(), "Use COPY with verified artifacts and checksums.", "CWE-494"));
    }
    if (/RUN[\s\S]*curl[^|]*\|\s*(ba)?sh/i.test(line)) {
      findings.push(iacFinding(file, "curl-pipe", index + 1, "Remote script piped to shell in build", "medium", line.trim(), "Download, verify checksums and execute a pinned artifact.", "CWE-494"));
    }
  }
  return findings;
}

function checkCompose(file: ScannedFile): FindingDraft[] {
  const findings: FindingDraft[] = [];
  const lines = file.content.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    if (/privileged\s*:\s*true/i.test(line)) findings.push(iacFinding(file, "privileged", index + 1, "Privileged container", "high", line.trim(), "Remove privileged mode and grant only the required capabilities.", "CWE-250"));
    if (/\/var\/run\/docker\.sock/.test(line)) findings.push(iacFinding(file, "docker-sock", index + 1, "Docker socket mounted into container", "critical", line.trim(), "Do not mount the Docker socket; use a restricted API proxy.", "CWE-269"));
    if (/network_mode\s*:\s*["']?host/i.test(line)) findings.push(iacFinding(file, "host-network", index + 1, "Host network mode", "medium", line.trim(), "Use a dedicated bridge network and explicit port mappings.", "CWE-284"));
    if (/^\s*-\s*["']?(?:0\.0\.0\.0:)?(?:3306|5432|6379|27017|9200|2375|2379|10250|15672):\d+/i.test(line)) {
      findings.push(iacFinding(file, "port", index + 1, "Sensitive service port published", "medium", line.trim(), "Bind sensitive services to 127.0.0.1 or an internal network.", "CWE-284"));
    }
  }
  return findings;
}

function checkWorkflow(file: ScannedFile): FindingDraft[] {
  const findings: FindingDraft[] = [];
  const lines = file.content.split(/\r?\n/);
  if (/pull_request_target\s*:/i.test(file.content)) {
    for (const [index, line] of lines.entries()) {
      if (/actions\/checkout/.test(line) && /(pull_request\.head|github\.event\.pull_request)/i.test(file.content)) {
        findings.push(iacFinding(file, "prt", index + 1, "pull_request_target checkout of untrusted code", "critical", `${line.trim()}\nWorkflow uses pull_request_target and checks out PR-controlled refs.`, "Use pull_request, or never execute untrusted code with elevated secrets.", "CWE-94"));
        break;
      }
    }
  }
  for (const [index, line] of lines.entries()) {
    if (/^\s*run\s*:.*\$\{\{\s*github\.event\./i.test(line) || /\$\{\{\s*github\.event\.(issue|comment|pull_request|head_commit)\./.test(line) && /run\s*:/i.test(line)) {
      findings.push(iacFinding(file, "expr", index + 1, "GitHub expression interpolated into shell", "high", line.trim(), "Pass untrusted values through env and quote them, or use actions/github-script with safe APIs.", "CWE-78"));
    }
    const uses = /uses\s*:\s*([^\s#]+)@([^\s#]+)/.exec(line);
    if (uses && (uses[2] === "main" || uses[2] === "master")) {
      findings.push(iacFinding(file, "uses-branch", index + 1, "Action pinned to a mutable branch", "medium", line.trim(), "Pin third-party actions to a full commit SHA.", "CWE-494"));
    } else if (uses && /^v\d+$/.test(uses[2]!) && !uses[1]!.startsWith("actions/")) {
      findings.push(iacFinding(file, "uses-tag", index + 1, "Third-party action pinned to a tag", "low", line.trim(), "Pin third-party actions to a full commit SHA.", "CWE-494"));
    }
    if (/permissions\s*:\s*write-all/i.test(line)) {
      findings.push(iacFinding(file, "permissions", index + 1, "Workflow has write-all permissions", "medium", line.trim(), "Declare least-privilege permissions per job.", "CWE-269"));
    }
  }
  return findings;
}

function checkTerraform(file: ScannedFile): FindingDraft[] {
  const findings: FindingDraft[] = [];
  const lines = file.content.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    if (/(acl|access)\s*=\s*["']public-read(-write)?["']/i.test(line) || /publicly_accessible\s*=\s*true/i.test(line)) {
      findings.push(iacFinding(file, "public", index + 1, "Public cloud storage or database exposure", "high", line.trim(), "Make the resource private and use signed URLs or controlled access.", "CWE-284"));
    }
    if (/cidr_blocks\s*=\s*\[[^\]]*0\.0\.0\.0\/0[^\]]*\]/i.test(line) && /(22|3389|3306|5432|6379|9200|27017)/.test(file.content)) {
      findings.push(iacFinding(file, "ingress", index + 1, "Security group open to 0.0.0.0/0", "high", line.trim(), "Restrict ingress CIDRs to trusted networks.", "CWE-284"));
    }
    if (/encrypted\s*=\s*false/i.test(line)) {
      findings.push(iacFinding(file, "encryption", index + 1, "Encryption disabled in IaC", "medium", line.trim(), "Enable encryption at rest with a managed key.", "CWE-311"));
    }
    if (/(skip_final_snapshot|deletion_protection|backup_retention_period)\s*=\s*(true|false|0)\b/i.test(line) && /(skip_final_snapshot\s*=\s*true|deletion_protection\s*=\s*false|backup_retention_period\s*=\s*0)/i.test(line)) {
      findings.push(iacFinding(file, "recovery", index + 1, "Recovery controls disabled", "low", line.trim(), "Enable deletion protection, final snapshots and backups.", "CWE-693"));
    }
  }
  return findings;
}

function checkKubernetes(file: ScannedFile): FindingDraft[] {
  const findings: FindingDraft[] = [];
  const lines = file.content.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    if (/privileged\s*:\s*true/i.test(line)) findings.push(iacFinding(file, "k8s-priv", index + 1, "Privileged Kubernetes container", "high", line.trim(), "Remove privileged mode; use granular capabilities.", "CWE-250"));
    if (/hostNetwork\s*:\s*true/i.test(line)) findings.push(iacFinding(file, "k8s-net", index + 1, "hostNetwork enabled", "medium", line.trim(), "Disable hostNetwork unless strictly required.", "CWE-284"));
    if (/hostPath\s*:/i.test(line)) findings.push(iacFinding(file, "k8s-path", index + 1, "hostPath volume mounted", "high", line.trim(), "Avoid hostPath or restrict to read-only, validated paths.", "CWE-269"));
    if (/allowPrivilegeEscalation\s*:\s*true/i.test(line)) findings.push(iacFinding(file, "k8s-esc", index + 1, "Privilege escalation allowed", "medium", line.trim(), "Set allowPrivilegeEscalation: false.", "CWE-250"));
    if (/runAsUser\s*:\s*0\b/i.test(line)) findings.push(iacFinding(file, "k8s-root", index + 1, "Container runs as UID 0", "medium", line.trim(), "Run as a non-root UID and set runAsNonRoot: true.", "CWE-250"));
    if (/image\s*:\s*[^\s:]+:latest\b/i.test(line)) findings.push(iacFinding(file, "k8s-latest", index + 1, "Mutable :latest image tag", "low", line.trim(), "Pin images by digest.", "CWE-1104"));
  }
  return findings;
}

function iacFinding(
  file: ScannedFile,
  rule: string,
  line: number | undefined,
  title: string,
  severity: Severity,
  evidence: string,
  remediation: string,
  cwe: string,
): FindingDraft {
  return {
    title: `${title} - ${file.relative}`,
    severity,
    category: "iac",
    confidence: "likely",
    tool: "argus-iac",
    target: file.relative,
    evidence: `${file.relative}${line ? `:${line}` : ""}\n${truncate(evidence, 500)}`,
    metadata: { path: file.relative, line, rule, source: line ? file.content.split(/\r?\n/)[line - 1] : undefined },
    description: "Infrastructure or CI configuration weakens the security posture.",
    remediation,
    references: ["https://owasp.org/www-project-top-ten/"],
    cwe,
    dedupeKey: `iac-${rule}-${file.relative}-${line ?? 0}`,
  };
}

function mapOsvSeverity(vuln: OsvVulnerability): Severity {
  const dbSeverity = vuln.database_specific?.severity?.toUpperCase();
  if (dbSeverity === "CRITICAL") return "critical";
  if (dbSeverity === "HIGH") return "high";
  if (dbSeverity === "MODERATE" || dbSeverity === "MEDIUM") return "medium";
  if (dbSeverity === "LOW") return "low";
  const severityArray = Array.isArray(vuln.severity) ? vuln.severity : [];
  for (const entry of severityArray) {
    const scoreText = entry.score ?? "";
    const impactCount = scoreText.match(/\/[CIA]:H/gi)?.length ?? 0;
    if (impactCount >= 2) return "high";
    if (impactCount === 1) return "medium";
    if (/^CVSS:4/i.test(scoreText)) return "high";
  }
  if (typeof vuln.severity === "string") {
    const normalized = vuln.severity.toUpperCase();
    if (normalized.includes("CRITICAL")) return "critical";
    if (normalized.includes("HIGH")) return "high";
    if (normalized.includes("MEDIUM") || normalized.includes("MODERATE")) return "medium";
    if (normalized.includes("LOW")) return "low";
  }
  return "medium";
}