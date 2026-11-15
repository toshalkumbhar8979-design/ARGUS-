/**
 * Skill packs: short, concrete playbooks the agent loads when it starts working
 * a vulnerability class. The Strix model injects a handful of skills per agent;
 * Argus exposes them as a tool so a text-only model can ask for the same depth
 * without carrying every playbook in the system prompt.
 *
 * These are testing guides, not exploits. They assume the operator's scope and
 * are written for non-destructive proof.
 */
export interface SkillPack {
  id: string;
  title: string;
  aliases: string[];
  when: string;
  steps: string[];
  confirm: string[];
  avoid: string[];
  refs?: string[];
}

export const SKILLS: SkillPack[] = [
  {
    id: "idor",
    title: "IDOR and broken object authorization",
    aliases: ["bola", "object-auth", "authorization", "access-control", "tenant-isolation"],
    when: "The app exposes object identifiers in paths, query strings, JSON bodies, GraphQL node ids or headers.",
    steps: [
      "Map the object model: which endpoints take an id, and what owns that id (user, tenant, org).",
      "Collect two of your own objects of the same type; note sequential vs opaque ids (UUID, hashid, base64).",
      "Replay a request with the other object's id while keeping your own session; compare body, status and length.",
      "Test the sibling surfaces: PUT/PATCH/DELETE on a foreign id, nested ids (/users/<mine>/orders/<theirs>), bulk endpoints and export/download routes.",
      "Try id substitution in headers (X-User-Id, X-Org-Id) and in GraphQL variables; check if the server trusts them.",
    ],
    confirm: [
      "Two-account differential: same request, same object id, different sessions, different data returned.",
      "The response contains another principal's data, or a state change lands in their tenant.",
    ],
    avoid: [
      "Do not enumerate wide id ranges; two or three probes are enough to prove it.",
      "Never modify or delete another principal's data: read-only proof, then stop.",
    ],
    refs: ["OWASP API1:2023", "CWE-639", "CWE-284"],
  },
  {
    id: "sqli",
    title: "SQL injection",
    aliases: ["sql", "sqli", "injection", "blind-sqli"],
    when: "User input reaches a database query: search, filters, sort, login, id parameters, JSON fields.",
    steps: [
      "Send a single quote and a matched pair (' vs '') and compare status, body and error text.",
      "Probe boolean logic: 1 AND 1=1 vs 1 AND 1=2, then ' AND '1'='1 vs ' AND '1'='2.",
      "Test numeric contexts without quotes (1 AND 1=1), and sort/order parameters with (SELECT 1) forms.",
      "If errors are suppressed, use a bounded time probe: sleep(2) vs sleep(0) and measure twice.",
      "Identify the backend from errors or dialect-specific syntax (MySQL, PostgreSQL, MSSQL, SQLite).",
    ],
    confirm: [
      "Repeatable differential: boolean pair changes the response, or a 2s delay reproduces twice.",
      "Captured SQL error naming a query fragment you injected.",
    ],
    avoid: [
      "No UNION dumps of user tables, no stacked destructive statements, no heavy time delays.",
      "Stop at proof of execution; do not exfiltrate real records.",
    ],
    refs: ["OWASP A03:2021", "CWE-89"],
  },
  {
    id: "xss",
    title: "Cross-site scripting (reflected, stored, DOM)",
    aliases: ["xss", "dom-xss", "script-injection"],
    when: "Input is echoed into HTML, attributes, JS strings, URLs or client-rendered templates.",
    steps: [
      "Send a unique marker like argusx123 and find every reflection (body, headers, JSON, script blocks).",
      "Determine the context: HTML text, attribute value, quoted/unquoted JS, URL, or DOM sink.",
      "Use the smallest context-appropriate probe: <b>argusx</b>, \"-alert(1)-, or javascript:alert(1).",
      "For SPAs, trace source to sink: location/hash/search/postMessage/localStorage into innerHTML, eval, document.write.",
      "Check whether a CSP blocks the probe and whether a bypass exists (JSONP, base-uri, unsafe-inline).",
    ],
    confirm: [
      "The unencoded payload appears in a response that a browser would execute.",
      "DOM sink receives your value; show the source line and the sink line.",
    ],
    avoid: ["No cookie theft, no keylogging, no payloads that call out to third-party hosts."],
    refs: ["OWASP A03:2021", "CWE-79"],
  },
  {
    id: "ssrf",
    title: "Server-side request forgery",
    aliases: ["ssrf", "url-fetch", "webhook", "metadata"],
    when: "The server fetches a URL you supply: webhooks, image import, PDF render, URL preview, proxy endpoints.",
    steps: [
      "Point the parameter at a host you control inside the authorized scope and confirm the fetch.",
      "Try alternate encodings: decimal IP, IPv6, userinfo (http://allowed@internal/), redirects and DNS rebinding names.",
      "Test scheme handling: file://, gopher://, dict:// and redirect chains from an allowed host.",
      "Check metadata endpoints only when the scope explicitly authorizes that target; the scope guard hard-blocks cloud metadata hosts.",
    ],
    confirm: [
      "The response body or timing proves the server made the request (banner, error page, callback hit).",
      "A redirect from your host to a blocked host is followed, proving missing re-validation.",
    ],
    avoid: [
      "Do not target internal networks, cloud metadata or third parties: out of scope by default.",
      "No port scanning through the SSRF primitive.",
    ],
    refs: ["OWASP A10:2021", "CWE-918"],
  },
  {
    id: "auth",
    title: "Authentication and session handling",
    aliases: ["authentication", "login", "session", "mfa", "password-reset"],
    when: "There are login, registration, reset, invite, MFA or remember-me flows.",
    steps: [
      "Walk the full lifecycle: login, refresh, logout, password change, reset, MFA enrollment and disable.",
      "Check logout and password change invalidate existing sessions and refresh tokens.",
      "Test reset tokens for predictability, reuse, long lifetime, user binding, and host-header poisoning of the reset link.",
      "Look for user enumeration via distinct error text or timing on login/reset.",
      "Test remember-me and API tokens for scope, expiry and revocation.",
    ],
    confirm: [
      "A token or session that should be dead still works, or a reset flow lets you take over an account you own.",
      "Differences between accounts prove enumeration or bypass.",
    ],
    avoid: ["Never test credentials you were not given.", "No brute force or credential stuffing."],
    refs: ["OWASP A07:2021", "CWE-287", "CWE-384"],
  },
  {
    id: "jwt",
    title: "JWT and token weaknesses",
    aliases: ["jwt", "token", "jku", "kid"],
    when: "The app issues or accepts JWTs in headers, cookies or query parameters.",
    steps: [
      "Decode header and claims; note alg, kid, jku/x5u, iss, aud, exp and role claims.",
      "Test alg confusion: none, HS256 signed with the public key material, and algorithm substitution.",
      "Check signature enforcement by flipping one character in the signature and one claim.",
      "Test claim trust: role/admin/tenant changes, expired token reuse, missing aud/iss validation.",
      "If jku/x5u/kid is present, check whether the server fetches attacker-controlled keys or paths.",
    ],
    confirm: [
      "A modified claim is accepted with the original signature, or an unsigned token is accepted.",
      "The server accepts a token signed with a key you control.",
    ],
    avoid: ["Use tokens for accounts you own; never forge another user's identity against production data."],
    refs: ["OWASP A02:2021", "CWE-347"],
  },
  {
    id: "traversal",
    title: "Path traversal and file read/write",
    aliases: ["path-traversal", "lfi", "directory-traversal", "file-read"],
    when: "A parameter names a file, template, language pack, log, backup or export path.",
    steps: [
      "Probe with ../ and ..\\ sequences, then URL-encoded (%2e%2e%2f) and double-encoded variants.",
      "Try absolute paths, null-byte suffixes and extension appends (../../etc/passwd%00.pdf).",
      "Test both read and write sinks: upload filenames, archive extraction (zip slip), template selection.",
      "Use a canary file you create inside the workspace to prove read/write without touching system paths.",
    ],
    confirm: ["A canary file's contents are returned, or a file you control is written outside the intended directory."],
    avoid: ["Do not read /etc/shadow, cloud credentials or other users' files."],
    refs: ["OWASP A01:2021", "CWE-22"],
  },
  {
    id: "command-injection",
    title: "OS command and argument injection",
    aliases: ["rce", "command", "shell-injection", "argument-injection"],
    when: "Input reaches a shell, subprocess, image/PDF converter, backup job or diagnostic endpoint.",
    steps: [
      "Start with separators that do not change state: ;id, |id, && id, $(id), backticks, newline.",
      "If output is hidden, use a bounded delay (sleep 2) or a DNS/HTTP callback to a host you control.",
      "Test argument injection separately: --output, -o, --config flags appended to a fixed binary.",
      "Check blind sinks: filename fields, headers passed to converters, cron/backup parameters.",
    ],
    confirm: ["Command output appears in the response, or a reproducible timing delta proves execution."],
    avoid: ["No reverse shells to third parties, no destructive commands, no persistence."],
    refs: ["OWASP A03:2021", "CWE-78", "CWE-88"],
  },
  {
    id: "upload",
    title: "File upload and archive handling",
    aliases: ["file-upload", "zip-slip", "multipart"],
    when: "The app accepts documents, images, avatars, imports or archives.",
    steps: [
      "Test content-type and extension handling independently: image/png with .php, .svg, .html, double extensions.",
      "Try polyglots (GIF header + script), SVG with script, and HTML served inline.",
      "Probe filename handling: ../, absolute paths, trailing dots/spaces, case variants.",
      "For archives, test zip slip, symlinks and compression bombs (bounded size only).",
      "Check where files land and whether they are served with a safe content type and disposition.",
    ],
    confirm: ["The uploaded file is stored and served in a way that executes or renders attacker content."],
    avoid: ["No web shells, no oversized archives, no writing outside the upload directory."],
    refs: ["OWASP A04:2021", "CWE-434"],
  },
  {
    id: "secrets",
    title: "Secrets and data exposure",
    aliases: ["secret", "credentials", "leak", "env", "source-maps"],
    when: "Reviewing a repo, bundle, container image or public bucket.",
    steps: [
      "Search tracked files for key prefixes (AKIA, sk-, ghp_, xoxb-, AIza), private key blocks and connection strings.",
      "Check .env, config, CI files, docker-compose, test fixtures and git history (.git present?).",
      "Inspect front-end bundles and source maps for embedded tokens and internal endpoints.",
      "Check public storage: buckets, backups, logs, .DS_Store, swagger, adminer, phpinfo.",
      "For every hit, determine whether the credential is live and what it can reach; never use it beyond its documented purpose.",
    ],
    confirm: ["A real credential format plus a live, scoped check that does not modify data."],
    avoid: ["Never print the full secret; redact to the first and last four characters.", "Never reuse a found credential against third-party services."],
    refs: ["OWASP A02:2021", "CWE-798"],
  },
];

function normalize(query: string): string {
  return query.trim().toLowerCase().replace(/[\s_]+/g, "-");
}

export function skillNames(): string[] {
  return SKILLS.map((skill) => skill.id);
}

export function findSkill(query: string): SkillPack | undefined {
  const key = normalize(query);
  if (!key) return undefined;
  const exact = SKILLS.find((skill) => skill.id === key || skill.aliases.includes(key));
  if (exact) return exact;
  const loose = SKILLS.find(
    (skill) =>
      skill.id.includes(key) ||
      skill.title.toLowerCase().includes(key) ||
      skill.aliases.some((alias) => alias.includes(key) || key.includes(alias)),
  );
  return loose;
}

export function formatSkill(skill: SkillPack): string {
  return [
    `SKILL ${skill.id} — ${skill.title}`,
    `Use when: ${skill.when}`,
    "Steps:",
    ...skill.steps.map((step, index) => `${index + 1}. ${step}`),
    "Confirm with:",
    ...skill.confirm.map((item) => `- ${item}`),
    "Do not:",
    ...skill.avoid.map((item) => `- ${item}`),
    ...(skill.refs?.length ? [`Refs: ${skill.refs.join(", ")}`] : []),
    "Record the verified result with report_finding and cite the finding id. A skill is a plan, not evidence.",
  ].join("\n");
}
