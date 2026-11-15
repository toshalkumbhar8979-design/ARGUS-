import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

export interface WebSearchResult {
  title: string;
  url: string;
  snippet: string;
}

export interface WebPage {
  url: string;
  title: string;
  text: string;
  truncated: boolean;
}

export interface WebOptions {
  fetchImpl?: typeof fetch;
  /** Injectable DNS resolver, mainly for tests. */
  resolveHost?: (host: string) => Promise<string[]>;
  signal?: AbortSignal;
  timeoutMs?: number;
}

const USER_AGENT = "Argus/0.1 (authorized security assessment research)";
const SEARCH_CACHE_MS = 10 * 60_000;
const searchCache = new Map<string, { at: number; results: WebSearchResult[] }>();
const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  ndash: "–",
  mdash: "—",
  hellip: "…",
  copy: "©",
  reg: "®",
  trade: "™",
};

function safeCodePoint(value: number): string {
  if (!Number.isInteger(value) || value <= 0 || value > 0x10ffff) return "";
  if (value >= 0xd800 && value <= 0xdfff) return "";
  return String.fromCodePoint(value);
}

export function decodeEntities(value: string): string {
  return value.replace(/&(#x?[0-9a-f]+|[a-z][a-z0-9]+);/gi, (whole, entity: string) => {
    if (entity.startsWith("#")) {
      const hex = entity[1]?.toLowerCase() === "x";
      const code = Number.parseInt(entity.slice(hex ? 2 : 1), hex ? 16 : 10);
      return safeCodePoint(code) || whole;
    }
    return NAMED_ENTITIES[entity.toLowerCase()] ?? whole;
  });
}

function stripTags(html: string): string {
  return decodeEntities(html.replace(/<[^>]*>/g, " "))
    .replace(/\s+/g, " ")
    .trim();
}

export function extractTitle(html: string): string {
  const match = /<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  return match ? stripTags(match[1] ?? "") : "";
}

/** Converts a page to plain text while keeping rough paragraph boundaries. */
export function htmlToText(html: string): string {
  const text = html
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<head\b[\s\S]*?<\/head>/gi, " ")
    .replace(/<title\b[\s\S]*?<\/title>/gi, " ")
    .replace(/<(script|style|noscript|svg|template|iframe|object)\b[\s\S]*?<\/\1>/gi, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(?:p|div|section|article|main|header|footer|li|tr|h[1-6]|blockquote|pre|table|ul|ol)\s*>/gi, "\n")
    .replace(/<[^>]+>/g, " ");
  return decodeEntities(text)
    .replace(/[ \t\f\v]+/g, " ")
    .replace(/ *\n */g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function unwrapDuckDuckGoUrl(href: string): string | undefined {
  const decoded = decodeEntities(href.trim());
  let candidate = decoded;
  if (candidate.startsWith("//")) candidate = `https:${candidate}`;
  try {
    const url = new URL(candidate, "https://duckduckgo.com");
    const wrapped = url.searchParams.get("uddg");
    if (wrapped) candidate = wrapped;
    const final = new URL(candidate, "https://duckduckgo.com");
    return /^https?:$/.test(final.protocol) ? final.toString() : undefined;
  } catch {
    return undefined;
  }
}

/** Parses the public DuckDuckGo HTML result page. */
export function parseDuckDuckGo(html: string, limit = 5): WebSearchResult[] {
  const results: WebSearchResult[] = [];
  const seen = new Set<string>();
  const anchor =
    /<a\b[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
  for (const match of html.matchAll(anchor)) {
    const url = unwrapDuckDuckGoUrl(match[1] ?? "");
    if (!url || seen.has(url)) continue;
    const title = stripTags(match[2] ?? "");
    if (!title) continue;
    const rest = html.slice(match.index + match[0].length, match.index + match[0].length + 5_000);
    const snippetMatch =
      /<a\b[^>]*class="[^"]*result__snippet[^"]*"[^>]*>([\s\S]*?)<\/a>/i.exec(rest) ??
      /<div\b[^>]*class="[^"]*result__snippet[^"]*"[^>]*>([\s\S]*?)<\/div>/i.exec(rest);
    const snippet = snippetMatch ? stripTags(snippetMatch[1] ?? "") : "";
    results.push({ title, url, snippet });
    seen.add(url);
    if (results.length >= limit) break;
  }
  return results;
}

function parseSearx(payload: string, limit: number): WebSearchResult[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload) as unknown;
  } catch {
    throw new Error("search endpoint returned invalid JSON");
  }
  const record =
    parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
  const items = Array.isArray(record?.results) ? record.results : [];
  const results: WebSearchResult[] = [];
  const seen = new Set<string>();
  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    const entry = item as Record<string, unknown>;
    const title = typeof entry.title === "string" ? stripTags(entry.title) : "";
    const url = typeof entry.url === "string" ? entry.url : "";
    const snippet = typeof entry.content === "string" ? stripTags(entry.content) : "";
    if (!title || !url) continue;
    try {
      const final = new URL(url);
      if (!/^https?:$/.test(final.protocol)) continue;
      const normalized = final.toString();
      if (seen.has(normalized)) continue;
      seen.add(normalized);
      results.push({ title, url: normalized, snippet });
    } catch {
      continue;
    }
    if (results.length >= limit) break;
  }
  return results;
}

/** Rejects obvious non-public IPv4 and IPv6 literals. */
export function isPrivateAddress(address: string): boolean {
  const value = address.trim().toLowerCase().replace(/^\[|\]$/g, "").split("%")[0] ?? "";
  if (!value) return true;
  if (value.includes(":")) {
    if (value === "::" || value === "::1") return true;
    if (value.startsWith("fc") || value.startsWith("fd")) return true;
    if (/^fe[89ab]/.test(value)) return true;
    if (value.startsWith("ff")) return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(value);
    if (mapped) return isPrivateAddress(mapped[1] ?? "");
    return false;
  }
  if (isIP(value) !== 4) return true;
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b, c] = parts as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127 || a >= 224 || a === 255) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  return false;
}

export function isPrivateHostname(host: string): boolean {
  const value = host.trim().toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (!value) return true;
  if (value === "localhost" || value.endsWith(".localhost")) return true;
  if (value.endsWith(".local") || value.endsWith(".internal") || value.endsWith(".home.arpa")) return true;
  if (value === "metadata" || value === "instance-data" || value === "metadata.google.internal") return true;
  if (isIP(value) && isPrivateAddress(value)) return true;
  return false;
}

async function resolveAddresses(host: string, options: WebOptions): Promise<string[]> {
  if (isIP(host)) return [host];
  if (options.resolveHost) return options.resolveHost(host);
  try {
    const rows = await lookup(host, { all: true, verbatim: true });
    return rows.map((row) => row.address);
  } catch (error) {
    throw new Error(`cannot resolve ${host}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** Validates a URL and every resolved address before any outbound request. */
export async function assertPublicUrl(value: string, options: WebOptions = {}): Promise<URL> {
  if (value.length > 2_048) throw new Error("URL is too long");
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw new Error(`invalid URL: ${value.slice(0, 120)}`);
  }
  if (!/^https?:$/.test(url.protocol)) throw new Error("only http and https URLs are supported");
  if (url.username || url.password) throw new Error("URLs with embedded credentials are refused");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (!host) throw new Error("URL has no host");
  if (isPrivateHostname(host)) throw new Error(`refusing a private or local host: ${host}`);
  const addresses = await resolveAddresses(host, options);
  if (addresses.length === 0) throw new Error(`cannot resolve ${host}`);
  if (addresses.some((address) => isPrivateAddress(address))) {
    throw new Error(`refusing ${host}: it resolves to a private or local address`);
  }
  return url;
}

function timeoutSignal(options: WebOptions): AbortSignal {
  const timeout = AbortSignal.timeout(options.timeoutMs ?? 12_000);
  return options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;
}

async function readLimited(response: Response, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error(`response is too large (${declared} bytes; limit ${maxBytes})`);
  }
  const body = response.body;
  if (!body) return (await response.text()).slice(0, maxBytes);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel();
        throw new Error(`response exceeded ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

interface PublicFetch {
  response: Response;
  url: URL;
  text: string;
}

async function fetchPublic(
  url: URL,
  options: WebOptions,
  maxBytes: number,
): Promise<PublicFetch> {
  let current = url;
  for (let hop = 0; hop <= 3; hop += 1) {
    const response = await (options.fetchImpl ?? fetch)(current.toString(), {
      method: "GET",
      redirect: "manual",
      credentials: "omit",
      signal: timeoutSignal(options),
      headers: {
        "user-agent": USER_AGENT,
        accept: "text/html,application/xhtml+xml,text/plain,application/json;q=0.8,*/*;q=0.2",
      },
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) throw new Error(`redirect from ${current.hostname} had no location`);
      current = await assertPublicUrl(new URL(location, current).toString(), options);
      continue;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""} from ${current.hostname}`);
    return { response, url: current, text: await readLimited(response, maxBytes) };
  }
  throw new Error("too many redirects");
}

function cleanQuery(query: string): string {
  const value = query.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
  if (value.length < 2) throw new Error("search query is too short");
  return value.slice(0, 256);
}

async function searchSearx(query: string, limit: number, options: WebOptions): Promise<WebSearchResult[]> {
  const configured = process.env.ARGUS_SEARCH_URL?.trim();
  if (!configured) return [];
  let endpoint: URL;
  try {
    endpoint = new URL(configured);
  } catch {
    throw new Error("ARGUS_SEARCH_URL is not a valid URL");
  }
  if (!/^https?:$/.test(endpoint.protocol)) throw new Error("ARGUS_SEARCH_URL must be http(s)");
  endpoint.searchParams.set("q", query);
  endpoint.searchParams.set("format", "json");
  const response = await (options.fetchImpl ?? fetch)(endpoint.toString(), {
    headers: { "user-agent": USER_AGENT, accept: "application/json" },
    signal: timeoutSignal(options),
  });
  if (!response.ok) throw new Error(`search endpoint returned HTTP ${response.status}`);
  return parseSearx(await readLimited(response, 1_000_000), limit);
}

/**
 * Keyless web search. Uses DuckDuckGo's public HTML endpoint, or a user-owned
 * SearXNG instance through ARGUS_SEARCH_URL. Results are cached briefly.
 */
export async function searchWeb(query: string, options: WebOptions & { limit?: number } = {}): Promise<WebSearchResult[]> {
  const cleaned = cleanQuery(query);
  const limit = Math.max(1, Math.min(5, options.limit ?? 4));
  const cacheKey = `${limit}:${cleaned.toLowerCase()}`;
  const cached = searchCache.get(cacheKey);
  if (cached && Date.now() - cached.at < SEARCH_CACHE_MS) return cached.results.map((result) => ({ ...result }));

  const searx = await searchSearx(cleaned, limit, options);
  let results = searx;
  if (results.length === 0) {
    const endpoint = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(cleaned)}`;
    const response = await (options.fetchImpl ?? fetch)(endpoint, {
      headers: {
        "user-agent": USER_AGENT,
        accept: "text/html,application/xhtml+xml",
      },
      signal: timeoutSignal(options),
    });
    if (!response.ok) {
      throw new Error(
        `web search failed with HTTP ${response.status}${response.status === 429 ? " (rate limited)" : ""}` +
          (process.env.ARGUS_SEARCH_URL ? "" : " — set ARGUS_SEARCH_URL to a SearXNG JSON endpoint if this persists"),
      );
    }
    const html = await readLimited(response, 750_000);
    results = parseDuckDuckGo(html, limit);
    if (results.length === 0 && /anomaly|captcha|unusual traffic/i.test(html)) {
      throw new Error("the search engine returned a bot check — set ARGUS_SEARCH_URL to a SearXNG JSON endpoint");
    }
  }
  if (results.length === 0) throw new Error(`no web results for "${cleaned}"`);
  searchCache.set(cacheKey, { at: Date.now(), results });
  return results.map((result) => ({ ...result }));
}

function cleanPageText(value: string): string {
  return value
    .replace(/\r/g, "")
    .replace(/[ \t\f\v]+/g, " ")
    .replace(/ *\n */g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/** Fetches a public page with redirect, size, content-type and SSRF checks. */
export async function readWebPage(
  value: string,
  options: WebOptions & { maxChars?: number } = {},
): Promise<WebPage> {
  const url = await assertPublicUrl(value, options);
  const { response, url: finalUrl, text } = await fetchPublic(url, options, 400_000);
  const contentType = (response.headers.get("content-type") ?? "").toLowerCase();
  if (contentType && !/text\/|application\/(xhtml|json|xml)/.test(contentType)) {
    throw new Error(`unsupported content type: ${contentType.split(";")[0]}`);
  }
  const maxChars = Math.max(1_000, Math.min(20_000, options.maxChars ?? 8_000));
  const html = /html|xml/.test(contentType) || /^\s*<!doctype html/i.test(text) || /<html\b/i.test(text);
  const title = html ? extractTitle(text) : "";
  const body = cleanPageText(html ? htmlToText(text) : text);
  if (!body) throw new Error("page returned no readable text");
  return {
    url: finalUrl.toString(),
    title: title || finalUrl.hostname,
    text: body.slice(0, maxChars),
    truncated: body.length > maxChars,
  };
}
