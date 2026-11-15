import http from "node:http";
import https from "node:https";
import { checkServerIdentity, connect as tlsConnect, type PeerCertificate } from "node:tls";
import type { TLSSocket } from "node:tls";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";
import type { Readable } from "node:stream";
import type { HttpClientOptions, HttpResponse, TlsInfo } from "./types";
import type { ScopeGuard } from "./scope";
import { sleep } from "./util";

export class ScopeViolationError extends Error {
  readonly code = "SCOPE_VIOLATION";
  constructor(message: string) {
    super(message);
    this.name = "ScopeViolationError";
  }
}

export class RequestTimeoutError extends Error {
  readonly code = "REQUEST_TIMEOUT";
  constructor(message: string) {
    super(message);
    this.name = "RequestTimeoutError";
  }
}

export class RateLimiter {
  private nextAt = 0;
  private readonly intervalMs: number;

  constructor(maxRps: number) {
    this.intervalMs = 1000 / Math.max(1, maxRps);
  }

  async acquire(signal?: AbortSignal): Promise<void> {
    const now = Date.now();
    const scheduled = Math.max(now, this.nextAt);
    this.nextAt = scheduled + this.intervalMs;
    if (scheduled > now) await sleep(scheduled - now, signal);
  }
}

export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxBodyBytes?: number;
  maxRedirects?: number;
  followRedirects?: boolean;
  signal?: AbortSignal;
  allowCrossOriginRedirects?: boolean;
}

export class HttpClient {
  readonly guard: ScopeGuard;
  readonly limiter: RateLimiter;
  readonly settings: HttpClientOptions;
  private readonly httpAgent: http.Agent;
  private readonly httpsAgent: https.Agent;
  private requestCount = 0;
  private errorCount = 0;

  constructor(guard: ScopeGuard, options: HttpClientOptions) {
    this.guard = guard;
    this.settings = options;
    this.limiter = new RateLimiter(options.maxRps ?? 20);
    const keepAlive = options.keepAlive ?? true;
    this.httpAgent = new http.Agent({ keepAlive, maxSockets: 12 });
    this.httpsAgent = new https.Agent({ keepAlive, maxSockets: 12, rejectUnauthorized: false });
  }

  get metrics(): { requests: number; errors: number } {
    return { requests: this.requestCount, errors: this.errorCount };
  }

  async request(rawUrl: string, options: RequestOptions = {}): Promise<HttpResponse> {
    const maxRedirects = options.maxRedirects ?? this.settings.maxRedirects ?? 5;
    const follow = options.followRedirects ?? true;
    const redirects: string[] = [];
    let currentUrl = rawUrl;
    let method = (options.method ?? "GET").toUpperCase();

    for (let hop = 0; hop <= maxRedirects; hop += 1) {
      const check = this.guard.checkUrl(currentUrl);
      if (!check.allowed) throw new ScopeViolationError(`${currentUrl} :: ${check.reason}`);
      await this.limiter.acquire(options.signal);
      const response = await this.singleRequest(currentUrl, method, options);
      if (!follow) return { ...response, redirects };
      const location = response.headers.location;
      if (!location || ![301, 302, 303, 307, 308].includes(response.status)) {
        return { ...response, redirects };
      }
      let nextUrl: string;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch {
        return { ...response, redirects };
      }
      redirects.push(nextUrl);
      const nextCheck = this.guard.checkUrl(nextUrl);
      if (!nextCheck.allowed) {
        if (options.allowCrossOriginRedirects === false) return { ...response, redirects };
        throw new ScopeViolationError(`Redirect escaped scope: ${nextCheck.reason}`);
      }
      currentUrl = nextUrl;
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === "POST")) {
        method = "GET";
      }
      if (method === "GET" || method === "HEAD") options = { ...options, body: undefined };
    }
    throw new Error(`Too many redirects starting at ${rawUrl}`);
  }

  async get(url: string, options: RequestOptions = {}): Promise<HttpResponse> {
    return this.request(url, { ...options, method: "GET" });
  }

  async head(url: string, options: RequestOptions = {}): Promise<HttpResponse> {
    return this.request(url, { ...options, method: "HEAD" });
  }

  async options(url: string, options: RequestOptions = {}): Promise<HttpResponse> {
    return this.request(url, { ...options, method: "OPTIONS" });
  }

  async post(url: string, body: string, options: RequestOptions = {}): Promise<HttpResponse> {
    return this.request(url, { ...options, method: "POST", body });
  }

  close(): void {
    this.httpAgent.destroy();
    this.httpsAgent.destroy();
  }

  private async singleRequest(url: string, method: string, options: RequestOptions): Promise<HttpResponse> {
    const started = Date.now();
    const target = new URL(url);
    const timeoutMs = options.timeoutMs ?? this.settings.timeoutMs;
    const maxBodyBytes = options.maxBodyBytes ?? this.settings.maxBodyBytes ?? 2_000_000;
    const isHttps = target.protocol === "https:";
    const headers: Record<string, string> = {
      "user-agent": this.settings.userAgent,
      accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
      "accept-language": "en-US,en;q=0.9",
      "accept-encoding": "gzip, deflate, br",
      connection: "keep-alive",
      ...(options.headers ?? {}),
    };
    if (options.body !== undefined) {
      headers["content-length"] = String(Buffer.byteLength(options.body));
      headers["content-type"] = headers["content-type"] ?? "application/x-www-form-urlencoded";
    }

    const requestOptions: https.RequestOptions = {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (isHttps ? 443 : 80),
      path: `${target.pathname}${target.search}`,
      method,
      headers,
      agent: isHttps ? this.httpsAgent : this.httpAgent,
      rejectUnauthorized: false,
      servername: isHttps && !isIpAddress(target.hostname) ? target.hostname : undefined,
    };

    this.requestCount += 1;
    return await new Promise<HttpResponse>((resolvePromise, reject) => {
      const transport = isHttps ? https : http;
      const req = transport.request(requestOptions, (res) => {
        // Peer-certificate details are only readable while the socket is still
        // attached. The agent releases it (res.socket -> null) once the body has
        // been consumed or the request is aborted, so read the handshake here
        // instead of inside the stream callbacks below.
        const tls = isHttps ? readPeerTls(res.socket, target.hostname) : undefined;
        const chunks: Buffer[] = [];
        let total = 0;
        let truncated = false;
        const stream = decodeStream(res);
        stream.on("data", (chunk: Buffer) => {
          if (total >= maxBodyBytes) return;
          const remaining = maxBodyBytes - total;
          const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
          chunks.push(slice);
          total += slice.length;
          if (slice.length < chunk.length) truncated = true;
        });
        stream.on("end", () => {
          // A throw here used to escape into the event loop: the socket call is
          // gone, but a res rejection keeps the request from hanging forever.
          try {
            const rawHeaders: Record<string, string[]> = {};
            for (let index = 0; index < res.rawHeaders.length; index += 2) {
              const key = res.rawHeaders[index]!.toLowerCase();
              const value = res.rawHeaders[index + 1] ?? "";
              (rawHeaders[key] ??= []).push(value);
            }
            const combined: Record<string, string> = {};
            for (const [key, values] of Object.entries(rawHeaders)) combined[key] = values.join(key === "set-cookie" ? "\n" : ", ");
            const buffer = Buffer.concat(chunks);
            const body = decodeBody(buffer, combined["content-type"]);
            resolvePromise({
              url,
              finalUrl: url,
              status: res.statusCode ?? 0,
              statusText: res.statusMessage ?? "",
              headers: combined,
              rawHeaders,
              body: truncated ? `${body}\n[argus: body truncated at ${maxBodyBytes} bytes]` : body,
              bodyBytes: total,
              elapsedMs: Date.now() - started,
              redirects: [],
              tls,
            });
          } catch (error) {
            this.errorCount += 1;
            reject(error instanceof Error ? error : new Error(String(error)));
          }
        });
        stream.on("error", (error) => {
          this.errorCount += 1;
          reject(error);
        });
      });
      req.on("error", (error) => {
        this.errorCount += 1;
        reject(error);
      });
      req.setTimeout(timeoutMs, () => {
        this.errorCount += 1;
        req.destroy(new RequestTimeoutError(`Request timed out after ${timeoutMs}ms: ${url}`));
      });
      const onAbort = () => req.destroy(new Error("aborted"));
      if (options.signal?.aborted) {
        req.destroy(new Error("aborted"));
        return;
      }
      options.signal?.addEventListener("abort", onAbort, { once: true });
      req.on("close", () => options.signal?.removeEventListener("abort", onAbort));
      if (options.body !== undefined && method !== "GET" && method !== "HEAD") req.write(options.body);
      req.end();
    });
  }
}

export async function probeTlsVersions(host: string, port: number, timeoutMs = 3000): Promise<Array<{ version: string; supported: boolean; cipher?: string }>> {
  const versions = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"] as const;
  const results: Array<{ version: string; supported: boolean; cipher?: string }> = [];
  for (const version of versions) {
    const result = await new Promise<{ version: string; supported: boolean; cipher?: string }>((resolvePromise) => {
      let settled = false;
      let socket: import("node:tls").TLSSocket;
      try {
        socket = tlsConnect({
          host,
          port,
          servername: isIpAddress(host) ? undefined : host,
          rejectUnauthorized: false,
          minVersion: version,
          maxVersion: version,
          timeout: timeoutMs,
        });
      } catch {
        resolvePromise({ version, supported: false });
        return;
      }
      const finish = (supported: boolean, cipher?: string) => {
        if (settled) return;
        settled = true;
        try {
          socket.destroy();
        } catch {
          // ignore
        }
        resolvePromise({ version, supported, cipher });
      };
      socket.once("secureConnect", () => {
        let cipher: string | undefined;
        try {
          cipher = socket.getCipher()?.name;
        } catch {
          cipher = undefined;
        }
        finish(true, cipher);
      });
      socket.once("error", () => finish(false));
      socket.once("timeout", () => finish(false));
    });
    results.push(result);
  }
  return results;
}

function decodeStream(res: http.IncomingMessage): Readable {
  const encoding = String(res.headers["content-encoding"] ?? "").toLowerCase();
  const stream = res as unknown as Readable;
  if (encoding.includes("gzip")) return stream.pipe(createGunzip());
  if (encoding.includes("deflate")) return stream.pipe(createInflate());
  if (encoding.includes("br")) return stream.pipe(createBrotliDecompress());
  return stream;
}

function decodeBody(buffer: Buffer, contentType?: string): string {
  const charset = /charset=([^;]+)/i.exec(contentType ?? "")?.[1]?.trim().toLowerCase();
  if (charset === "iso-8859-1" || charset === "latin1") return buffer.toString("latin1");
  if (charset === "utf-16le") return buffer.toString("utf16le");
  return buffer.toString("utf8");
}

/**
 * Peer-certificate details for whatever socket a response still carries.
 * `res.socket` is null once the body has been read or the request aborted, so a
 * missing socket is normal: it means the handshake details are simply gone.
 */
export function readPeerTls(socket: unknown, hostname: string): TlsInfo | undefined {
  const candidate = socket as TLSSocket | null | undefined;
  if (!candidate || typeof candidate.getPeerCertificate !== "function") return undefined;
  return readTls(candidate, hostname);
}

function readTls(socket: TLSSocket, hostname: string): TlsInfo | undefined {
  try {
    const cert = socket.getPeerCertificate(false);
    if (!cert || !cert.subject) return undefined;
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);
    const daysRemaining = Math.ceil((validTo.getTime() - Date.now()) / (24 * 60 * 60 * 1000));
    const san = parseSan(cert);
    const mismatch = checkServerIdentity(hostname, cert as PeerCertificate);
    const issuer = cert.issuer ?? {};
    const subject = cert.subject ?? {};
    const selfSigned = JSON.stringify(issuer) === JSON.stringify(subject);
    return {
      protocol: socket.getProtocol() ?? "unknown",
      cipher: socket.getCipher()?.name ?? "unknown",
      subject: formatDn(subject),
      issuer: formatDn(issuer),
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      daysRemaining,
      san,
      selfSigned,
      hostnameMatch: !mismatch,
      fingerprint256: cert.fingerprint256 ?? "",
    };
  } catch {
    return undefined;
  }
}

export function parseSan(cert: PeerCertificate): string[] {
  const san = (cert as PeerCertificate & { subjectaltname?: string }).subjectaltname;
  if (!san) return [];
  return san
    .split(",")
    .map((part) => part.trim())
    .map((part) => part.replace(/^DNS:/i, "").replace(/^IP Address:/i, ""))
    .filter(Boolean);
}

function formatDn(dn: Record<string, unknown>): string {
  const keys = ["CN", "O", "OU", "C", "L", "ST"];
  const parts: string[] = [];
  for (const key of keys) {
    const value = dn[key];
    if (value) parts.push(`${key}=${Array.isArray(value) ? value.join("/") : String(value)}`);
  }
  return parts.join(", ") || "unknown";
}

function isIpAddress(value: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":");
}
