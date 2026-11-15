/**
 * Local intercepting proxy, modelled on the proxy surface Strix exposes to its
 * agents (list captured traffic, inspect a request, replay/modify it, sitemap).
 *
 * Plain HTTP is fully inspectable: requests can be held, inspected, modified and
 * then forwarded or dropped. HTTPS is tunnelled with CONNECT and recorded as
 * metadata only - Argus does not generate a CA or decrypt TLS, because doing so
 * silently on an operator's machine would be a much larger security decision
 * than a pentest harness should make on its own.
 *
 * The proxy is opt-in per session (`proxy start`), binds loopback only, and
 * keeps at most a bounded set of captures in memory. Nothing is written to disk.
 */
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { connect as netConnect, type Socket } from "node:net";
import { newId } from "./util";

export type ProxySource = "http" | "connect";

export interface ProxyEntry {
  id: string;
  method: string;
  url: string;
  host: string;
  path: string;
  status: number;
  statusText: string;
  bytes: number;
  startedAt: string;
  elapsedMs: number;
  source: ProxySource;
  requestHeaders?: Record<string, string>;
  requestBody?: string;
  responsePreview?: string;
  note?: string;
}

export interface ProxyQuery {
  host?: string;
  status?: number;
  method?: string;
  contains?: string;
  limit?: number;
}

export interface ProxyModifications {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string;
}

interface HeldRequest {
  entry: ProxyEntry;
  resolve: (decision: "allow" | "drop", modifications?: ProxyModifications) => void;
}

const MAX_BODY = 1_000_000;
const MAX_PREVIEW = 32_000;

function parseTarget(raw: string): { url: URL; host: string; path: string } | undefined {
  try {
    const url = new URL(raw);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    return { url, host: url.host.toLowerCase(), path: `${url.pathname}${url.search}` };
  } catch {
    return undefined;
  }
}

function headersFor(entry: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(entry.headers)) {
    if (value === undefined) continue;
    out[key] = Array.isArray(value) ? value.join(", ") : String(value);
  }
  return out;
}

function sanitizeForwardHeaders(headers: Record<string, string>, host: string): Record<string, string> {
  const blocked = new Set(["proxy-connection", "connection", "keep-alive", "upgrade", "host", "content-length", "transfer-encoding"]);
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!blocked.has(key.toLowerCase())) out[key] = value;
  }
  out.host = host;
  return out;
}

export class InterceptProxy {
  private server?: Server;
  private sockets = new Set<Socket>();
  private entries: ProxyEntry[] = [];
  private held = new Map<string, HeldRequest>();
  private intercepting = false;
  private listeningPort = 0;

  get url(): string {
    return this.listeningPort ? `http://127.0.0.1:${this.listeningPort}` : "";
  }

  get running(): boolean {
    return Boolean(this.server);
  }

  get interceptEnabled(): boolean {
    return this.intercepting;
  }

  async start(port = 0): Promise<{ url: string; port: number }> {
    if (this.server) return { url: this.url, port: this.listeningPort };
    const server = createServer((request, response) => {
      void this.handleRequest(request, response);
    });
    server.on("connect", (request, socket, head) => this.handleConnect(request, socket as Socket, head));
    server.on("connection", (socket) => {
      this.sockets.add(socket);
      socket.on("close", () => this.sockets.delete(socket));
    });
    await new Promise<void>((done, fail) => {
      server.once("error", fail);
      server.listen(port, "127.0.0.1", () => done());
    });
    this.server = server;
    const address = server.address();
    this.listeningPort = typeof address === "object" && address ? address.port : port;
    return { url: this.url, port: this.listeningPort };
  }

  async stop(): Promise<void> {
    for (const held of this.held.values()) held.resolve("drop");
    this.held.clear();
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    const server = this.server;
    this.server = undefined;
    this.listeningPort = 0;
    if (!server) return;
    await new Promise<void>((done) => server.close(() => done()));
  }

  setIntercept(enabled: boolean): void {
    this.intercepting = enabled;
    if (!enabled) {
      for (const held of this.held.values()) held.resolve("allow");
      this.held.clear();
    }
  }

  history(query: ProxyQuery = {}): ProxyEntry[] {
    const host = query.host?.toLowerCase();
    const method = query.method?.toUpperCase();
    const needle = query.contains?.toLowerCase();
    const rows = this.entries.filter((entry) => {
      if (host && entry.host !== host) return false;
      if (query.status !== undefined && entry.status !== query.status) return false;
      if (method && entry.method.toUpperCase() !== method) return false;
      if (needle) {
        const haystack = `${entry.url} ${entry.requestBody ?? ""} ${entry.responsePreview ?? ""}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
    const limit = Math.min(query.limit ?? 50, 200);
    return rows.slice(-limit);
  }

  pending(): ProxyEntry[] {
    return [...this.held.values()].map((held) => held.entry);
  }

  allow(id: string, modifications?: ProxyModifications): boolean {
    const held = this.held.get(id);
    if (!held) return false;
    this.held.delete(id);
    held.resolve("allow", modifications);
    return true;
  }

  drop(id: string): boolean {
    const held = this.held.get(id);
    if (!held) return false;
    this.held.delete(id);
    held.resolve("drop");
    return true;
  }

  clear(): void {
    this.entries.length = 0;
  }

  private record(entry: ProxyEntry): void {
    this.entries.push(entry);
    if (this.entries.length > 500) this.entries.splice(0, this.entries.length - 500);
  }

  private async readBody(request: IncomingMessage): Promise<string> {
    return new Promise((done, fail) => {
      let body = "";
      let size = 0;
      request.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY) {
          fail(new Error("Request body exceeds the 1 MB proxy capture limit."));
          request.destroy();
          return;
        }
        body += chunk.toString();
      });
      request.on("end", () => done(body));
      request.on("error", fail);
    });
  }

  private async handleRequest(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const rawUrl = request.url ?? "";
    const target = parseTarget(rawUrl);
    if (!target) {
      response.writeHead(400, { "content-type": "text/plain" });
      response.end("ARGUS proxy expects an absolute http:// URL (configure it as an HTTP proxy).\n");
      return;
    }
    const started = Date.now();
    let body = "";
    try {
      body = await this.readBody(request);
    } catch (error) {
      response.writeHead(413, { "content-type": "text/plain" });
      response.end(error instanceof Error ? error.message : String(error));
      return;
    }
    const base: ProxyEntry = {
      id: newId("proxy"),
      method: (request.method ?? "GET").toUpperCase(),
      url: target.url.toString(),
      host: target.host,
      path: target.path,
      status: 0,
      statusText: "",
      bytes: 0,
      startedAt: new Date(started).toISOString(),
      elapsedMs: 0,
      source: "http",
      requestHeaders: headersFor(request),
      ...(body ? { requestBody: body.slice(0, MAX_PREVIEW) } : {}),
    };

    let modifications: ProxyModifications | undefined;
    if (this.intercepting) {
      const decision = await new Promise<{ action: "allow" | "drop"; modifications?: ProxyModifications }>((done) => {
        this.held.set(base.id, { entry: base, resolve: (action, mods) => done({ action, modifications: mods }) });
      });
      if (decision.action === "drop") {
        const entry: ProxyEntry = {
          ...base,
          status: 403,
          statusText: "Dropped by intercept",
          note: "held and dropped by the operator or agent",
          elapsedMs: Date.now() - started,
        };
        this.record(entry);
        response.writeHead(403, { "content-type": "text/plain" });
        response.end("Dropped by the ARGUS proxy intercept.\n");
        return;
      }
      modifications = decision.modifications;
    }

    const method = (modifications?.method ?? base.method).toUpperCase();
    const sendUrl = modifications?.url ? new URL(modifications.url) : target.url;
    const sendBody = modifications?.body ?? body;
    const headers = sanitizeForwardHeaders(
      { ...(base.requestHeaders ?? {}), ...(modifications?.headers ?? {}) },
      sendUrl.host,
    );
    if (sendBody) headers["content-length"] = String(Buffer.byteLength(sendBody));

    await new Promise<void>((done) => {
      const upstream = httpRequest(
        {
          protocol: sendUrl.protocol,
          hostname: sendUrl.hostname,
          port: sendUrl.port || (sendUrl.protocol === "https:" ? 443 : 80),
          path: `${sendUrl.pathname}${sendUrl.search}`,
          method,
          headers,
          timeout: 30_000,
        },
        (upstreamResponse) => {
          const status = upstreamResponse.statusCode ?? 0;
          response.writeHead(status, upstreamResponse.statusMessage, upstreamResponse.headers);
          const chunks: Buffer[] = [];
          let preview = "";
          upstreamResponse.on("data", (chunk: Buffer) => {
            if (preview.length < MAX_PREVIEW) {
              chunks.push(chunk);
              preview = Buffer.concat(chunks).toString().slice(0, MAX_PREVIEW);
            }
            response.write(chunk);
          });
          upstreamResponse.on("end", () => {
            response.end();
            this.record({
              ...base,
              method,
              url: sendUrl.toString(),
              status,
              statusText: upstreamResponse.statusMessage ?? "",
              bytes: Number(upstreamResponse.headers["content-length"] ?? preview.length),
              elapsedMs: Date.now() - started,
              ...(preview ? { responsePreview: preview } : {}),
              ...(modifications ? { note: "modified before forwarding" } : {}),
            });
            done();
          });
        },
      );
      upstream.on("timeout", () => upstream.destroy(new Error("Upstream timed out.")));
      upstream.on("error", (error) => {
        if (!response.headersSent) {
          response.writeHead(502, { "content-type": "text/plain" });
        }
        response.end(`Upstream error: ${error.message}\n`);
        this.record({
          ...base,
          method,
          url: sendUrl.toString(),
          status: 502,
          statusText: "Bad Gateway",
          elapsedMs: Date.now() - started,
          note: error.message,
        });
        done();
      });
      if (sendBody) upstream.write(sendBody);
      upstream.end();
    });
  }

  private handleConnect(request: IncomingMessage, clientSocket: Socket, head: Buffer): void {
    const target = request.url ?? "";
    const [host, portRaw] = target.split(":");
    const port = Number(portRaw ?? 443);
    const entry: ProxyEntry = {
      id: newId("proxy"),
      method: "CONNECT",
      url: `https://${host}:${port}`,
      host: `${host}:${port}`.toLowerCase(),
      path: "/",
      status: 0,
      statusText: "",
      bytes: 0,
      startedAt: new Date().toISOString(),
      elapsedMs: 0,
      source: "connect",
      note: "TLS tunnel, not decrypted",
    };
    const started = Date.now();
    const upstream = netConnect(port, host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
      this.record({ ...entry, status: 200, statusText: "Connection Established", elapsedMs: Date.now() - started });
    });
    let bytes = 0;
    upstream.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
    });
    upstream.on("error", () => {
      if (!clientSocket.destroyed) clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      this.record({ ...entry, status: 502, statusText: "Bad Gateway", bytes, elapsedMs: Date.now() - started });
    });
    upstream.on("close", () => {
      entry.bytes = bytes;
      clientSocket.destroy();
    });
    clientSocket.on("error", () => upstream.destroy());
  }
}
