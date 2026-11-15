/**
 * Traffic history for one agent session. Argus has no intercepting proxy, so
 * this is the structured record behind http_request: every request the agent
 * sent, queryable by host/status/method, plus a sitemap of observed endpoints.
 */
export interface TrafficEntry {
  id: string;
  method: string;
  url: string;
  host: string;
  path: string;
  status: number;
  statusText: string;
  bytes: number;
  elapsedMs: number;
  contentType?: string;
  finalUrl?: string;
  at: string;
}

export interface TrafficQuery {
  host?: string;
  status?: number;
  method?: string;
  contains?: string;
  limit?: number;
}

export interface SitemapHost {
  host: string;
  requests: number;
  endpoints: Array<{ path: string; methods: string[]; lastStatus: number; count: number }>;
}

export type TrafficInput = Omit<TrafficEntry, "id" | "at" | "host" | "path"> & { at?: string };

function hostAndPath(rawUrl: string): { host: string; path: string } {
  try {
    const url = new URL(rawUrl);
    return { host: url.host.toLowerCase(), path: url.pathname || "/" };
  } catch {
    return { host: "", path: rawUrl };
  }
}

export class TrafficLog {
  private readonly items: TrafficEntry[] = [];
  private seq = 0;

  constructor(private readonly max = 500) {}

  get size(): number {
    return this.items.length;
  }

  record(input: TrafficInput): TrafficEntry {
    const { host, path } = hostAndPath(input.url);
    const entry: TrafficEntry = {
      ...input,
      id: `req-${++this.seq}`,
      host,
      path,
      at: input.at ?? new Date().toISOString(),
    };
    this.items.push(entry);
    if (this.items.length > this.max) this.items.splice(0, this.items.length - this.max);
    return entry;
  }

  list(query: TrafficQuery = {}): TrafficEntry[] {
    const host = query.host?.toLowerCase();
    const method = query.method?.toUpperCase();
    const needle = query.contains?.toLowerCase();
    const rows = this.items.filter((entry) => {
      if (host && entry.host !== host) return false;
      if (query.status !== undefined && entry.status !== query.status) return false;
      if (method && entry.method.toUpperCase() !== method) return false;
      if (needle) {
        const haystack = `${entry.url} ${entry.status} ${entry.contentType ?? ""}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
    const limit = Math.min(query.limit ?? 50, 200);
    return rows.slice(-limit);
  }

  sitemap(): SitemapHost[] {
    const hosts = new Map<string, Map<string, { methods: Set<string>; lastStatus: number; count: number }>>();
    for (const entry of this.items) {
      if (!entry.host) continue;
      let endpoints = hosts.get(entry.host);
      if (!endpoints) {
        endpoints = new Map();
        hosts.set(entry.host, endpoints);
      }
      const current = endpoints.get(entry.path) ?? { methods: new Set<string>(), lastStatus: entry.status, count: 0 };
      current.methods.add(entry.method.toUpperCase());
      current.lastStatus = entry.status;
      current.count += 1;
      endpoints.set(entry.path, current);
    }
    return [...hosts.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([host, endpoints]) => ({
        host,
        requests: [...endpoints.values()].reduce((sum, value) => sum + value.count, 0),
        endpoints: [...endpoints.entries()]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([path, value]) => ({
            path,
            methods: [...value.methods].sort(),
            lastStatus: value.lastStatus,
            count: value.count,
          })),
      }));
  }

  clear(): void {
    this.items.length = 0;
  }
}
