import net from "node:net";
import type { FindingDraft, PhaseTask, ProbeContext } from "../types";
import { COMMON_PORTS, type PortInfo } from "../signatures";
import { detectTechnologies, expandCidrHosts, extractTitle } from "../recon-utils";
import { formatDuration, truncate } from "../util";

interface OpenPort {
  host: string;
  port: number;
  info?: PortInfo;
  banner: string;
  scheme?: "http" | "https";
  response?: { status: number; title: string; server: string; technologies: string[]; body: string; url: string };
}

const HTTP_SERVICE_PORTS = new Set([80, 443, 3000, 5000, 5601, 5984, 6443, 7001, 8000, 8080, 8081, 8086, 8443, 8500, 8888, 9000, 9001, 9090, 9200, 9443, 15672, 2375, 2376, 10250, 2379, 2380]);
const RISKY_ADMIN = /Grafana|Kibana|Jenkins|Portainer|Consul|Vault|RabbitMQ|Prometheus|Jupyter|Elasticsearch|MinIO|Docker|Kubernetes/i;

export const networkTasks: PhaseTask[] = [
  {
    id: "ports",
    label: "Port scan & exposed service audit",
    phase: "surface",
    requiresActive: true,
    run: async (ctx) => {
      const hosts = resolveHosts(ctx);
      if (hosts.length === 0) return;
      let ports = selectPorts(ctx);
      if (ctx.target.port && !ports.includes(ctx.target.port)) ports.push(ctx.target.port);
      ports = [...new Set(ports)].sort((a, b) => a - b);
      let truncatedHosts = false;
      const attemptsPerHost = ports.length;
      const maxAttempts = 2500;
      let scanHosts = hosts;
      if (scanHosts.length * attemptsPerHost > maxAttempts) {
        const maxHosts = Math.max(1, Math.floor(maxAttempts / attemptsPerHost));
        scanHosts = scanHosts.slice(0, maxHosts);
        truncatedHosts = scanHosts.length < hosts.length;
      }
      ctx.log("info", `Scanning ${scanHosts.length} host(s) x ${ports.length} port(s)${truncatedHosts ? " (range truncated)" : ""}`, "ports");
      const started = Date.now();
      const open: OpenPort[] = [];
      const tasks: Array<{ host: string; port: number }> = [];
      let blocked = 0;
      for (const host of scanHosts) {
        for (const port of ports) {
          if (ctx.signal.aborted) break;
          const hostCheck = ctx.guard.checkHost(host, port, port === 443 || port === 8443 || port === 9443 ? "https" : "http");
          const portCheck = ctx.guard.checkPort(port);
          if (!hostCheck.allowed || !portCheck.allowed) {
            blocked += 1;
            continue;
          }
          tasks.push({ host, port });
        }
      }
      if (blocked > 0) ctx.log("debug", `${blocked} host/port combinations blocked by scope`, "ports");
      const concurrency = Math.min(100, Math.max(5, ctx.options.concurrency ?? 50));
      await mapPool(tasks, concurrency, async (task) => {
        const result = await probeTcp(task.host, task.port, ctx.options.timeoutMs ?? 10_000);
        if (result.open) open.push({ host: task.host, port: task.port, info: COMMON_PORTS.find((entry) => entry.port === task.port), banner: result.banner });
      }, ctx.signal);
      ctx.log("info", `Port scan complete: ${open.length} open of ${tasks.length} probes in ${formatDuration(Date.now() - started)}`, "ports");
      const findings: FindingDraft[] = [];
      const seen = new Set<string>();
      for (const entry of open.sort((a, b) => a.host.localeCompare(b.host) || a.port - b.port)) {
        const key = `${entry.host}:${entry.port}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const info = entry.info;
        const severity = info?.severity ?? "info";
        const bannerText = entry.banner ? `\nBanner: ${truncate(entry.banner, 500)}` : "";
        const serviceName = info?.service ?? guessService(entry.port, entry.banner);
        findings.push({
          title: info && severity !== "info" ? `Exposed service: ${serviceName} (${entry.port}/tcp)` : `Open port: ${entry.port}/tcp (${serviceName})`,
          severity,
          category: "network",
          confidence: "confirmed",
          tool: "argus-ports",
          target: `${entry.host}:${entry.port}`,
          evidence: `TCP connect succeeded to ${entry.host}:${entry.port}.\n${info?.note ?? "Service identified by port number."}${bannerText}`,
          description:
            severity === "info"
              ? "The port is reachable from the assessment network."
              : "A potentially sensitive service is reachable. Exposure alone does not confirm weak authentication, but database, admin and remote-access ports should not be internet-facing unless strictly required.",
          remediation: "Restrict the service to trusted networks, require strong authentication, and keep the software patched.",
          references: [],
          metadata: { host: entry.host, port: entry.port, service: serviceName, banner: entry.banner },
          dedupeKey: `port-${entry.host}-${entry.port}`,
        });
      }
      if (ctx.scope.allowActive) {
        await auditServices(ctx, open, findings);
      }
      if (truncatedHosts) {
        findings.push({
          title: "Large network range scan truncated",
          severity: "info",
          category: "recon",
          confidence: "confirmed",
          tool: "argus-ports",
          evidence: `Native scanner capped the range at ${scanHosts.length} of ${hosts.length} hosts. Use the nmap adapter for larger ranges.`,
          description: "The native scanner limits attempts to keep load predictable.",
          remediation: "Install nmap for broad range scans, or narrow the authorized CIDR.",
          references: [],
          dedupeKey: "ports-truncated",
        });
      }
      return findings;
    },
  },
];

function resolveHosts(ctx: ProbeContext): string[] {
  const host = ctx.target.host;
  if (!host) return [];
  if (host.includes("/") && /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(host)) {
    const expanded = expandCidrHosts(host, 256);
    if (expanded.truncated) ctx.log("warn", `CIDR ${host} has ${expanded.total} hosts; scanning first ${expanded.hosts.length}`, "ports");
    return expanded.hosts;
  }
  return [host];
}

function selectPorts(ctx: ProbeContext): number[] {
  if (ctx.scope.allowedPorts?.length) {
    return ctx.scope.allowedPorts.filter((port) => ctx.guard.checkPort(port).allowed);
  }
  return COMMON_PORTS.map((entry) => entry.port);
}

function probeTcp(host: string, port: number, timeoutMs: number): Promise<{ open: boolean; banner: string }> {
  return new Promise((resolvePromise) => {
    let banner = "";
    let settled = false;
    const socket = net.createConnection({ host, port });
    const finish = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolvePromise({ open, banner: sanitizeBanner(banner) });
    };
    const timer = setTimeout(() => finish(false), Math.min(2500, timeoutMs));
    socket.once("connect", () => {
      clearTimeout(timer);
      const bannerTimer = setTimeout(() => finish(true), 650);
      socket.on("data", (chunk) => {
        banner += chunk.toString("utf8");
        if (banner.length > 2000) banner = banner.slice(0, 2000);
        clearTimeout(bannerTimer);
        setTimeout(() => finish(true), 120);
      });
      socket.on("error", () => finish(true));
      socket.on("close", () => finish(true));
      setTimeout(() => finish(true), 650);
    });
    socket.once("error", () => {
      clearTimeout(timer);
      finish(false);
    });
    socket.setTimeout(Math.min(2500, timeoutMs), () => finish(false));
  });
}

function tcpExchange(host: string, port: number, payload: string, timeoutMs = 2500): Promise<string> {
  return new Promise((resolvePromise) => {
    let output = "";
    let settled = false;
    const socket = net.createConnection({ host, port });
    const finish = () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolvePromise(output);
    };
    const timer = setTimeout(finish, timeoutMs);
    socket.once("connect", () => {
      socket.write(payload);
    });
    socket.on("data", (chunk) => {
      output += chunk.toString("utf8");
      if (output.length > 4000) finish();
    });
    socket.on("error", finish);
    socket.on("close", finish);
    socket.setTimeout(timeoutMs, finish);
    timer.unref?.();
  });
}

async function auditServices(ctx: ProbeContext, open: OpenPort[], findings: FindingDraft[]): Promise<void> {
  for (const entry of open) {
    if (ctx.signal.aborted) return;
    const host = entry.host;
    const port = entry.port;
    const info = entry.info;
    if (port === 6379) {
      const reply = await tcpExchange(host, port, "PING\r\n");
      if (reply.includes("+PONG")) {
        findings.push({
          title: "Unauthenticated Redis instance",
          severity: "critical",
          category: "network",
          confidence: "confirmed",
          tool: "argus-services",
          target: `${host}:${port}`,
          evidence: `PING -> ${truncate(reply, 200)}`,
          description: "Redis accepted an unauthenticated PING. Such instances allow data theft, configuration changes and often remote code execution.",
          remediation: "Bind Redis to private interfaces, require strong ACLs, disable dangerous commands and firewall the port.",
          references: ["https://redis.io/docs/management/security/"],
          cwe: "CWE-306",
          metadata: { host, port, service: "redis" },
          dedupeKey: `service-redis-${host}-${port}`,
        });
      }
      continue;
    }
    if (port === 11211) {
      const reply = await tcpExchange(host, port, "stats\r\n");
      if (/STAT\s+pid/i.test(reply)) {
        findings.push({
          title: "Unauthenticated Memcached instance",
          severity: "high",
          category: "network",
          confidence: "confirmed",
          tool: "argus-services",
          target: `${host}:${port}`,
          evidence: truncate(reply, 500),
          description: "Memcached returned statistics without authentication, indicating open cache access.",
          remediation: "Bind Memcached to private interfaces, enable SASL where supported, and block external access.",
          references: ["https://www.memcached.org/blog/amplification-attacks/"],
          cwe: "CWE-306",
          metadata: { host, port, service: "memcached" },
          dedupeKey: `service-memcached-${host}-${port}`,
        });
      }
      continue;
    }
    if (!HTTP_SERVICE_PORTS.has(port) && !info?.http && !info?.https) continue;
    const schemes: Array<"http" | "https"> = info?.https || port === 443 || port === 8443 || port === 9443 || port === 6443 || port === 2376 ? ["https", "http"] : ["http", "https"];
    let response;
    for (const scheme of schemes) {
      const url = serviceUrl(host, port, scheme === "https");
      if (!ctx.guard.checkUrl(url).allowed) continue;
      try {
        response = await ctx.http.get(url, { maxBodyBytes: 400_000, maxRedirects: 2 });
        entry.scheme = scheme;
        entry.response = {
          status: response.status,
          title: extractTitle(response.body),
          server: response.headers.server ?? "",
          technologies: detectTechnologies(response).map((tech) => tech.name),
          body: response.body,
          url: response.finalUrl,
        };
        break;
      } catch {
        // try the next scheme
      }
    }
    if (!entry.response) continue;
    const admin = RISKY_ADMIN.test(`${entry.response.title} ${entry.response.technologies.join(" ")} ${entry.response.server}`);
    if (admin) {
      findings.push({
        title: `Administrative web interface exposed: ${entry.response.title || entry.response.technologies[0] || `port ${port}`}`,
        severity: port === 2375 ? "critical" : "medium",
        category: "network",
        confidence: "likely",
        tool: "argus-services",
        url: entry.response.url,
        target: `${host}:${port}`,
        evidence: `HTTP ${entry.response.status} - title: ${entry.response.title || "(none)"} - server: ${entry.response.server || "(none)"} - tech: ${entry.response.technologies.join(", ") || "(unknown)"}\n${truncate(entry.response.body.replace(/\s+/g, " "), 400)}`,
        description: "A management or infrastructure interface is reachable from the assessment network.",
        remediation: "Place management interfaces behind VPN or SSO, restrict source ranges, and enforce strong authentication.",
        references: [],
        cwe: "CWE-284",
        metadata: { host, port, scheme: entry.scheme },
        dedupeKey: `service-admin-${host}-${port}`,
      });
    }
    if (port === 2375) {
      try {
        const docker = await ctx.http.get(serviceUrl(host, port, false, "/version"), { maxBodyBytes: 200_000 });
        if (docker.status === 200 && /"ApiVersion"/i.test(docker.body)) {
          findings.push({
            title: "Unauthenticated Docker Engine API",
            severity: "critical",
            category: "network",
            confidence: "confirmed",
            tool: "argus-services",
            url: serviceUrl(host, port, false, "/version"),
            target: `${host}:${port}`,
            evidence: truncate(docker.body, 800),
            description: "The Docker Engine API accepted an unauthenticated /version request. Exposed Docker APIs commonly grant host-level control.",
            remediation: "Remove public exposure immediately, enable TLS client authentication, and restrict the socket/API to trusted administrators.",
            references: ["https://docs.docker.com/engine/security/protect-access/"],
            cwe: "CWE-306",
            metadata: { host, port },
            dedupeKey: `service-docker-${host}-${port}`,
          });
        }
      } catch {
        // ignore
      }
    }
    if (port === 2379) {
      try {
        const etcd = await ctx.http.get(serviceUrl(host, port, false, "/version"), { maxBodyBytes: 100_000 });
        if (etcd.status === 200 && /etcdserver/i.test(etcd.body)) {
          findings.push({
            title: "etcd API exposed",
            severity: "high",
            category: "network",
            confidence: "confirmed",
            tool: "argus-services",
            url: serviceUrl(host, port, false, "/version"),
            target: `${host}:${port}`,
            evidence: truncate(etcd.body, 500),
            description: "etcd is reachable and identifies itself publicly. etcd frequently stores cluster secrets.",
            remediation: "Restrict etcd to the control plane and require mutual TLS.",
            references: ["https://etcd.io/docs/latest/op-guide/security/"],
            cwe: "CWE-306",
            metadata: { host, port },
            dedupeKey: `service-etcd-${host}-${port}`,
          });
        }
      } catch {
        // ignore
      }
    }
    if (port === 8500) {
      try {
        const consul = await ctx.http.get(serviceUrl(host, port, false, "/v1/status/leader"), { maxBodyBytes: 100_000 });
        if (consul.status === 200 && consul.body.trim().length > 0) {
          findings.push({
            title: "Consul API exposed without authentication",
            severity: "high",
            category: "network",
            confidence: "confirmed",
            tool: "argus-services",
            url: serviceUrl(host, port, false, "/v1/status/leader"),
            target: `${host}:${port}`,
            evidence: truncate(consul.body, 500),
            description: "Consul status API is reachable and returned a cluster leader.",
            remediation: "Enable Consul ACLs, gossip encryption and restrict the HTTP API.",
            references: ["https://developer.hashicorp.com/consul/docs/security"],
            cwe: "CWE-306",
            metadata: { host, port },
            dedupeKey: `service-consul-${host}-${port}`,
          });
        }
      } catch {
        // ignore
      }
    }
    if (port === 9200) {
      try {
        const es = await ctx.http.get(serviceUrl(host, port, false, "/"), { maxBodyBytes: 300_000 });
        if (es.status === 200 && /"cluster_name"/i.test(es.body) && /"tagline"/i.test(es.body)) {
          findings.push({
            title: "Unauthenticated Elasticsearch API",
            severity: "high",
            category: "network",
            confidence: "confirmed",
            tool: "argus-services",
            url: serviceUrl(host, port, false, "/"),
            target: `${host}:${port}`,
            evidence: truncate(es.body, 800),
            description: "Elasticsearch returned cluster metadata without authentication.",
            remediation: "Enable Elasticsearch security features, require authentication and restrict network access.",
            references: ["https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"],
            cwe: "CWE-306",
            metadata: { host, port },
            dedupeKey: `service-elasticsearch-${host}-${port}`,
          });
        }
      } catch {
        // ignore
      }
    }
    if (port === 9090) {
      try {
        const prom = await ctx.http.get(serviceUrl(host, port, false, "/-/healthy"), { maxBodyBytes: 100_000 });
        if (prom.status === 200) {
          findings.push({
            title: "Prometheus server reachable",
            severity: "medium",
            category: "network",
            confidence: "confirmed",
            tool: "argus-services",
            url: serviceUrl(host, port, false, "/-/healthy"),
            target: `${host}:${port}`,
            evidence: `HTTP ${prom.status}: ${truncate(prom.body, 300)}`,
            description: "Prometheus health endpoint is publicly reachable and may expose operational metadata.",
            remediation: "Restrict Prometheus to monitoring networks and remove public exposure.",
            references: [],
            cwe: "CWE-284",
            metadata: { host, port },
            dedupeKey: `service-prometheus-${host}-${port}`,
          });
        }
      } catch {
        // ignore
      }
    }
    if (port === 8888) {
      try {
        const jupyter = await ctx.http.get(serviceUrl(host, port, false, "/api"), { maxBodyBytes: 100_000 });
        if (jupyter.status === 200 && /"version"/i.test(jupyter.body)) {
          findings.push({
            title: "Jupyter API reachable",
            severity: "high",
            category: "network",
            confidence: "confirmed",
            tool: "argus-services",
            url: serviceUrl(host, port, false, "/api"),
            target: `${host}:${port}`,
            evidence: truncate(jupyter.body, 500),
            description: "A Jupyter server API is reachable without an authentication challenge.",
            remediation: "Require a token/password, place Jupyter behind SSO, and never expose it directly.",
            references: ["https://jupyter-notebook.readthedocs.io/en/stable/security.html"],
            cwe: "CWE-306",
            metadata: { host, port },
            dedupeKey: `service-jupyter-${host}-${port}`,
          });
        }
      } catch {
        // ignore
      }
    }
    if (port === 10250) {
      try {
        const kubelet = await ctx.http.get(serviceUrl(host, port, true, "/healthz"), { maxBodyBytes: 100_000 });
        if (kubelet.status === 200) {
          findings.push({
            title: "Kubelet API reachable",
            severity: "high",
            category: "network",
            confidence: "confirmed",
            tool: "argus-services",
            url: serviceUrl(host, port, true, "/healthz"),
            target: `${host}:${port}`,
            evidence: `HTTP ${kubelet.status}: ${truncate(kubelet.body, 300)}`,
            description: "The Kubelet health endpoint is reachable. Kubelet APIs can expose pods and command execution when anonymous auth is enabled.",
            remediation: "Disable anonymous auth, enable webhook authorization, and never expose Kubelet to untrusted networks.",
            references: ["https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/"],
            cwe: "CWE-306",
            metadata: { host, port },
            dedupeKey: `service-kubelet-${host}-${port}`,
          });
        }
      } catch {
        // ignore
      }
    }
    if (port === 15672) {
      try {
        const rabbit = await ctx.http.get(serviceUrl(host, port, false, "/api/overview"), { maxBodyBytes: 200_000 });
        if (rabbit.status === 200 && /"rabbitmq_version"/i.test(rabbit.body)) {
          findings.push({
            title: "Unauthenticated RabbitMQ management API",
            severity: "high",
            category: "network",
            confidence: "confirmed",
            tool: "argus-services",
            url: serviceUrl(host, port, false, "/api/overview"),
            target: `${host}:${port}`,
            evidence: truncate(rabbit.body, 600),
            description: "RabbitMQ management API exposed without authentication.",
            remediation: "Restrict the management interface, enforce strong credentials and enable TLS.",
            references: ["https://www.rabbitmq.com/management.html#security"],
            cwe: "CWE-306",
            metadata: { host, port },
            dedupeKey: `service-rabbitmq-${host}-${port}`,
          });
        }
      } catch {
        // ignore
      }
    }
    if (port === 5000) {
      try {
        const registry = await ctx.http.get(serviceUrl(host, port, false, "/v2/_catalog"), { maxBodyBytes: 300_000 });
        if (registry.status === 200 && /"repositories"/i.test(registry.body)) {
          findings.push({
            title: "Unauthenticated Docker registry",
            severity: "high",
            category: "network",
            confidence: "confirmed",
            tool: "argus-services",
            url: serviceUrl(host, port, false, "/v2/_catalog"),
            target: `${host}:${port}`,
            evidence: truncate(registry.body, 600),
            description: "A Docker registry catalog is readable without authentication.",
            remediation: "Require authentication, enforce TLS and restrict registry access to trusted networks.",
            references: ["https://distribution.github.io/distribution/spec/auth/"],
            cwe: "CWE-306",
            metadata: { host, port },
            dedupeKey: `service-registry-${host}-${port}`,
          });
        }
      } catch {
        // ignore
      }
    }
  }
}

function guessService(port: number, banner: string): string {
  const known = COMMON_PORTS.find((entry) => entry.port === port);
  if (known) return known.service;
  if (/^SSH-/i.test(banner)) return "SSH";
  if (/^220.*(ftp|FTP)/i.test(banner)) return "FTP";
  if (/^220.*(smtp|SMTP|mail)/i.test(banner)) return "SMTP";
  if (/HTTP\/\d/i.test(banner)) return "HTTP";
  return "unknown";
}

function sanitizeBanner(value: string): string {
  return value.replace(/[^\x20-\x7E\r\n\t]/g, ".").trim().slice(0, 2000);
}

async function mapPool<T>(items: T[], concurrency: number, worker: (item: T) => Promise<void>, signal?: AbortSignal): Promise<void> {
  let index = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (index < items.length) {
      if (signal?.aborted) return;
      const current = items[index++];
      if (current === undefined) return;
      try {
        await worker(current);
      } catch {
        // per-item failure is already reflected by absence of a result
      }
    }
  });
  await Promise.all(runners);
}

function serviceUrl(host: string, port: number, secure: boolean, path = "/"): string {
  const formatted = host.includes(":") ? `[${host}]` : host;
  return `${secure ? "https" : "http"}://${formatted}:${port}${path}`;
}