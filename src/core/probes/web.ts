import type { FindingDraft, HttpResponse, ProbeContext } from "../types";
import type { PhaseTask } from "../types";
import { probeTlsVersions } from "../http";
import {
  API_DOC_PATHS,
  EXPOSURE_PATHS,
  GRAPHQL_PATHS,
} from "../signatures";
import {
  crtshSubdomains,
  decodeHtmlEntities,
  detectTechnologies,
  detectWaf,
  extractMetaGenerator,
  extractTitle,
  findTakeoverSignals,
  htmlSignature,
  parseCookies,
  registrableDomain,
  resolveDns,
  scanTextForSecrets,
} from "../recon-utils";
import { truncate } from "../util";
import { attackTasks, injectionPoints } from "./attacks";

const BASELINE_KEY = "web:baseline";
const BASELINE_PROMISE_KEY = "web:baseline:promise";

async function getBaseline(ctx: ProbeContext): Promise<HttpResponse> {
  const cached = ctx.state.get(BASELINE_KEY) as HttpResponse | undefined;
  if (cached) return cached;
  const pending = ctx.state.get(BASELINE_PROMISE_KEY) as Promise<HttpResponse> | undefined;
  if (pending) return pending;
  const url = ctx.target.url ?? ctx.target.baseUrl!;
  const promise = ctx.http.get(url, { maxBodyBytes: 2_000_000 }).then((response) => {
    ctx.state.set(BASELINE_KEY, response);
    return response;
  });
  ctx.state.set(BASELINE_PROMISE_KEY, promise);
  try {
    return await promise;
  } finally {
    ctx.state.delete(BASELINE_PROMISE_KEY);
  }
}

function originOf(ctx: ProbeContext): string {
  return ctx.target.baseUrl ?? new URL(ctx.target.url!).origin;
}

function resolveRelative(ctx: ProbeContext, path: string): string {
  return new URL(path, `${originOf(ctx)}/`).toString();
}

async function safeRequest(ctx: ProbeContext, url: string, init?: Parameters<ProbeContext["http"]["get"]>[1]): Promise<HttpResponse | undefined> {
  try {
    return await ctx.http.get(url, init);
  } catch (error) {
    if (error instanceof Error && error.name === "ScopeViolationError") {
      ctx.log("debug", `Skipped out-of-scope request: ${url}`, "scope");
      return undefined;
    }
    ctx.log("debug", `${url} failed: ${error instanceof Error ? error.message : String(error)}`, "http");
    return undefined;
  }
}

export const reconTasks: PhaseTask[] = [
  {
    id: "dns",
    label: "DNS, mail policy & takeover signals",
    phase: "recon",
    run: async (ctx) => {
      const host = ctx.target.host;
      if (!host) return;
      const findings: FindingDraft[] = [];
      const report = await resolveDns(host);
      ctx.state.set("dns", report);
      const records = {
        a: report.a,
        aaaa: report.aaaa,
        cname: report.cname,
        mx: report.mx,
        ns: report.ns,
        txt: report.txt,
        caa: report.caa,
      };
      ctx.log("info", `DNS: ${report.a.length} A, ${report.aaaa.length} AAAA, ${report.cname.length} CNAME, ${report.mx.length} MX`, "dns");
      findings.push({
        title: "DNS footprint",
        severity: "info",
        category: "recon",
        confidence: "confirmed",
        tool: "argus-dns",
        evidence: truncate(JSON.stringify(records, null, 2), 3000),
        description: "Public DNS records discovered for the target.",
        remediation: "Review exposed records and remove stale entries.",
        references: [],
        metadata: records,
        dedupeKey: "dns-footprint",
      });
      if (!host.includes(":") && !/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        const apex = registrableDomain(host);
        const spf = report.txt.find((value) => /^v=spf1\b/i.test(value));
        if (!spf) {
          findings.push({
            title: "SPF record missing",
            severity: "medium",
            category: "dns",
            confidence: "confirmed",
            tool: "argus-dns",
            evidence: `No v=spf1 TXT record found for ${apex}.`,
            description: "Without SPF, the domain can be spoofed in email messages.",
            remediation: `Publish a restrictive SPF record for ${apex} and enforce DMARC.`,
            references: ["https://owasp.org/www-community/controls/SPF"],
            dedupeKey: "dns-spf",
          });
        }
        const dmarc = report.dmarc.find((value) => /^v=DMARC1\b/i.test(value));
        if (!dmarc) {
          findings.push({
            title: "DMARC record missing",
            severity: "medium",
            category: "dns",
            confidence: "confirmed",
            tool: "argus-dns",
            evidence: `No v=DMARC1 TXT record found at _dmarc.${apex}.`,
            description: "Without DMARC, spoofed mail is not rejected and reporting is unavailable.",
            remediation: "Publish a DMARC policy starting at p=none, then move to quarantine or reject.",
            references: ["https://dmarc.org/overview/"],
            dedupeKey: "dns-dmarc",
          });
        }
        if (report.caa.length === 0) {
          findings.push({
            title: "CAA record missing",
            severity: "low",
            category: "dns",
            confidence: "confirmed",
            tool: "argus-dns",
            evidence: `No CAA records for ${apex}.`,
            description: "Any certificate authority may issue certificates for the domain.",
            remediation: "Publish CAA records restricting issuance to authorized CAs.",
            references: ["https://datatracker.ietf.org/doc/html/rfc8659"],
            dedupeKey: "dns-caa",
          });
        }
        if (report.wildcardDns) {
          findings.push({
            title: "Wildcard DNS resolution enabled",
            severity: "low",
            category: "dns",
            confidence: "confirmed",
            tool: "argus-dns",
            evidence: `Random label under ${apex} resolved successfully.`,
            description: "Wildcard DNS can hide dangling records and complicate host enumeration.",
            remediation: "Confirm the wildcard is intentional and monitor subdomains for takeover.",
            references: [],
            dedupeKey: "dns-wildcard",
          });
        }
      }
      if (report.cname.length > 0) {
        const baseline = ctx.state.get(BASELINE_KEY) as HttpResponse | undefined;
        const signals = findTakeoverSignals(baseline?.body ?? "", report.cname);
        for (const signal of signals) {
          findings.push({
            title: "Possible subdomain takeover",
            severity: signal.evidence ? "high" : "low",
            category: "takeover",
            confidence: signal.evidence ? "likely" : "possible",
            tool: "argus-dns",
            evidence: `CNAME ${report.cname.join(", ")} → ${signal.provider}. ${signal.evidence ? `Response marker: ${signal.evidence}` : "Provider fingerprint present."}`,
            description: "The hostname points at a third-party service that appears unclaimed or misconfigured.",
            remediation: "Claim or remove the dangling DNS record and audit other CNAME targets.",
            references: ["https://owasp.org/www-community/attacks/Subdomain_takeover"],
            cwe: "CWE-350",
            dedupeKey: `takeover-${signal.provider}`,
          });
        }
      }
      return findings;
    },
  },
  {
    id: "subdomains",
    label: "Passive subdomain discovery",
    phase: "recon",
    requiresActive: false,
    run: async (ctx) => {
      if (!ctx.options.allowExternal || !ctx.scope.allowExternal) {
        ctx.log("debug", "Passive subdomain discovery skipped: enable allowExternal", "intel");
        return;
      }
      const host = ctx.target.host;
      if (!host || /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return;
      const apex = registrableDomain(host);
      let names: string[];
      try {
        names = await crtshSubdomains(apex);
      } catch (error) {
        ctx.log("warn", `crt.sh lookup failed: ${error instanceof Error ? error.message : String(error)}`, "intel");
        return;
      }
      const inScope = names.filter((name) => ctx.guard.checkHost(name, 443).allowed);
      ctx.log("info", `crt.sh returned ${names.length} names; ${inScope.length} match the authorized scope`, "intel");
      if (inScope.length === 0) return;
      const evidence = inScope.slice(0, 40).map((name) => `- ${name}`).join("\n");
      return [
        {
          title: "Passive subdomain inventory",
          severity: "info",
          category: "recon",
          confidence: "confirmed",
          tool: "argus-intel",
          evidence: `${inScope.length} in-scope names discovered via certificate transparency.\n${evidence}`,
          description: "Subdomains discovered from public certificate transparency logs.",
          remediation: "Remove stale names and include subdomain takeover monitoring.",
          references: ["https://crt.sh/"],
          metadata: { count: inScope.length, names: inScope.slice(0, 40) },
          dedupeKey: "subdomain-inventory",
        },
      ];
    },
  },
];

export const webTasks: PhaseTask[] = [
  {
    id: "web-baseline",
    label: "HTTP baseline & technology fingerprint",
    phase: "surface",
    run: async (ctx) => {
      const response = await getBaseline(ctx);
      const technologies = detectTechnologies(response);
      const wafs = detectWaf(response);
      const title = extractTitle(response.body);
      const generator = extractMetaGenerator(response.body);
      ctx.state.set("web:tech", technologies);
      ctx.state.set("web:waf", wafs);
      ctx.state.set("web:title", title);
      ctx.log(
        "info",
        `HTTP ${response.status} in ${response.elapsedMs}ms :: ${title || "(no title)"}${technologies.length ? ` :: ${technologies.map((tech) => tech.name).join(", ")}` : ""}${wafs.length ? ` :: WAF ${wafs.join(", ")}` : ""}`,
        "web",
      );
      const findings: FindingDraft[] = [];
      if (technologies.length > 0) {
        findings.push({
          title: "Technology fingerprint",
          severity: "info",
          category: "recon",
          confidence: "confirmed",
          tool: "argus-web",
          url: response.finalUrl,
          evidence: technologies.map((tech) => `${tech.name}${tech.version ? ` ${tech.version}` : ""} (${tech.category})`).join("\n"),
          description: "Frameworks and platforms inferred from response headers and content.",
          remediation: "Suppress unnecessary version banners and keep components patched.",
          references: [],
          metadata: { technologies, waf: wafs, status: response.status, title },
          dedupeKey: "web-tech",
        });
      }
      if (wafs.length > 0) {
        findings.push({
          title: "Web application firewall detected",
          severity: "info",
          category: "recon",
          confidence: "likely",
          tool: "argus-web",
          url: response.finalUrl,
          evidence: wafs.join(", "),
          description: "A WAF or reverse proxy may filter some probes; absence of a finding is not proof of safety.",
          remediation: "Do not rely on the WAF as the only control; test origin exposure and bypass paths.",
          references: [],
          dedupeKey: "web-waf",
        });
      }
      if (ctx.target.scheme === "http") {
        if (response.finalUrl.startsWith("https://")) {
          findings.push({
            title: "HTTP redirects to HTTPS",
            severity: "info",
            category: "transport",
            confidence: "confirmed",
            tool: "argus-web",
            url: response.finalUrl,
            evidence: `http:// target redirected to ${response.finalUrl}.`,
            description: "Cleartext HTTP is redirected to HTTPS.",
            remediation: "Add HSTS so future requests never traverse HTTP.",
            references: [],
            cwe: "CWE-319",
            dedupeKey: "web-https-redirect",
          });
        } else {
          findings.push({
            title: "Site is served over plain HTTP",
            severity: "high",
            category: "transport",
            confidence: "confirmed",
            tool: "argus-web",
            url: response.finalUrl,
            evidence: `Target scheme is http:// and the final URL is ${response.finalUrl}.`,
            description: "Traffic can be intercepted, modified or downgraded in transit.",
            remediation: "Redirect all HTTP traffic to HTTPS and enable HSTS.",
            references: ["https://owasp.org/www-community/controls/Transport_Layer_Protection_Cheat_Sheet"],
            cwe: "CWE-319",
            dedupeKey: "web-http",
          });
        }
      }
      if (response.redirects.length > 0) {
        findings.push({
          title: "HTTP redirect chain",
          severity: "info",
          category: "recon",
          confidence: "confirmed",
          tool: "argus-web",
          url: response.finalUrl,
          evidence: [...response.redirects.slice(0, 8), response.finalUrl].join("\n→ "),
          description: "Redirect targets observed while following the landing page.",
          remediation: "Keep redirect targets within trusted origins.",
          references: [],
          dedupeKey: "web-redirects",
        });
      }
      if (generator) {
        findings.push({
          title: "Generator metadata disclosed",
          severity: "low",
          category: "misconfiguration",
          confidence: "confirmed",
          tool: "argus-web",
          url: response.finalUrl,
          evidence: `meta generator: ${generator}`,
          description: "CMS or framework metadata helps attackers choose version-specific attacks.",
          remediation: "Remove generator meta tags where possible.",
          references: [],
          dedupeKey: "web-generator",
        });
      }
      const server = response.headers.server;
      if (server && /\d+\.\d+/.test(server)) {
        findings.push({
          title: "Server version disclosed",
          severity: "low",
          category: "misconfiguration",
          confidence: "confirmed",
          tool: "argus-web",
          url: response.finalUrl,
          evidence: `Server: ${server}`,
          description: "Exact server versions reduce attacker reconnaissance effort.",
          remediation: "Suppress or normalize server version banners.",
          references: ["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
          cwe: "CWE-200",
          dedupeKey: "web-server-version",
        });
      }
      const poweredBy = response.headers["x-powered-by"];
      if (poweredBy) {
        findings.push({
          title: "X-Powered-By header disclosed",
          severity: "low",
          category: "misconfiguration",
          confidence: "confirmed",
          tool: "argus-web",
          url: response.finalUrl,
          evidence: `X-Powered-By: ${poweredBy}`,
          description: "Runtime and framework metadata is unnecessarily disclosed.",
          remediation: "Disable X-Powered-By in the application server configuration.",
          references: [],
          cwe: "CWE-200",
          dedupeKey: "web-powered-by",
        });
      }
      const download = response.headers["content-disposition"];
      if (download && /filename/i.test(download)) {
        ctx.log("debug", `Content-Disposition: ${download}`, "web");
      }
      ctx.state.set("web:baseline-findings", findings);
      return findings;
    },
  },
  {
    id: "web-headers",
    label: "Security headers & transport policy",
    phase: "audit",
    run: async (ctx) => {
      const response = await getBaseline(ctx);
      const isHttps = response.finalUrl.startsWith("https://");
      const headers = response.headers;
      const csp = headers["content-security-policy"] ?? "";
      const findings: FindingDraft[] = [];
      if (isHttps && !headers["strict-transport-security"]) {
        findings.push({
          title: "HSTS header missing",
          severity: "medium",
          category: "misconfiguration",
          confidence: "confirmed",
          tool: "argus-headers",
          url: response.finalUrl,
          evidence: "No Strict-Transport-Security response header.",
          description: "Browsers may accept downgraded HTTP connections on subsequent visits.",
          remediation: "Send Strict-Transport-Security with a long max-age after confirming all subdomains support HTTPS.",
          references: ["https://owasp.org/www-project-secure-headers/#strict-transport-security"],
          cwe: "CWE-319",
          dedupeKey: "headers-hsts",
        });
      }
      if (!csp) {
        findings.push({
          title: "Content-Security-Policy missing",
          severity: "medium",
          category: "misconfiguration",
          confidence: "confirmed",
          tool: "argus-headers",
          url: response.finalUrl,
          evidence: "No Content-Security-Policy header or meta policy.",
          description: "Without CSP, injected scripts have fewer barriers to execution.",
          remediation: "Deploy a restrictive CSP with nonces or hashes and no unsafe-inline for scripts.",
          references: ["https://owasp.org/www-project-secure-headers/#content-security-policy"],
          cwe: "CWE-693",
          dedupeKey: "headers-csp",
        });
      } else if (/script-src[^;]*unsafe-inline/i.test(csp)) {
        findings.push({
          title: "CSP allows inline scripts",
          severity: "low",
          category: "misconfiguration",
          confidence: "confirmed",
          tool: "argus-headers",
          url: response.finalUrl,
          evidence: truncate(csp, 600),
          description: "unsafe-inline weakens CSP protection against XSS.",
          remediation: "Replace unsafe-inline with nonces or hashes.",
          references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
          dedupeKey: "headers-csp-inline",
        });
      }
      if (!headers["x-frame-options"] && !/frame-ancestors/i.test(csp)) {
        findings.push({
          title: "Clickjacking protection missing",
          severity: "low",
          category: "misconfiguration",
          confidence: "confirmed",
          tool: "argus-headers",
          url: response.finalUrl,
          evidence: "No X-Frame-Options header and no CSP frame-ancestors directive.",
          description: "The site can be framed by attacker-controlled pages.",
          remediation: "Set X-Frame-Options: DENY or SAMEORIGIN, or CSP frame-ancestors.",
          references: ["https://owasp.org/www-community/attacks/Clickjacking"],
          cwe: "CWE-1021",
          dedupeKey: "headers-frame",
        });
      }
      if (!headers["x-content-type-options"]) {
        findings.push({
          title: "X-Content-Type-Options missing",
          severity: "low",
          category: "misconfiguration",
          confidence: "confirmed",
          tool: "argus-headers",
          url: response.finalUrl,
          evidence: "No X-Content-Type-Options: nosniff header.",
          description: "Browsers may MIME-sniff responses and execute content unexpectedly.",
          remediation: "Send X-Content-Type-Options: nosniff.",
          references: ["https://owasp.org/www-project-secure-headers/#x-content-type-options"],
          dedupeKey: "headers-nosniff",
        });
      }
      if (!headers["referrer-policy"]) {
        findings.push({
          title: "Referrer-Policy missing",
          severity: "low",
          category: "misconfiguration",
          confidence: "confirmed",
          tool: "argus-headers",
          url: response.finalUrl,
          evidence: "No Referrer-Policy header.",
          description: "Sensitive URL paths can leak to third parties through the Referer header.",
          remediation: "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
          references: ["https://owasp.org/www-project-secure-headers/#referrer-policy"],
          dedupeKey: "headers-referrer",
        });
      }
      if (!headers["permissions-policy"]) {
        findings.push({
          title: "Permissions-Policy missing",
          severity: "low",
          category: "misconfiguration",
          confidence: "confirmed",
          tool: "argus-headers",
          url: response.finalUrl,
          evidence: "No Permissions-Policy header.",
          description: "Powerful browser features remain enabled for the origin and embedded content.",
          remediation: "Define a Permissions-Policy that disables unused features.",
          references: ["https://owasp.org/www-project-secure-headers/#permissions-policy"],
          dedupeKey: "headers-permissions",
        });
      }
      if (/^public,\s*max-age/i.test(headers["cache-control"] ?? "") && /login|account|admin|dashboard/i.test(response.finalUrl)) {
        findings.push({
          title: "Sensitive page marked publicly cacheable",
          severity: "low",
          category: "misconfiguration",
          confidence: "possible",
          tool: "argus-headers",
          url: response.finalUrl,
          evidence: `Cache-Control: ${headers["cache-control"]}`,
          description: "Shared caches may retain sensitive pages.",
          remediation: "Use Cache-Control: no-store for authenticated or sensitive responses.",
          references: [],
          dedupeKey: "headers-cache",
        });
      }
      return findings;
    },
  },
  {
    id: "web-cookies",
    label: "Cookie flags & session hygiene",
    phase: "audit",
    run: async (ctx) => {
      const response = await getBaseline(ctx);
      const cookies = parseCookies(response);
      if (cookies.length === 0) return;
      ctx.state.set("web:cookies", cookies);
      const isHttps = response.finalUrl.startsWith("https://");
      const findings: FindingDraft[] = [];
      for (const cookie of cookies) {
        const sensitive = /session|sess|auth|token|jwt|sid|remember/i.test(cookie.name);
        if (!cookie.secure) {
          findings.push({
            title: `Cookie without Secure flag: ${cookie.name}`,
            severity: isHttps ? (sensitive ? "medium" : "low") : "low",
            category: "session",
            confidence: "confirmed",
            tool: "argus-cookies",
            url: response.finalUrl,
            evidence: `Set-Cookie: ${cookie.name}=<redacted>; attributes: ${cookie.flags.join("; ") || "(none)"}`,
            description: "The cookie can be transmitted over an unencrypted connection.",
            remediation: "Add the Secure attribute to all session and authentication cookies.",
            references: ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            cwe: "CWE-614",
            dedupeKey: `cookie-secure-${cookie.name}`,
          });
        }
        if (!cookie.httpOnly) {
          findings.push({
            title: `Cookie without HttpOnly flag: ${cookie.name}`,
            severity: sensitive ? "medium" : "low",
            category: "session",
            confidence: "confirmed",
            tool: "argus-cookies",
            url: response.finalUrl,
            evidence: `Set-Cookie: ${cookie.name}=<redacted>; attributes: ${cookie.flags.join("; ") || "(none)"}`,
            description: "Client-side scripts can read this cookie, increasing XSS impact.",
            remediation: "Add HttpOnly to session and authentication cookies.",
            references: ["https://owasp.org/www-community/HttpOnly"],
            cwe: "CWE-1004",
            dedupeKey: `cookie-httponly-${cookie.name}`,
          });
        }
        if (!cookie.sameSite) {
          findings.push({
            title: `Cookie without SameSite attribute: ${cookie.name}`,
            severity: sensitive ? "low" : "info",
            category: "session",
            confidence: "confirmed",
            tool: "argus-cookies",
            url: response.finalUrl,
            evidence: `Set-Cookie: ${cookie.name}=<redacted>; attributes: ${cookie.flags.join("; ") || "(none)"}`,
            description: "Cross-site requests may include this cookie, weakening CSRF defenses.",
            remediation: "Set SameSite=Lax or Strict, and use CSRF tokens for state-changing actions.",
            references: ["https://owasp.org/www-community/SameSite"],
            cwe: "CWE-1275",
            dedupeKey: `cookie-samesite-${cookie.name}`,
          });
        }
      }
      return findings;
    },
  },
  {
    id: "web-content",
    label: "Page content & client-side hygiene",
    phase: "audit",
    run: async (ctx) => {
      const response = await getBaseline(ctx);
      const findings: FindingDraft[] = [];
      const isHttps = response.finalUrl.startsWith("https://");
      const title = extractTitle(response.body);
      if (/^index of \//i.test(title)) {
        findings.push({
          title: "Directory listing enabled",
          severity: "medium",
          category: "exposure",
          confidence: "confirmed",
          tool: "argus-web",
          url: response.finalUrl,
          evidence: `Page title: ${title}`,
          description: "The web server lists directory contents.",
          remediation: "Disable automatic directory indexes.",
          references: ["https://owasp.org/www-community/attacks/Directory_traversal"],
          cwe: "CWE-548",
          dedupeKey: "web-directory-listing",
        });
      }
      const comments = response.body.match(/<!--([\s\S]{4,500}?)-->/g) ?? [];
      const sensitiveComments = comments
        .map((comment) => decodeHtmlEntities(comment.replace(/<!--|-->/g, "").trim()))
        .filter((comment) => /(password|passwd|secret|api[_-]?key|token|todo|fixme|internal|staging|debug|credentials|bearer)/i.test(comment));
      if (sensitiveComments.length > 0) {
        findings.push({
          title: "Sensitive HTML comments",
          severity: "low",
          category: "exposure",
          confidence: "possible",
          tool: "argus-web",
          url: response.finalUrl,
          evidence: sensitiveComments.slice(0, 5).map((comment) => truncate(comment, 300)).join("\n---\n"),
          description: "Developer comments may reveal internal systems or credentials.",
          remediation: "Strip comments during the build and review templates.",
          references: [],
          cwe: "CWE-200",
          dedupeKey: "web-comments",
        });
      }
      if (isHttps) {
        const mixed = [...response.body.matchAll(/(?:src|href)=["'](http:\/\/[^"']+)["']/gi)]
          .map((match) => match[1]!)
          .filter((url) => !url.startsWith("http://localhost") && !url.startsWith("http://127.0.0.1"));
        if (mixed.length > 0) {
          findings.push({
            title: "Mixed content references",
            severity: "low",
            category: "transport",
            confidence: "likely",
            tool: "argus-web",
            url: response.finalUrl,
            evidence: mixed.slice(0, 10).join("\n"),
            description: "HTTPS pages load resources over HTTP, allowing tampering or blocking.",
            remediation: "Load all resources over HTTPS and enable upgrade-insecure-requests.",
            references: [],
            cwe: "CWE-319",
            dedupeKey: "web-mixed-content",
          });
        }
        const insecureForms = [...response.body.matchAll(/<form[^>]+action=["'](http:\/\/[^"']+)["']/gi)].map((match) => match[1]!);
        if (insecureForms.length > 0) {
          findings.push({
            title: "Form submits over HTTP",
            severity: "high",
            category: "transport",
            confidence: "confirmed",
            tool: "argus-web",
            url: response.finalUrl,
            evidence: insecureForms.slice(0, 10).join("\n"),
            description: "Credentials or sensitive data submitted by the form can be intercepted.",
            remediation: "Change form actions to HTTPS.",
            references: [],
            cwe: "CWE-319",
            dedupeKey: "web-insecure-form",
          });
        }
      }
      if (/sourceMappingURL=/i.test(response.body)) {
        findings.push({
          title: "JavaScript source maps referenced",
          severity: "info",
          category: "exposure",
          confidence: "possible",
          tool: "argus-web",
          url: response.finalUrl,
          evidence: truncate((/sourceMappingURL=([^\s*]+)/i.exec(response.body) ?? [])[0] ?? "", 300),
          description: "Source maps can disclose original source code when publicly served.",
          remediation: "Do not deploy source maps to production, or restrict access.",
          references: [],
          dedupeKey: "web-sourcemaps",
        });
      }
      const secretHits = scanTextForSecrets(response.body, { limit: 10 });
      if (secretHits.length > 0) {
        for (const hit of secretHits.slice(0, 5)) {
          findings.push({
            title: `Potential secret in page content: ${hit.name}`,
            severity: hit.severity,
            category: "secrets",
            confidence: hit.confidence,
            tool: "argus-secrets",
            url: response.finalUrl,
            evidence: `line ${hit.line}: ${hit.context}\nmatch: ${hit.masked}`,
            description: hit.description,
            remediation: "Remove the secret from client-visible content and rotate it immediately.",
            references: ["https://cwe.mitre.org/data/definitions/798.html"],
            cwe: "CWE-798",
            dedupeKey: `web-secret-${hit.id}-${hit.masked}`,
          });
        }
      }
      return findings;
    },
  },
  {
    id: "web-tls",
    label: "TLS configuration & certificate",
    phase: "audit",
    run: async (ctx) => {
      if (!ctx.target.host) return;
      let response = ctx.state.get(BASELINE_KEY) as HttpResponse | undefined;
      if (!response || !response.finalUrl.startsWith("https://")) {
        const port = ctx.target.port === 443 || !ctx.target.port ? 443 : ctx.target.port;
        const url = `https://${ctx.target.host.includes(":") ? `[${ctx.target.host}]` : ctx.target.host}${port === 443 ? "" : `:${port}`}/`;
        if (!ctx.guard.checkUrl(url).allowed) return;
        response = await safeRequest(ctx, url, { maxBodyBytes: 100_000 });
      }
      const tls = response?.tls;
      if (!tls) {
        ctx.log("warn", "TLS certificate details unavailable", "tls");
        return;
      }
      const findings: FindingDraft[] = [];
      const days = tls.daysRemaining;
      if (days < 0) {
        findings.push({
          title: "TLS certificate expired",
          severity: "high",
          category: "tls",
          confidence: "confirmed",
          tool: "argus-tls",
          url: response?.finalUrl,
          evidence: `Certificate expired ${Math.abs(days)} day(s) ago (${tls.validTo}).`,
          description: "Clients will reject or warn on the expired certificate.",
          remediation: "Renew and deploy the certificate, and monitor expiry automatically.",
          references: [],
          cwe: "CWE-298",
          dedupeKey: "tls-expired",
        });
      } else if (days <= 30) {
        findings.push({
          title: "TLS certificate expires soon",
          severity: "medium",
          category: "tls",
          confidence: "confirmed",
          tool: "argus-tls",
          url: response?.finalUrl,
          evidence: `Certificate expires in ${days} day(s) (${tls.validTo}).`,
          description: "Certificate expiry will cause outages or client warnings.",
          remediation: "Renew the certificate and automate renewal monitoring.",
          references: [],
          dedupeKey: "tls-expiry",
        });
      }
      if (tls.selfSigned) {
        findings.push({
          title: "Self-signed TLS certificate",
          severity: "medium",
          category: "tls",
          confidence: "confirmed",
          tool: "argus-tls",
          url: response?.finalUrl,
          evidence: `${tls.subject} issued by ${tls.issuer}`,
          description: "Clients cannot validate the certificate through a trusted chain.",
          remediation: "Use a publicly trusted or properly managed internal CA certificate.",
          references: [],
          cwe: "CWE-295",
          dedupeKey: "tls-self-signed",
        });
      }
      if (!tls.hostnameMatch) {
        findings.push({
          title: "TLS certificate hostname mismatch",
          severity: "high",
          category: "tls",
          confidence: "confirmed",
          tool: "argus-tls",
          url: response?.finalUrl,
          evidence: `Certificate names: ${tls.san.slice(0, 12).join(", ") || tls.subject}`,
          description: "The certificate is not valid for the requested hostname.",
          remediation: "Reissue the certificate with the correct SAN entries.",
          references: [],
          cwe: "CWE-297",
          dedupeKey: "tls-hostname",
        });
      }
      if (/TLSv1(?:\.0|\.1)?$/.test(tls.protocol) || tls.protocol === "TLSv1") {
        findings.push({
          title: "Deprecated TLS protocol negotiated",
          severity: "medium",
          category: "tls",
          confidence: "confirmed",
          tool: "argus-tls",
          url: response?.finalUrl,
          evidence: `${tls.protocol} with ${tls.cipher}`,
          description: "TLS 1.0/1.1 are deprecated and vulnerable to known attacks.",
          remediation: "Require TLS 1.2 or higher and disable legacy protocols.",
          references: [],
          cwe: "CWE-327",
          dedupeKey: "tls-version",
        });
      }
      if (/RC4|3DES|DES|EXPORT|MD5|NULL/i.test(tls.cipher)) {
        findings.push({
          title: "Weak TLS cipher negotiated",
          severity: "high",
          category: "tls",
          confidence: "confirmed",
          tool: "argus-tls",
          url: response?.finalUrl,
          evidence: `${tls.protocol} with ${tls.cipher}`,
          description: "The negotiated cipher suite is cryptographically weak.",
          remediation: "Disable legacy ciphers and prefer AEAD suites.",
          references: [],
          cwe: "CWE-327",
          dedupeKey: "tls-cipher",
        });
      }
      if (ctx.target.host && !ctx.target.host.includes(":")) {
        const versions = await probeTlsVersions(ctx.target.host, ctx.target.port ?? 443, 2500);
        const legacy = versions.filter((version) => version.supported && (version.version === "TLSv1" || version.version === "TLSv1.1"));
        if (legacy.length > 0) {
          findings.push({
            title: "Legacy TLS versions enabled",
            severity: "medium",
            category: "tls",
            confidence: "confirmed",
            tool: "argus-tls",
            url: response?.finalUrl,
            evidence: legacy.map((version) => `${version.version} accepted (${version.cipher ?? "cipher unknown"})`).join("\n"),
            description: "The server accepts TLS 1.0 or TLS 1.1 handshakes.",
            remediation: "Disable TLS 1.0/1.1 at the load balancer and origin.",
            references: [],
            cwe: "CWE-327",
            dedupeKey: "tls-legacy-versions",
          });
        }
      }
      findings.push({
        title: "TLS certificate details",
        severity: "info",
        category: "tls",
        confidence: "confirmed",
        tool: "argus-tls",
        url: response?.finalUrl,
        evidence: `${tls.protocol} / ${tls.cipher}\nSubject: ${tls.subject}\nIssuer: ${tls.issuer}\nValid: ${tls.validFrom} → ${tls.validTo}\nSAN: ${tls.san.slice(0, 20).join(", ")}`,
        description: "Observed certificate and protocol metadata.",
        remediation: "Review certificate lifecycle and protocol policy.",
        references: [],
        metadata: { tls },
        dedupeKey: "tls-details",
      });
      return findings;
    },
  },
  {
    id: "well-known",
    label: "robots.txt, sitemap & security.txt",
    phase: "surface",
    requiresActive: false,
    run: async (ctx) => {
      const findings: FindingDraft[] = [];
      const robotsUrl = resolveRelative(ctx, "/robots.txt");
      const robots = await safeRequest(ctx, robotsUrl, { maxBodyBytes: 200_000 });
      if (robots && robots.status === 200 && !/<html/i.test(robots.body.slice(0, 500))) {
        const disallows = robots.body
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => /^disallow:/i.test(line))
          .map((line) => line.replace(/^disallow:\s*/i, ""))
          .filter((path) => path && path !== "/");
        const interesting = disallows.filter((path) => /admin|backup|config|private|internal|secret|debug|api|dashboard|upload|log|test|staging|\.git/i.test(path));
        if (interesting.length > 0) {
          findings.push({
            title: "robots.txt discloses sensitive paths",
            severity: "low",
            category: "exposure",
            confidence: "confirmed",
            tool: "argus-web",
            url: robotsUrl,
            evidence: interesting.slice(0, 30).join("\n"),
            description: "robots.txt advertises paths that may be worth reviewing.",
            remediation: "Do not rely on robots.txt for access control; remove sensitive entries.",
            references: [],
            cwe: "CWE-200",
            dedupeKey: "well-known-robots",
          });
        } else {
          ctx.log("info", `robots.txt parsed (${disallows.length} disallow entries)`, "web");
        }
      }
      const sitemapUrl = resolveRelative(ctx, "/sitemap.xml");
      const sitemap = await safeRequest(ctx, sitemapUrl, { maxBodyBytes: 2_000_000 });
      if (sitemap && sitemap.status === 200 && /<urlset|<sitemapindex/i.test(sitemap.body)) {
        const urls = [...sitemap.body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map((match) => match[1]!.trim());
        findings.push({
          title: "Sitemap published",
          severity: "info",
          category: "recon",
          confidence: "confirmed",
          tool: "argus-web",
          url: sitemapUrl,
          evidence: `${urls.length} URLs; sample:\n${urls.slice(0, 20).join("\n")}`,
          description: "Sitemap exposes a structured list of public URLs.",
          remediation: "Ensure sitemap excludes internal or sensitive endpoints.",
          references: [],
          metadata: { urlCount: urls.length, urls: urls.slice(0, 100) },
          dedupeKey: "well-known-sitemap",
        });
      }
      const securityUrl = resolveRelative(ctx, "/.well-known/security.txt");
      const security = await safeRequest(ctx, securityUrl, { maxBodyBytes: 200_000 });
      if (security && security.status === 200 && /contact\s*:/i.test(security.body)) {
        findings.push({
          title: "Security contact file present",
          severity: "info",
          category: "recon",
          confidence: "confirmed",
          tool: "argus-web",
          url: securityUrl,
          evidence: truncate(security.body, 1000),
          description: "security.txt publishes a vulnerability disclosure contact.",
          remediation: "Keep the contact and expiry fields current.",
          references: ["https://www.rfc-editor.org/rfc/rfc9116"],
          dedupeKey: "security-txt",
        });
      }
      return findings;
    },
  },
  {
    id: "cors",
    label: "CORS origin reflection",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const response = await getBaseline(ctx);
      const url = response.finalUrl;
      const canary = `https://argus-canary-${Math.random().toString(36).slice(2, 8)}.invalid`;
      const findings: FindingDraft[] = [];
      let optionsResponse: HttpResponse | undefined;
      try {
        optionsResponse = await ctx.http.options(url, {
          headers: {
            origin: canary,
            "access-control-request-method": "GET",
            "access-control-request-headers": "authorization,content-type",
          },
          maxBodyBytes: 50_000,
        });
      } catch (error) {
        ctx.log("debug", `CORS preflight failed: ${error instanceof Error ? error.message : String(error)}`, "cors");
      }
      let getResponse: HttpResponse | undefined;
      try {
        getResponse = await ctx.http.get(url, { headers: { origin: "null" }, maxBodyBytes: 100_000 });
      } catch {
        // ignore
      }
      const samples = [optionsResponse, getResponse].filter(Boolean) as HttpResponse[];
      const reflected = samples.filter((sample) => sample.headers["access-control-allow-origin"] === canary || sample.headers["access-control-allow-origin"] === "null");
      const wildcard = samples.filter((sample) => sample.headers["access-control-allow-origin"] === "*");
      const credentials = samples.some((sample) => sample.headers["access-control-allow-credentials"] === "true");
      if (reflected.length > 0) {
        findings.push({
          title: credentials ? "CORS reflects arbitrary origins with credentials" : "CORS reflects arbitrary origins",
          severity: credentials ? "high" : "medium",
          category: "cors",
          confidence: "confirmed",
          tool: "argus-cors",
          url,
          evidence: reflected
            .map(
              (sample) =>
                `${sample.url} → ACAO: ${sample.headers["access-control-allow-origin"]}${sample.headers["access-control-allow-credentials"] ? " / ACAC: true" : ""}`,
            )
            .join("\n"),
          description: credentials
            ? "Any website can make credentialed cross-origin requests and read responses, enabling account data theft."
            : "Any website can read cross-origin responses from this endpoint.",
          remediation: "Validate the Origin against a strict allowlist and never combine reflected origins with credentials.",
          references: ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
          cwe: "CWE-942",
          dedupeKey: "cors-reflected",
        });
      } else if (wildcard.length > 0 && credentials) {
        findings.push({
          title: "CORS wildcard with credentials",
          severity: "high",
          category: "cors",
          confidence: "confirmed",
          tool: "argus-cors",
          url,
          evidence: samples.map((sample) => `ACAO: ${sample.headers["access-control-allow-origin"]} / ACAC: ${sample.headers["access-control-allow-credentials"] ?? "false"}`).join("\n"),
          description: "Wildcard CORS is combined with credentialed access, which browsers may handle unsafely and indicates a permissive policy.",
          remediation: "Use an explicit origin allowlist for credentialed endpoints.",
          references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
          cwe: "CWE-942",
          dedupeKey: "cors-wildcard-creds",
        });
      } else if (wildcard.length > 0) {
        findings.push({
          title: "CORS wildcard policy",
          severity: "low",
          category: "cors",
          confidence: "confirmed",
          tool: "argus-cors",
          url,
          evidence: samples.map((sample) => `${sample.url} → ACAO: *`).join("\n"),
          description: "Any origin can read unauthenticated responses from this endpoint.",
          remediation: "Restrict ACAO to trusted origins if responses contain sensitive data.",
          references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
          cwe: "CWE-942",
          dedupeKey: "cors-wildcard",
        });
      }
      return findings;
    },
  },
  {
    id: "methods",
    label: "HTTP methods & TRACE",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const response = await getBaseline(ctx);
      const findings: FindingDraft[] = [];
      let optionsResponse: HttpResponse | undefined;
      try {
        optionsResponse = await ctx.http.options(response.finalUrl, { maxBodyBytes: 50_000 });
      } catch {
        return;
      }
      const allow = optionsResponse.headers.allow ?? optionsResponse.headers["access-control-allow-methods"] ?? "";
      const methods = allow
        .split(",")
        .map((method) => method.trim().toUpperCase())
        .filter(Boolean);
      if (methods.length > 0) {
        const dangerous = methods.filter((method) => ["PUT", "DELETE", "PATCH", "CONNECT"].includes(method));
        if (dangerous.length > 0) {
          findings.push({
            title: "Potentially dangerous HTTP methods enabled",
            severity: "medium",
            category: "misconfiguration",
            confidence: "possible",
            tool: "argus-methods",
            url: response.finalUrl,
            evidence: `Allow: ${allow}`,
            description: "Write-capable methods are advertised by the endpoint.",
            remediation: "Disable methods that are not required and enforce authorization server-side.",
            references: [],
            cwe: "CWE-650",
            dedupeKey: "methods-dangerous",
          });
        }
        if (methods.includes("TRACE")) {
          try {
            const trace = await ctx.http.request(response.finalUrl, { method: "TRACE", maxBodyBytes: 100_000 });
            if (trace.status >= 200 && trace.status < 300 && trace.body.includes("TRACE")) {
              findings.push({
                title: "HTTP TRACE method enabled",
                severity: "medium",
                category: "misconfiguration",
                confidence: "confirmed",
                tool: "argus-methods",
                url: response.finalUrl,
                evidence: `TRACE ${response.finalUrl} → ${trace.status}\n${truncate(trace.body, 500)}`,
                description: "TRACE can echo request headers and enable cross-site tracing attacks.",
                remediation: "Disable the TRACE method at the web server.",
                references: ["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                cwe: "CWE-693",
                dedupeKey: "methods-trace",
              });
            }
          } catch {
            // ignore
          }
        }
        findings.push({
          title: "HTTP methods advertised",
          severity: "info",
          category: "recon",
          confidence: "confirmed",
          tool: "argus-methods",
          url: response.finalUrl,
          evidence: `Allow: ${allow}`,
          description: "Methods advertised by the target.",
          remediation: "Keep the method surface minimal.",
          references: [],
          dedupeKey: "methods-list",
        });
      }
      return findings;
    },
  },
  {
    id: "exposures",
    label: "Sensitive file & metadata exposure",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const findings: FindingDraft[] = [];
      const origin = originOf(ctx);
      const randomPath = `/argus-${Math.random().toString(36).slice(2, 10)}.txt`;
      const notFound = await safeRequest(ctx, resolveRelative(ctx, randomPath), { maxBodyBytes: 200_000 });
      const notFoundSig = notFound ? htmlSignature(notFound.body) : "";
      const notFoundLength = notFound?.bodyBytes ?? 0;
      const notFoundStatus = notFound?.status ?? 404;
      let checked = 0;
      let blocked = 0;
      for (const exposure of EXPOSURE_PATHS) {
        const url = `${origin}${exposure.path}`;
        if (!ctx.guard.checkUrl(url).allowed) {
          blocked += 1;
          continue;
        }
        const response = await safeRequest(ctx, url, { maxBodyBytes: 1_500_000 });
        if (!response) continue;
        checked += 1;
        if (response.status !== 200 && response.status !== 206) continue;
        const sig = htmlSignature(response.body);
        const soft404 =
          response.status === notFoundStatus ||
          (notFoundSig && sig.length > 0 && sig === notFoundSig) ||
          (notFoundLength > 0 && Math.abs(response.bodyBytes - notFoundLength) / Math.max(1, notFoundLength) < 0.02 && exposure.patterns?.every((pattern) => !pattern.test(response.body)));
        if (soft404) continue;
        const matched = exposure.patterns?.find((pattern) => pattern.test(response.body));
        const contentTypeOk = exposure.contentTypes?.some((pattern) => pattern.test(response.headers["content-type"] ?? "")) ?? false;
        const sizeOk = exposure.minLength ? response.bodyBytes >= exposure.minLength : true;
        const signatureOk = exposure.patterns ? Boolean(matched) : true;
        if (!signatureOk && !(contentTypeOk && sizeOk)) continue;
        if (!signatureOk && exposure.patterns) continue;
        const secretHits = exposure.scanSecrets ? scanTextForSecrets(response.body, { limit: 8 }) : [];
        const specMeta = parseApiSpecMeta(response.body, exposure.path);
        findings.push({
          title: exposure.name,
          severity: exposure.severity,
          category: "exposure",
          confidence: exposure.confidence ?? (signatureOk ? "likely" : "possible"),
          tool: "argus-exposure",
          url,
          evidence: [
            `${url} → HTTP ${response.status}, ${response.bodyBytes} bytes, content-type ${response.headers["content-type"] ?? "unknown"}`,
            matched ? `Matched: ${truncate(matched.source, 160)}` : `Rule: ${exposure.description}`,
            specMeta ? `Spec: ${specMeta}` : "",
            truncate(response.body.replace(/\s+/g, " ").slice(0, 600), 600),
          ]
            .filter(Boolean)
            .join("\n"),
          description: `${exposure.description} Path: ${exposure.path}`,
          remediation: "Remove the file from the public document root, require authentication, or block the path at the edge.",
          references: ["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Mismatch"],
          cwe: "CWE-538",
          metadata: { path: exposure.path, status: response.status, bytes: response.bodyBytes, spec: specMeta },
          dedupeKey: `exposure-${exposure.path}`,
        });
        for (const hit of secretHits.slice(0, 5)) {
          findings.push({
            title: `Exposed secret: ${hit.name} (${exposure.path})`,
            severity: hit.severity,
            category: "secrets",
            confidence: hit.confidence,
            tool: "argus-secrets",
            url,
            evidence: `line ${hit.line}: ${hit.context}\nmatch: ${hit.masked}`,
            description: hit.description,
            remediation: "Remove the exposed file immediately, rotate the credential, and review access logs.",
            references: ["https://cwe.mitre.org/data/definitions/798.html"],
            cwe: "CWE-798",
            dedupeKey: `exposure-secret-${exposure.path}-${hit.id}-${hit.masked}`,
          });
        }
      }
      ctx.log("info", `Exposure audit checked ${checked} paths (${blocked} blocked by scope)`, "exposure");
      return findings;
    },
  },
  {
    id: "graphql",
    label: "GraphQL endpoint & introspection",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const findings: FindingDraft[] = [];
      const origin = originOf(ctx);
      const query = "query ArgusIntrospection { __schema { queryType { name } mutationType { name } types { name kind } } }";
      for (const path of GRAPHQL_PATHS) {
        const url = `${origin}${path}`;
        if (!ctx.guard.checkUrl(url).allowed) continue;
        let response: HttpResponse;
        try {
          response = await ctx.http.post(url, JSON.stringify({ query }), {
            headers: { "content-type": "application/json", accept: "application/json" },
            maxBodyBytes: 2_000_000,
          });
        } catch {
          continue;
        }
        if (response.status !== 200) continue;
        let parsed: { data?: { __schema?: { types?: Array<{ name: string; kind: string }>; mutationType?: { name?: string } | null } }; errors?: Array<{ message?: string }> } | undefined;
        try {
          parsed = JSON.parse(response.body) as typeof parsed;
        } catch {
          continue;
        }
        if (parsed?.data?.__schema) {
          const types = parsed.data.__schema.types ?? [];
          findings.push({
            title: "GraphQL introspection enabled",
            severity: "medium",
            category: "api",
            confidence: "confirmed",
            tool: "argus-graphql",
            url,
            evidence: `Endpoint responded to introspection.\nTypes: ${types.length}\nMutations: ${parsed.data.__schema.mutationType?.name ?? "none"}\nSample types: ${types.slice(0, 25).map((type) => type.name).join(", ")}`,
            description: "Introspection exposes the full API schema, including hidden queries and mutations.",
            remediation: "Disable introspection in production or restrict it to trusted clients.",
            references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
            cwe: "CWE-200",
            metadata: { typeCount: types.length, mutations: parsed.data.__schema.mutationType?.name },
            dedupeKey: "graphql-introspection",
          });
        } else if (parsed?.errors?.some((error) => /introspection/i.test(error.message ?? ""))) {
          findings.push({
            title: "GraphQL endpoint detected",
            severity: "info",
            category: "api",
            confidence: "confirmed",
            tool: "argus-graphql",
            url,
            evidence: `Introspection disabled: ${truncate(parsed.errors.map((error) => error.message).filter(Boolean).join("; "), 400)}`,
            description: "A GraphQL endpoint was identified; introspection is restricted.",
            remediation: "Continue testing authorization on discovered operations.",
            references: [],
            dedupeKey: "graphql-endpoint",
          });
        }
      }
      return findings;
    },
  },
  {
    id: "reflection",
    label: "Reflection & open redirect probes",
    phase: "audit",
    requiresActive: true,
    run: async (ctx) => {
      const baseline = await getBaseline(ctx);
      const targetUrl = new URL(baseline.finalUrl);
      const findings: FindingDraft[] = [];
      // Attack the parameters the site actually publishes, not just the ones on
      // the entry URL; otherwise nothing discovered on the page is ever tested.
      const points = (await injectionPoints(ctx)).filter((point) => point.method === "GET");
      const params = points.map((point) => point.name);
      const marker = `argus-${Math.random().toString(36).slice(2, 9)}"'><x-argus>`;
      for (const point of points) {
        const param = point.name;
        const probeUrl = new URL(point.url);
        probeUrl.searchParams.set(param, marker);
        if (!ctx.guard.checkUrl(probeUrl.toString()).allowed) continue;
        let response: HttpResponse;
        try {
          response = await ctx.http.get(probeUrl.toString(), { maxBodyBytes: 500_000 });
        } catch {
          continue;
        }
        if (response.body.includes(marker)) {
          findings.push({
            title: "Reflected query parameter",
            severity: "low",
            category: "injection",
            confidence: "possible",
            tool: "argus-reflect",
            url: probeUrl.toString(),
            evidence: `Parameter ${param} reflected unencoded in the response.`,
            description: "Unencoded input reflection may lead to cross-site scripting depending on context.",
            remediation: "Contextually encode output and add a restrictive CSP; validate the parameter server-side.",
            references: ["https://owasp.org/www-community/attacks/xss/"],
            cwe: "CWE-79",
            dedupeKey: `reflect-${param}-${probeUrl.pathname}`,
          });
        }
      }
      const redirectPoints = points.length > 0
        ? points
        : ["next", "url", "redirect", "return", "returnUrl", "continue", "dest", "target"].map((name) => ({
            url: targetUrl.toString(),
            name,
            method: "GET" as const,
          }));
      const canary = `https://argus-canary-${Math.random().toString(36).slice(2, 8)}.invalid/`;
      for (const point of redirectPoints.slice(0, 16)) {
        const param = point.name;
        const probeUrl = new URL(point.url);
        probeUrl.searchParams.set(param, canary);
        if (!ctx.guard.checkUrl(probeUrl.toString()).allowed) continue;
        let response: HttpResponse;
        try {
          response = await ctx.http.get(probeUrl.toString(), { followRedirects: false, maxBodyBytes: 100_000 });
        } catch {
          continue;
        }
        const location = response.headers.location ?? "";
        if ([301, 302, 303, 307, 308].includes(response.status) && location.startsWith("https://argus-canary-")) {
          findings.push({
            title: "Open redirect",
            severity: "medium",
            category: "redirect",
            confidence: "confirmed",
            tool: "argus-redirect",
            url: probeUrl.toString(),
            evidence: `Parameter ${param} produced Location: ${location} (HTTP ${response.status}).`,
            description: "The application redirects to an attacker-controlled destination, enabling phishing and token leakage.",
            remediation: "Validate redirect destinations against an allowlist and reject external URLs.",
            references: ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
            cwe: "CWE-601",
            dedupeKey: `open-redirect-${param}-${probeUrl.pathname}`,
          });
          break;
        }
      }
      return findings;
    },
  },
];

function parseApiSpecMeta(body: string, path: string): string | undefined {
  if (!API_DOC_PATHS.includes(path)) return undefined;
  try {
    const parsed = JSON.parse(body) as { openapi?: string; swagger?: string; paths?: Record<string, unknown>; info?: { title?: string; version?: string } };
    if (!parsed.openapi && !parsed.swagger) return undefined;
    const pathCount = parsed.paths ? Object.keys(parsed.paths).length : 0;
    return `${parsed.openapi ? `OpenAPI ${parsed.openapi}` : `Swagger ${parsed.swagger}`} — ${parsed.info?.title ?? "untitled"} v${parsed.info?.version ?? "?"} — ${pathCount} paths`;
  } catch {
    return undefined;
  }
}

export function webProbeTasks(): PhaseTask[] {
  return [...reconTasks, ...webTasks, ...attackTasks];
}
