export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export type TargetKind = "web" | "api" | "network" | "repo";

export type ProfileId = "quick" | "recon" | "web" | "api" | "network" | "deep" | "repo";

export type RunStatus = "pending" | "running" | "completed" | "failed" | "aborted";
export type TaskStatus = "pending" | "running" | "done" | "skipped" | "failed";
export type Confidence = "confirmed" | "likely" | "possible";

export interface ScopePolicy {
  version: 1;
  name: string;
  authorizedBy: string;
  authorizationRef: string;
  expiresAt: string;
  allow: string[];
  deny?: string[];
  maxRps?: number;
  allowedPorts?: number[];
  allowActive?: boolean;
  allowIntrusive?: boolean;
  allowExternal?: boolean;
}

export interface ScopeValidation {
  ok: boolean;
  errors: string[];
  warnings: string[];
  expired: boolean;
  active: boolean;
  intrusive: boolean;
  external: boolean;
  allowedCount: number;
}

export interface Target {
  raw: string;
  kind: TargetKind;
  host?: string;
  ip?: string;
  port?: number;
  scheme?: "http" | "https";
  url?: string;
  baseUrl?: string;
  path?: string;
  display: string;
}

export interface Finding {
  id: string;
  runId: string;
  title: string;
  severity: Severity;
  category: string;
  confidence: Confidence;
  target: string;
  url?: string;
  evidence: string;
  description: string;
  remediation: string;
  references: string[];
  cwe?: string;
  owasp?: string;
  /** CVSS v3.1 base score and the vector it was derived from. */
  cvss?: { score: number; vector: string };
  tool: string;
  timestamp: string;
  fingerprint: string;
  metadata?: Record<string, unknown>;
}

export interface FindingDraft {
  title: string;
  severity: Severity;
  category: string;
  confidence?: Confidence;
  target?: string;
  url?: string;
  evidence?: string;
  description?: string;
  remediation?: string;
  references?: string[];
  cwe?: string;
  owasp?: string;
  cvss?: { score: number; vector: string };
  tool: string;
  metadata?: Record<string, unknown>;
  dedupeKey?: string;
}

export interface RunOptions {
  profile: ProfileId;
  passiveOnly?: boolean;
  maxRps?: number;
  timeoutMs?: number;
  concurrency?: number;
  allowExternal?: boolean;
  detectTools?: boolean;
  intrusive?: boolean;
  /** Extra attempts for a probe that throws. 0 keeps single-shot behaviour. */
  retryFailedTasks?: number;
  exportFormats?: ReportFormat[];
}

export interface DependencyNode {
  key: string;
  name: string;
  version: string;
  ecosystem: string;
  direct: boolean;
  range?: string;
  latest?: string;
  outdated?: boolean;
}

export interface DependencyEdge {
  from: string;
  to: string;
}

export interface DependencySummary {
  nodes: number;
  direct: number;
  transitive: number;
  edges: number;
  outdated: number;
  ecosystems: string[];
  packageManager: string;
  latestCheck: "registry" | "skipped" | "failed";
}

export interface DependencyGraphSnapshot {
  manifests: string[];
  lockfiles: string[];
  nodes: DependencyNode[];
  edges: DependencyEdge[];
  summary: DependencySummary;
  notes: string[];
}

export interface RunRecord {
  id: string;
  target: Target;
  profile: ProfileId;
  scope: ScopePolicy;
  scopePath: string;
  options: RunOptions;
  status: RunStatus;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  counts: SeverityCounts;
  phaseSummary: PhaseSummary[];
  dependencies?: DependencyGraphSnapshot;
  error?: string;
  dataDir: string;
}

export type SeverityCounts = Record<Severity, number>;

export interface PhaseSummary {
  id: string;
  label: string;
  status: TaskStatus;
  durationMs?: number;
}

export interface RunHandle {
  record: RunRecord;
  findings: Finding[];
}

export type ReportFormat = "markdown" | "json" | "sarif" | "csv" | "html" | "research";

export interface PhaseTask {
  id: string;
  label: string;
  phase: string;
  requiresActive?: boolean;
  requiresIntrusive?: boolean;
  run: (ctx: ProbeContext) => Promise<FindingDraft[] | void>;
}

export interface Phase {
  id: string;
  label: string;
  description: string;
  tasks: PhaseTask[];
}

export interface HttpResponse {
  url: string;
  finalUrl: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  rawHeaders: Record<string, string[]>;
  body: string;
  bodyBytes: number;
  elapsedMs: number;
  redirects: string[];
  tls?: TlsInfo;
  fromCache?: boolean;
}

export interface TlsInfo {
  protocol: string;
  cipher: string;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  san: string[];
  selfSigned: boolean;
  hostnameMatch: boolean;
  fingerprint256: string;
}

export interface ToolAvailability {
  id: string;
  name: string;
  category: string;
  binary: string;
  installed: boolean;
  path?: string;
  version?: string;
  install: string;
  intrusive: boolean;
  description: string;
}

export interface ExternalToolResult {
  findings: FindingDraft[];
  stdout: string;
  stderr: string;
  exitCode: number;
  skipped?: string;
}

export interface HttpClientOptions {
  timeoutMs: number;
  maxRps?: number;
  userAgent: string;
  maxRedirects?: number;
  maxBodyBytes?: number;
  insecure?: boolean;
  /** Reuse sockets for scans; one-off manual requests can turn this off. */
  keepAlive?: boolean;
}

export interface JsonRpcToolInfo {
  server: string;
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface McpServerConfig {
  transport: "stdio" | "http";
  command?: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
  enabled?: boolean;
}

export interface ConnectorConfig {
  id: string;
  type: "webhook" | "slack" | "discord" | "github" | "jira" | "file";
  enabled: boolean;
  minSeverity?: Severity;
  options: Record<string, string | boolean | number>;
}

export interface ArgusConfig {
  dataDir: string;
  defaultProfile: ProfileId;
  maxRps: number;
  timeoutMs: number;
  concurrency: number;
  userAgent: string;
  allowExternalIntel: boolean;
  maxFileScanBytes: number;
  mcpServers: Record<string, McpServerConfig>;
  connectors: ConnectorConfig[];
  disabledTools: string[];
  llm?: {
    enabled: boolean;
    providerId?: string;
    baseUrl: string;
    model: string;
    apiKeyEnv: string;
  };
}

export interface ProbeContext {
  runId: string;
  target: Target;
  scope: ScopePolicy;
  guard: import("./scope").ScopeGuard;
  options: RunOptions;
  http: import("./http").HttpClient;
  guardRequest: <T>(fn: () => Promise<T>) => Promise<T>;
  addFindings: (drafts: FindingDraft[]) => Finding[];
  emit: (event: import("./events").ArgusEventInput) => void;
  log: (level: "debug" | "info" | "warn" | "error", message: string, source?: string) => void;
  signal: AbortSignal;
  state: Map<string, unknown>;
  dataDir: string;
  runDir: string;
  workspace: string;
}

export interface EngineHooks {
  onEvent?: (event: import("./events").ArgusEvent) => void;
  onFinding?: (finding: Finding) => void;
  signal?: AbortSignal;
}
