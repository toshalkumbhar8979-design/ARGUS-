import type { Severity } from "./types";

export interface TechSignature {
  name: string;
  category: string;
  headers?: Array<{ name: string; pattern: RegExp }>;
  body?: RegExp[];
  cookie?: RegExp[];
}

export const TECH_SIGNATURES: TechSignature[] = [
  { name: "Cloudflare", category: "cdn", headers: [{ name: "server", pattern: /cloudflare/i }, { name: "cf-ray", pattern: /.+/ }] },
  { name: "Akamai", category: "cdn", headers: [{ name: "server", pattern: /akamai|ghost/i }, { name: "x-akamai-transformed", pattern: /.+/ }] },
  { name: "Fastly", category: "cdn", headers: [{ name: "x-served-by", pattern: /cache-/i }, { name: "x-fastly-request-id", pattern: /.+/ }] },
  { name: "Amazon CloudFront", category: "cdn", headers: [{ name: "x-amz-cf-id", pattern: /.+/ }, { name: "server", pattern: /cloudfront/i }] },
  { name: "Vercel", category: "platform", headers: [{ name: "server", pattern: /vercel/i }, { name: "x-vercel-id", pattern: /.+/ }] },
  { name: "Netlify", category: "platform", headers: [{ name: "server", pattern: /netlify/i }, { name: "x-nf-request-id", pattern: /.+/ }] },
  { name: "Nginx", category: "server", headers: [{ name: "server", pattern: /nginx/i }] },
  { name: "Apache HTTP Server", category: "server", headers: [{ name: "server", pattern: /apache/i }] },
  { name: "Microsoft IIS", category: "server", headers: [{ name: "server", pattern: /microsoft-iis/i }] },
  { name: "Caddy", category: "server", headers: [{ name: "server", pattern: /caddy/i }] },
  { name: "LiteSpeed", category: "server", headers: [{ name: "server", pattern: /litespeed/i }] },
  { name: "Envoy", category: "proxy", headers: [{ name: "server", pattern: /envoy/i }, { name: "x-envoy-upstream-service-time", pattern: /.+/ }] },
  { name: "Node.js", category: "runtime", headers: [{ name: "x-powered-by", pattern: /express/i }], body: [/__NEXT_DATA__/, /<div id="root"><\/div>/] },
  { name: "Next.js", category: "framework", headers: [{ name: "x-nextjs-cache", pattern: /.+/ }, { name: "x-powered-by", pattern: /next\.js/i }], body: [/__NEXT_DATA__/, /\/_next\/static\//] },
  { name: "React", category: "framework", body: [/data-reactroot/, /__REACT_DEVTOOLS_GLOBAL_HOOK__/, /react(?:-dom)?(?:\.production)?\.min\.js/] },
  { name: "Vue.js", category: "framework", body: [/__VUE__/, /data-v-[a-f0-9]{8}/, /vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js/] },
  { name: "Angular", category: "framework", body: [/ng-version=/, /angular(?:\.min)?\.js/, /<app-root/] },
  { name: "WordPress", category: "cms", body: [/wp-content\/themes\//, /wp-includes\//, /<meta name="generator" content="WordPress/i], cookie: [/wordpress_/i] },
  { name: "Drupal", category: "cms", body: [/\/sites\/default\/files\//, /Drupal\.settings/, /<meta name="Generator" content="Drupal/i], headers: [{ name: "x-generator", pattern: /drupal/i }] },
  { name: "Joomla", category: "cms", body: [/\/media\/system\/js\//, /Joomla!/i], headers: [{ name: "x-content-encoded-by", pattern: /joomla/i }] },
  { name: "Ghost", category: "cms", body: [/ghost\/v\d/, /<meta name="generator" content="Ghost/i] },
  { name: "Shopify", category: "ecommerce", headers: [{ name: "x-shopid", pattern: /.+/ }, { name: "x-shopify-stage", pattern: /.+/ }], body: [/cdn\.shopify\.com/, /Shopify\.theme/] },
  { name: "Magento", category: "ecommerce", body: [/\/static\/version\d+\//, /Magento_/], cookie: [/frontend=/i] },
  { name: "Laravel", category: "framework", cookie: [/laravel_session/i], headers: [{ name: "set-cookie", pattern: /laravel_session/i }], body: [/Whoops! There was an error/i] },
  { name: "Django", category: "framework", cookie: [/csrftoken/i], body: [/csrfmiddlewaretoken/, /__admin_media_prefix__/] },
  { name: "Ruby on Rails", category: "framework", cookie: [/^_session_id=/i], headers: [{ name: "x-runtime", pattern: /^\d/ }, { name: "server", pattern: /puma|unicorn|passenger/i }] },
  { name: "ASP.NET", category: "framework", headers: [{ name: "x-aspnet-version", pattern: /.+/ }, { name: "x-powered-by", pattern: /asp\.net/i }], cookie: [/ASP\.NET_SessionId/i] },
  { name: "Spring Boot", category: "framework", headers: [{ name: "x-application-context", pattern: /.+/ }], body: [/Whitelabel Error Page/, /"timestamp":\d+,"status":\d+/] },
  { name: "PHP", category: "runtime", headers: [{ name: "x-powered-by", pattern: /php/i }, { name: "server", pattern: /php/i }], cookie: [/PHPSESSID/i] },
  { name: "Java", category: "runtime", cookie: [/JSESSIONID/i], headers: [{ name: "server", pattern: /tomcat|jetty|wildfly|jboss|weblogic|websphere/i }] },
  { name: "Tomcat", category: "server", body: [/Apache Tomcat/, /Tomcat Manager/i], headers: [{ name: "server", pattern: /tomcat/i }] },
  { name: "Jenkins", category: "devops", headers: [{ name: "x-jenkins", pattern: /.+/ }], body: [/Jenkins<\/title>/, /jenkins-head-icon/] },
  { name: "Grafana", category: "observability", body: [/grafanaBootData/, /<title>Grafana<\/title>/] },
  { name: "GitLab", category: "devops", body: [/gon\.gitlab_url/, /GitLab Community Edition/, /content="GitLab"/] },
  { name: "Kibana", category: "observability", body: [/kbn-injected-metadata/, /<title>Kibana<\/title>/] },
  { name: "Elasticsearch", category: "database", body: [/"cluster_name"\s*:/, /"tagline"\s*:\s*"You Know, for Search"/] },
  { name: "Kubernetes", category: "platform", body: [/"gitVersion"\s*:\s*"v1\./, /"kind"\s*:\s*"APIVersions"/] },
  { name: "Portainer", category: "devops", body: [/portainer\.store/, /<title>Portainer<\/title>/] },
  { name: "Prometheus", category: "observability", body: [/# HELP [a-z_]+ /, /<title>Prometheus Time Series Collection and Processing Server<\/title>/] },
  { name: "Jupyter", category: "devops", body: [/<title>Jupyter Notebook<\/title>/, /jupyterlab/] },
  { name: "MinIO", category: "storage", body: [/<title>MinIO Console<\/title>/, /X-Minio-Deployment-Id/i] },
  { name: "RabbitMQ", category: "messaging", body: [/RabbitMQ Management/, /<title>RabbitMQ Management<\/title>/] },
  { name: "Consul", category: "platform", body: [/"Consul"\s*:/, /<title>Consul by HashiCorp<\/title>/] },
  { name: "Vault", category: "security", body: [/<title>Vault<\/title>/, /vault-ui/] },
  { name: "Gitea", category: "devops", body: [/<title>Gitea/, /gitea-logo/] },
  { name: "OpenAPI", category: "api", body: [/"openapi"\s*:\s*"3\./, /"swagger"\s*:\s*"2\./] },
  { name: "GraphQL", category: "api", body: [/GraphQL introspection is not allowed/, /"__schema"\s*:/] },
];

export interface WafSignature {
  name: string;
  patterns: RegExp[];
}

export const WAF_SIGNATURES: WafSignature[] = [
  { name: "Cloudflare", patterns: [/cf-ray:/i, /server: cloudflare/i, /__cf_bm=/i] },
  { name: "Akamai", patterns: [/akamai-ghost/i, /x-akamai/i, /reference #\d+\.[0-9a-f]+/i] },
  { name: "Imperva / Incapsula", patterns: [/x-iinfo:/i, /incap_ses_/i, /visid_incap_/i] },
  { name: "F5 BIG-IP ASM", patterns: [/x-wa-info:/i, /bigipserver/i, /the requested url was rejected/i] },
  { name: "Sucuri", patterns: [/x-sucuri-id:/i, /sucuri website firewall/i] },
  { name: "AWS WAF", patterns: [/x-amzn-waf/i, /awswaf/i] },
  { name: "ModSecurity", patterns: [/mod_security/i, /modsecurity/i, /not acceptable!.*mod security/i] },
  { name: "Wordfence", patterns: [/wordfence/i] },
  { name: "Barracuda", patterns: [/barracuda/i, /barra_counter_session/i] },
  { name: "Fastly", patterns: [/x-fastly/i, /fastly-error/i] },
  { name: "Azure Front Door", patterns: [/x-azure-ref:/i, /azurefd/i] },
  { name: "Google Cloud Armor", patterns: [/x-cloud-trace-context/i, /google frontend/i] },
];

export interface PortInfo {
  port: number;
  service: string;
  severity: Severity;
  note: string;
  http?: boolean;
  https?: boolean;
  protocol?: "redis" | "memcached";
}

export const COMMON_PORTS: PortInfo[] = [
  { port: 21, service: "FTP", severity: "medium", note: "Cleartext file transfer service." },
  { port: 22, service: "SSH", severity: "info", note: "Remote shell service. Restrict source ranges and prefer keys." },
  { port: 23, service: "Telnet", severity: "high", note: "Cleartext remote shell." },
  { port: 25, service: "SMTP", severity: "low", note: "Mail transfer service." },
  { port: 53, service: "DNS", severity: "info", note: "DNS service. Check for zone transfer exposure." },
  { port: 80, service: "HTTP", severity: "info", note: "HTTP service.", http: true },
  { port: 110, service: "POP3", severity: "medium", note: "Cleartext mail retrieval." },
  { port: 111, service: "rpcbind", severity: "medium", note: "RPC portmapper exposure." },
  { port: 135, service: "MSRPC", severity: "medium", note: "Windows RPC endpoint mapper." },
  { port: 139, service: "NetBIOS", severity: "medium", note: "Legacy Windows file sharing." },
  { port: 143, service: "IMAP", severity: "medium", note: "Cleartext mail retrieval." },
  { port: 161, service: "SNMP", severity: "medium", note: "SNMP service; check community strings." },
  { port: 389, service: "LDAP", severity: "medium", note: "Directory service; check anonymous bind." },
  { port: 443, service: "HTTPS", severity: "info", note: "TLS web service.", https: true },
  { port: 445, service: "SMB", severity: "high", note: "Windows file sharing exposed to the network." },
  { port: 465, service: "SMTPS", severity: "info", note: "TLS mail submission." },
  { port: 512, service: "rexec", severity: "high", note: "Legacy remote execution." },
  { port: 513, service: "rlogin", severity: "high", note: "Legacy remote login." },
  { port: 514, service: "rsh/syslog", severity: "high", note: "Legacy remote shell / syslog." },
  { port: 587, service: "SMTP submission", severity: "info", note: "Mail submission service." },
  { port: 636, service: "LDAPS", severity: "info", note: "TLS directory service." },
  { port: 873, service: "rsync", severity: "medium", note: "File synchronization service." },
  { port: 993, service: "IMAPS", severity: "info", note: "TLS mail retrieval." },
  { port: 995, service: "POP3S", severity: "info", note: "TLS mail retrieval." },
  { port: 1433, service: "MSSQL", severity: "high", note: "Microsoft SQL Server exposed." },
  { port: 1521, service: "Oracle DB", severity: "high", note: "Oracle database listener exposed." },
  { port: 2049, service: "NFS", severity: "high", note: "Network file system exposed." },
  { port: 2181, service: "ZooKeeper", severity: "high", note: "ZooKeeper coordination service exposed." },
  { port: 2375, service: "Docker API", severity: "critical", note: "Unauthenticated Docker API commonly grants host control." },
  { port: 2376, service: "Docker TLS API", severity: "high", note: "Docker API exposed." },
  { port: 2379, service: "etcd", severity: "critical", note: "etcd key-value store exposed; often contains cluster secrets." },
  { port: 3000, service: "HTTP dev server", severity: "low", note: "Development web server exposed." },
  { port: 3306, service: "MySQL", severity: "high", note: "Database service exposed." },
  { port: 3389, service: "RDP", severity: "high", note: "Remote Desktop exposed to the network." },
  { port: 4000, service: "HTTP alt", severity: "info", note: "Web service.", http: true },
  { port: 5000, service: "Docker Registry / HTTP", severity: "medium", note: "Registry or development web service.", http: true },
  { port: 5432, service: "PostgreSQL", severity: "high", note: "Database service exposed." },
  { port: 5601, service: "Kibana", severity: "high", note: "Kibana dashboards exposed.", http: true },
  { port: 5672, service: "RabbitMQ", severity: "medium", note: "Message broker exposed." },
  { port: 5900, service: "VNC", severity: "high", note: "Remote desktop without network isolation." },
  { port: 5984, service: "CouchDB", severity: "high", note: "CouchDB exposed.", http: true },
  { port: 6379, service: "Redis", severity: "high", note: "Redis exposed; unauthenticated instances allow data theft and RCE.", protocol: "redis" },
  { port: 6443, service: "Kubernetes API", severity: "high", note: "Kubernetes API server exposed.", https: true },
  { port: 7001, service: "WebLogic", severity: "high", note: "Oracle WebLogic exposed.", http: true },
  { port: 8000, service: "HTTP alt", severity: "info", note: "Web service.", http: true },
  { port: 8080, service: "HTTP alt", severity: "info", note: "Web service.", http: true },
  { port: 8081, service: "HTTP alt", severity: "info", note: "Web service.", http: true },
  { port: 8086, service: "InfluxDB", severity: "medium", note: "Time-series database exposed.", http: true },
  { port: 8443, service: "HTTPS alt", severity: "info", note: "TLS web service.", https: true },
  { port: 8500, service: "Consul", severity: "high", note: "Consul API exposed.", http: true },
  { port: 8888, service: "Jupyter", severity: "high", note: "Notebook server exposed.", http: true },
  { port: 9000, service: "Portainer / app", severity: "medium", note: "Container management or app service.", http: true },
  { port: 9001, service: "HTTP alt", severity: "info", note: "Web service.", http: true },
  { port: 9090, service: "Prometheus", severity: "medium", note: "Metrics server exposed.", http: true },
  { port: 9092, service: "Kafka", severity: "high", note: "Kafka broker exposed." },
  { port: 9200, service: "Elasticsearch", severity: "high", note: "Elasticsearch API exposed; frequently unauthenticated.", http: true },
  { port: 9300, service: "Elasticsearch transport", severity: "high", note: "Elasticsearch transport exposed." },
  { port: 9418, service: "Git", severity: "medium", note: "Git protocol service exposed." },
  { port: 9443, service: "HTTPS alt", severity: "info", note: "TLS web service.", https: true },
  { port: 10250, service: "Kubelet", severity: "critical", note: "Kubelet API exposed; may allow command execution." },
  { port: 11211, service: "Memcached", severity: "high", note: "Memcached exposed; unauthenticated access and amplification risk.", protocol: "memcached" },
  { port: 15672, service: "RabbitMQ Management", severity: "high", note: "RabbitMQ management UI exposed.", http: true },
  { port: 27017, service: "MongoDB", severity: "high", note: "MongoDB exposed." },
  { port: 27018, service: "MongoDB shard", severity: "high", note: "MongoDB shard exposed." },
  { port: 50000, service: "Jenkins agent", severity: "high", note: "CI agent port exposed." },
];

export interface ExposurePath {
  path: string;
  name: string;
  severity: Severity;
  description: string;
  patterns?: RegExp[];
  contentTypes?: RegExp[];
  minLength?: number;
  scanSecrets?: boolean;
  confidence?: "confirmed" | "likely" | "possible";
}

export const EXPOSURE_PATHS: ExposurePath[] = [
  { path: "/.git/HEAD", name: "Exposed Git repository metadata", severity: "high", description: "Git internals are publicly readable and can expose full source history.", patterns: [/^ref:\s+refs\//m, /^[0-9a-f]{40}$/m], confidence: "confirmed" },
  { path: "/.git/config", name: "Exposed Git configuration", severity: "high", description: "Git config can disclose remote URLs and credentials.", patterns: [/\[core\]/i, /\[remote/i], confidence: "confirmed" },
  { path: "/.svn/entries", name: "Exposed Subversion metadata", severity: "medium", description: "SVN metadata may disclose repository paths.", patterns: [/^\d+$/m, /dir/i], confidence: "likely" },
  { path: "/.hg/requires", name: "Exposed Mercurial metadata", severity: "medium", description: "Mercurial internals are publicly readable.", patterns: [/revlog/i, /store/i], confidence: "likely" },
  { path: "/.env", name: "Exposed environment file", severity: "critical", description: "Environment files frequently contain database passwords, API keys and signing secrets.", patterns: [/^[A-Z][A-Z0-9_]{2,}=.{2,}$/m], scanSecrets: true, confidence: "confirmed" },
  { path: "/.env.local", name: "Exposed local environment file", severity: "critical", description: "Local environment secrets are publicly readable.", patterns: [/^[A-Z][A-Z0-9_]{2,}=.{2,}$/m], scanSecrets: true, confidence: "confirmed" },
  { path: "/.env.production", name: "Exposed production environment file", severity: "critical", description: "Production environment secrets are publicly readable.", patterns: [/^[A-Z][A-Z0-9_]{2,}=.{2,}$/m], scanSecrets: true, confidence: "confirmed" },
  { path: "/.aws/credentials", name: "Exposed AWS credentials", severity: "critical", description: "AWS access keys are publicly readable.", patterns: [/aws_access_key_id/i, /aws_secret_access_key/i], confidence: "confirmed" },
  { path: "/.ssh/id_rsa", name: "Exposed SSH private key", severity: "critical", description: "An SSH private key is publicly readable.", patterns: [/-----BEGIN [A-Z ]*PRIVATE KEY-----/], confidence: "confirmed" },
  { path: "/id_rsa", name: "Exposed SSH private key", severity: "critical", description: "An SSH private key is publicly readable.", patterns: [/-----BEGIN [A-Z ]*PRIVATE KEY-----/], confidence: "confirmed" },
  { path: "/.bash_history", name: "Exposed shell history", severity: "high", description: "Shell history can reveal credentials and infrastructure details.", minLength: 20, confidence: "likely" },
  { path: "/.DS_Store", name: "Exposed directory index", severity: "low", description: "macOS directory metadata discloses file names.", patterns: [/Bud1/], confidence: "confirmed" },
  { path: "/server-status", name: "Apache server-status exposed", severity: "medium", description: "Server status reveals requests, clients and internal paths.", patterns: [/Apache Server Status/i, /Server Version:/i], confidence: "confirmed" },
  { path: "/server-info", name: "Apache server-info exposed", severity: "medium", description: "Server configuration details are exposed.", patterns: [/Apache Server Information/i, /Server Settings/i], confidence: "confirmed" },
  { path: "/phpinfo.php", name: "PHP info exposed", severity: "medium", description: "phpinfo discloses configuration, secrets and environment variables.", patterns: [/PHP Version/i, /phpinfo\(\)/i], confidence: "confirmed", scanSecrets: true },
  { path: "/info.php", name: "PHP info exposed", severity: "medium", description: "phpinfo discloses configuration and environment details.", patterns: [/PHP Version/i, /phpinfo\(\)/i], confidence: "confirmed", scanSecrets: true },
  { path: "/actuator", name: "Spring Actuator index exposed", severity: "medium", description: "Spring Boot management endpoints are exposed.", patterns: [/"(_links|self)"\s*:/, /actuator/i], confidence: "confirmed" },
  { path: "/actuator/env", name: "Spring Actuator environment exposed", severity: "high", description: "Actuator environment can disclose secrets and configuration.", patterns: [/propertSources|propertySources/i, /"activeProfiles"/i], scanSecrets: true, confidence: "confirmed" },
  { path: "/actuator/health", name: "Spring Actuator health exposed", severity: "low", description: "Health endpoint is exposed.", patterns: [/"status"\s*:\s*"UP"/i], confidence: "confirmed" },
  { path: "/actuator/heapdump", name: "Spring heap dump exposed", severity: "critical", description: "Heap dumps can contain credentials and session tokens.", contentTypes: [/octet-stream/i, /application\/x-java/i], minLength: 100000, confidence: "likely" },
  { path: "/swagger.json", name: "OpenAPI specification exposed", severity: "low", description: "API schema helps attackers enumerate endpoints and parameters.", patterns: [/"swagger"\s*:\s*"/, /"openapi"\s*:\s*"/], confidence: "confirmed" },
  { path: "/openapi.json", name: "OpenAPI specification exposed", severity: "low", description: "API schema helps attackers enumerate endpoints and parameters.", patterns: [/"swagger"\s*:\s*"/, /"openapi"\s*:\s*"/], confidence: "confirmed" },
  { path: "/v3/api-docs", name: "OpenAPI specification exposed", severity: "low", description: "API schema helps attackers enumerate endpoints and parameters.", patterns: [/"openapi"\s*:\s*"/, /"paths"\s*:\s*\{/], confidence: "confirmed" },
  { path: "/api-docs", name: "API documentation exposed", severity: "low", description: "API documentation is publicly readable.", patterns: [/"swagger"\s*:\s*"/, /"openapi"\s*:\s*"/], confidence: "likely" },
  { path: "/debug/vars", name: "Go expvar debug endpoint exposed", severity: "medium", description: "Debug variables may disclose runtime and application data.", patterns: [/^\{[\s\S]*"cmdline"/m, /"memstats"/], confidence: "confirmed" },
  { path: "/metrics", name: "Prometheus metrics exposed", severity: "low", description: "Metrics can disclose internal service names and performance data.", patterns: [/^# HELP /m, /^# TYPE /m], confidence: "confirmed" },
  { path: "/config.json", name: "Configuration file exposed", severity: "high", description: "Configuration files can contain secrets and internal endpoints.", patterns: [/"(apiKey|secret|password|token|database)"\s*:/i], scanSecrets: true, confidence: "likely" },
  { path: "/config.yml", name: "Configuration file exposed", severity: "high", description: "Configuration files can contain secrets and internal endpoints.", patterns: [/(password|secret|token|api_key)\s*:/i], scanSecrets: true, confidence: "likely" },
  { path: "/web.config", name: "IIS web.config exposed", severity: "high", description: "web.config can expose connection strings and machine keys.", patterns: [/<configuration/i, /<connectionStrings/i], scanSecrets: true, confidence: "confirmed" },
  { path: "/appsettings.json", name: "ASP.NET appsettings exposed", severity: "high", description: "Application settings can contain connection strings and secrets.", patterns: [/"ConnectionStrings"/i, /"Logging"\s*:/], scanSecrets: true, confidence: "confirmed" },
  { path: "/package.json", name: "Node.js package manifest exposed", severity: "info", description: "Dependency metadata is publicly readable.", patterns: [/"dependencies"\s*:/, /"version"\s*:/], confidence: "confirmed" },
  { path: "/composer.lock", name: "Composer lockfile exposed", severity: "info", description: "Dependency versions are publicly readable.", patterns: [/"packages"\s*:/, /"content-hash"/], confidence: "confirmed" },
  { path: "/package-lock.json", name: "npm lockfile exposed", severity: "info", description: "Dependency versions are publicly readable.", patterns: [/"lockfileVersion"/, /"packages"\s*:/], confidence: "confirmed" },
  { path: "/yarn.lock", name: "Yarn lockfile exposed", severity: "info", description: "Dependency versions are publicly readable.", patterns: [/yarn lockfile v\d/i], confidence: "confirmed" },
  { path: "/Dockerfile", name: "Dockerfile exposed", severity: "low", description: "Build instructions disclose internal structure.", patterns: [/^FROM\s+/m, /^RUN\s+/m], confidence: "confirmed" },
  { path: "/docker-compose.yml", name: "Docker Compose file exposed", severity: "medium", description: "Compose files can disclose services, credentials and volumes.", patterns: [/^services\s*:/m, /image\s*:/], scanSecrets: true, confidence: "confirmed" },
  { path: "/kubeconfig", name: "Kubeconfig exposed", severity: "critical", description: "Kubeconfig may grant cluster access.", patterns: [/apiVersion:\s*v1/i, /clusters\s*:/i, /users\s*:/i], scanSecrets: true, confidence: "confirmed" },
  { path: "/.kube/config", name: "Kubeconfig exposed", severity: "critical", description: "Kubeconfig may grant cluster access.", patterns: [/apiVersion:\s*v1/i, /clusters\s*:/i], scanSecrets: true, confidence: "confirmed" },
  { path: "/backup.sql", name: "Database backup exposed", severity: "critical", description: "Database backups can disclose all application data.", patterns: [/CREATE TABLE/i, /INSERT INTO/i], scanSecrets: true, confidence: "likely" },
  { path: "/dump.sql", name: "Database dump exposed", severity: "critical", description: "Database dumps can disclose all application data.", patterns: [/CREATE TABLE/i, /INSERT INTO/i], confidence: "likely" },
  { path: "/backup.zip", name: "Backup archive exposed", severity: "high", description: "Backup archives frequently contain source and secrets.", contentTypes: [/zip/i, /octet-stream/i], minLength: 1000, confidence: "possible" },
  { path: "/backup.tar.gz", name: "Backup archive exposed", severity: "high", description: "Backup archives frequently contain source and secrets.", contentTypes: [/gzip/i, /octet-stream/i], minLength: 1000, confidence: "possible" },
  { path: "/crossdomain.xml", name: "Permissive crossdomain policy", severity: "medium", description: "A wildcard Flash crossdomain policy can allow cross-origin reads.", patterns: [/<allow-access-from domain="\*"/i], confidence: "confirmed" },
  { path: "/clientaccesspolicy.xml", name: "Permissive Silverlight policy", severity: "low", description: "Wildcard client access policy can allow cross-origin reads.", patterns: [/<domain uri="\*"/i], confidence: "confirmed" },
  { path: "/elmah.axd", name: "ELMAH error log exposed", severity: "high", description: "Error logs can disclose stack traces, paths and secrets.", patterns: [/Error Log for/i, /ELMAH/i], scanSecrets: true, confidence: "confirmed" },
  { path: "/__debug__/", name: "Django debug toolbar exposed", severity: "medium", description: "Debug toolbar discloses SQL, settings and request internals.", patterns: [/djdt/i, /Debug Toolbar/i], confidence: "likely" },
  { path: "/telescope", name: "Laravel Telescope exposed", severity: "high", description: "Telescope reveals requests, queries and secrets.", patterns: [/Laravel Telescope/i, /telescope/i], confidence: "likely" },
  { path: "/_profiler", name: "Symfony profiler exposed", severity: "high", description: "Profiler discloses internals and potentially secrets.", patterns: [/Symfony Profiler/i, /sf-toolbar/i], confidence: "likely" },
  { path: "/console", name: "Administrative console exposed", severity: "low", description: "Administrative interface is publicly reachable.", minLength: 100, confidence: "possible" },
  { path: "/admin", name: "Administrative interface exposed", severity: "low", description: "Administrative interface is publicly reachable.", minLength: 100, confidence: "possible" },
  { path: "/.well-known/security.txt", name: "Security contact file present", severity: "info", description: "security.txt identifies a vulnerability disclosure contact.", patterns: [/Contact:/i], confidence: "confirmed" },
  { path: "/.well-known/openid-configuration", name: "OpenID configuration exposed", severity: "info", description: "Identity provider metadata is publicly readable.", patterns: [/"issuer"\s*:/, /"authorization_endpoint"\s*:/], confidence: "confirmed" },
];

export const API_DOC_PATHS = ["/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/v3/api-docs", "/api-docs", "/api/swagger.json", "/swagger-ui.html", "/swagger-ui/index.html", "/docs", "/redoc"];

export const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];

export const WORDLIST = [
  "admin", "api", "app", "assets", "auth", "backup", "backups", "beta", "bin", "build", "cache", "cdn", "cgi-bin",
  "config", "console", "dashboard", "data", "db", "debug", "dev", "docs", "download", "downloads", "env", "files",
  "git", "graphql", "health", "help", "images", "img", "internal", "js", "login", "logs", "metrics", "monitor",
  "oauth", "old", "panel", "private", "prod", "public", "reports", "robots.txt", "s3", "sdk", "server-status",
  "settings", "setup", "sitemap.xml", "staging", "static", "status", "storage", "swagger", "system", "temp",
  "test", "tmp", "uploads", "user", "users", "v1", "v2", "v3", "vendor", "web", "webhook", "webhooks", "wp-admin",
  "wp-content", "wp-includes", "wp-login.php", ".well-known", "actuator", "swagger-ui", "openapi.json",
  "phpinfo.php", "info.php", "server-info", "elmah.axd", "trace", "metrics", "version", "readme.md", "readme",
  "changelog", "license", "Dockerfile", "docker-compose.yml", "package.json", "composer.json", "yarn.lock",
  "package-lock.json", ".git/HEAD", ".env", ".env.local", ".env.production", ".aws/credentials",
  "server-status?auto", "jenkins", "grafana", "kibana", "prometheus", "rabbitmq", "consul", "vault", "portainer",
];

export interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  confidence: "confirmed" | "likely" | "possible";
  description: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  { id: "aws-access-key", name: "AWS access key", regex: /\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/g, severity: "critical", confidence: "confirmed", description: "Hard-coded AWS access key identifier." },
  { id: "github-token", name: "GitHub token", regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, severity: "critical", confidence: "confirmed", description: "GitHub personal access or app token." },
  { id: "github-fine-grained", name: "GitHub fine-grained token", regex: /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g, severity: "critical", confidence: "confirmed", description: "GitHub fine-grained personal access token." },
  { id: "gitlab-token", name: "GitLab token", regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, severity: "critical", confidence: "confirmed", description: "GitLab personal access token." },
  { id: "slack-token", name: "Slack token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, severity: "critical", confidence: "confirmed", description: "Slack API token." },
  { id: "stripe-secret", name: "Stripe secret key", regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g, severity: "critical", confidence: "confirmed", description: "Stripe live secret key." },
  { id: "google-api-key", name: "Google API key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "high", confidence: "likely", description: "Google API key." },
  { id: "openai-key", name: "OpenAI API key", regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b/g, severity: "critical", confidence: "likely", description: "OpenAI API key." },
  { id: "private-key", name: "Private key block", regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, severity: "critical", confidence: "confirmed", description: "Private key material committed or exposed." },
  { id: "npm-token", name: "npm token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "high", confidence: "confirmed", description: "npm automation token." },
  { id: "sendgrid-key", name: "SendGrid API key", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: "high", confidence: "confirmed", description: "SendGrid API key." },
  { id: "twilio-key", name: "Twilio API key", regex: /\bSK[0-9a-fA-F]{32}\b/g, severity: "high", confidence: "possible", description: "Twilio API key." },
  { id: "digitalocean-token", name: "DigitalOcean token", regex: /\bdop_v1_[a-f0-9]{64}\b/g, severity: "high", confidence: "confirmed", description: "DigitalOcean API token." },
  { id: "jwt", name: "JSON Web Token", regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: "medium", confidence: "possible", description: "Embedded JWT that may grant access." },
  { id: "db-uri", name: "Database URI with credentials", regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s@/]+@[^\s)'"]+/g, severity: "critical", confidence: "likely", description: "Connection string containing embedded credentials." },
  { id: "basic-auth-url", name: "URL with basic auth", regex: /\bhttps?:\/\/[^\s:@/]+:[^\s@/]+@[^\s)'"]+/g, severity: "high", confidence: "likely", description: "URL embeds credentials." },
  { id: "generic-secret", name: "Hard-coded secret assignment", regex: /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["'][^"'\s]{12,}["']/gi, severity: "medium", confidence: "possible", description: "Potential hard-coded credential." },
];

export interface TakeoverFingerprint {
  provider: string;
  cnameSuffixes: string[];
  body: RegExp[];
}

export const TAKEOVER_FINGERPRINTS: TakeoverFingerprint[] = [
  { provider: "GitHub Pages", cnameSuffixes: ["github.io"], body: [/There isn't a GitHub Pages site here/i, /For root URLs \(http:\/\/example\.com\/\) you must provide an index\.html file/i] },
  { provider: "Heroku", cnameSuffixes: ["herokuapp.com", "herokussl.com"], body: [/No such app/i, /heroku \| no such app/i] },
  { provider: "Netlify", cnameSuffixes: ["netlify.app", "netlify.com"], body: [/Not Found - Request ID/i, /page not found/i] },
  { provider: "Vercel", cnameSuffixes: ["vercel.app", "now.sh"], body: [/The deployment could not be found/i, /DEPLOYMENT_NOT_FOUND/i] },
  { provider: "Azure", cnameSuffixes: ["azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"], body: [/404 Web Site not found/i, /Error 404 - Web app not found/i] },
  { provider: "Amazon S3", cnameSuffixes: ["s3.amazonaws.com", "s3-website"], body: [/NoSuchBucket/i, /The specified bucket does not exist/i] },
  { provider: "Shopify", cnameSuffixes: ["myshopify.com"], body: [/Sorry, this shop is currently unavailable/i, /Only one step left/i] },
  { provider: "Tumblr", cnameSuffixes: ["tumblr.com"], body: [/Whatever you were looking for doesn't currently exist at this address/i] },
  { provider: "WordPress.com", cnameSuffixes: ["wordpress.com"], body: [/doesn’t exist/i, /doesn't exist/i] },
  { provider: "Bitbucket", cnameSuffixes: ["bitbucket.io"], body: [/Repository not found/i] },
  { provider: "Ghost", cnameSuffixes: ["ghost.io"], body: [/The thing you were looking for is no longer here/i] },
  { provider: "Surge.sh", cnameSuffixes: ["surge.sh"], body: [/project not found/i] },
  { provider: "Read the Docs", cnameSuffixes: ["readthedocs.io"], body: [/<title>404 Not Found<\/title>/i] },
  { provider: "Zendesk", cnameSuffixes: ["zendesk.com"], body: [/Help Center Closed/i] },
  { provider: "Freshdesk", cnameSuffixes: ["freshdesk.com"], body: [/May be the account has been deleted/i] },
  { provider: "Statuspage", cnameSuffixes: ["statuspage.io"], body: [/Status page not found/i] },
  { provider: "Unbounce", cnameSuffixes: ["unbounce.com"], body: [/The requested URL was not found/i] },
];

export const TOOL_INSTALL_HINTS: Record<string, string> = {
  nmap: "winget install Insecure.Nmap | choco install nmap | brew install nmap | sudo apt install nmap",
  nuclei: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
  ffuf: "go install github.com/ffuf/ffuf/v2@latest",
  nikto: "sudo apt install nikto | docker pull sullo/nikto",
  sqlmap: "python -m pip install sqlmap | sudo apt install sqlmap",
  subfinder: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
  naabu: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
  gobuster: "go install github.com/OJ/gobuster/v3@latest",
  semgrep: "python -m pip install semgrep | brew install semgrep",
  gitleaks: "go install github.com/gitleaks/gitleaks/v8@latest | winget install gitleaks.gitleaks",
  trivy: "winget install AquaSecurity.Trivy | brew install trivy | sudo apt install trivy",
  "osv-scanner": "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest",
  bandit: "python -m pip install bandit",
  checkov: "python -m pip install checkov",
  whatweb: "sudo apt install whatweb | gem install whatweb",
  httpx: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
};

export const TECHNOLOGY_VERSION_PATTERNS: Array<{ name: string; patterns: RegExp[] }> = [
  { name: "WordPress", patterns: [/<meta name="generator" content="WordPress ([0-9.]+)"/i, /\?ver=([0-9.]+)/i] },
  { name: "nginx", patterns: [/nginx\/([0-9.]+)/i] },
  { name: "Apache", patterns: [/Apache\/([0-9.]+)/i] },
  { name: "PHP", patterns: [/PHP\/([0-9.]+)/i, /X-Powered-By: PHP\/([0-9.]+)/i] },
  { name: "Express", patterns: [/Express\/([0-9.]+)/i] },
  { name: "IIS", patterns: [/Microsoft-IIS\/([0-9.]+)/i] },
  { name: "OpenSSH", patterns: [/OpenSSH[_\/(]([0-9.]+)/i] },
];
