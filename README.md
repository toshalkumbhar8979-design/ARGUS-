# ARGUS

[![npm version](https://img.shields.io/npm/v/argus-pentest.svg)](https://www.npmjs.com/package/argus-pentest)

Terminal-first, authorization-gated security assessment harness. Ask it in plain
English and a grounded agent plans scans, reads the source, searches the workspace and
reports only findings that real tools produced. It runs native probes plus optional
external adapters, saves every event and finding, and writes reports.

> Only assess systems you have written permission to test. Naming a target in the
> prompt is the authorization record; a manual scope file remains available for teams
> that need one.

## Install and run

Global install (the npm name `argus` belongs to an unrelated package, so the package
is `argus-pentest`; the installed command is `argus`):

```bash
npm install -g argus-pentest   # needs Bun >= 1.3.14 on PATH
argus --version
argus tui                      # terminal UI
argus --help                   # command-line interface
argus doctor                   # environment and toolchain check
```

The installed command is `argus`, not `argus-pentest`. If an installed copy ever
fails to resolve an MCP SDK subpath, run `bun upgrade` and start `argus` again.

From a checkout:

```bash
bun install
bun run tui        # terminal UI (alias: bun run dev)
bun run cli --help # command-line interface
```

## Terminal UI

The TUI is a normal prompt-driven terminal, laid out like a quiet instrument panel:

```
▌ ARGUS  security assessment                       OpenAI · gpt-4.1-mini
scope  example.com · valid · TICKET-42                          scope.json
──────────────────────────────────────────────────────────────────────────
❯ audit example.com and rank what you find

RESULT ──────────────────────────────────────────────────────────────────
...
FINDINGS ────────────────────────────────────────────────────────────────
MED  SPF record missing · example.com

  ⠹  HTTP baseline & technology fingerprint  ███████░░░░░  3/7  00:12
╭──────────────────────────────────────────────────────────────────────╮
│ ❯ ask in plain English, or / for commands                            │
╰──────────────────────────────────────────────────────────────────────╯
/help  tab complete  esc interrupt  ctrl+c exit        key from OPENAI_API_KEY
```

The masthead carries the identity, the active provider/model and the authorization in
play. Operator prompts use the accent `❯`, findings render as coloured severity chips,
section headings get a hairline, and one status line above the prompt shows the live
phase with a block progress meter or the session's finding counts. Everything is a
single column, so narrow terminals keep the same layout. Panels and lists use a solid
`▌` selection bar (k9s/lazygit convention), and all markers are terminal glyphs — no
emoji, no bracketed tags, nothing that needs a Nerd Font. Plain text goes to the agent (`audit example.com and find real bugs`). Type `/`
to open the command menu; `Up`/`Down` select, `tab` completes, `enter` opens the highlighted
picker or runs the command. `esc` closes a modal, aborts the agent or clears the prompt.

Drag across transcript text to select it, then press `ctrl+c` to copy; the selection is
highlighted by the renderer and copying works through OSC 52 plus the native platform
clipboard, so it also works over SSH in terminals such as Windows Terminal, iTerm2,
kitty and WezTerm. `/copy` copies the last agent answer and `/copy all` copies the
whole transcript. With no selection, `ctrl+c` still aborts a running job or exits.

Mouse support is enabled by default: click the prompt to focus it, click a command
suggestion or a provider/model/MCP row to act on it, click `esc to close` in a modal,
and use the wheel over the transcript or a modal list. Dragging still selects text for
copying.

| Command | What it does |
| --- | --- |
| `/help` | list every command and scan flag |
| `/doctor [--chat]` | preflight provider, key, model, scope, memory, store and adapters; `--chat` sends one tiny completion |
| `/scan <target>` | start an assessment; scope follows the target (defaults to the `deep` profile) |
| `/dashboard` | overview, risk gauge, severity and category bars, probe coverage, dependency graph, outdated packages, fix plan and findings |
| `/providers` | provider picker modal |
| `/models` | model picker grouped by provider, with live discovery and search across providers and models |
| `/connect` | provider and MCP picker with search; `enter` activates a provider or opens key entry, or connects an MCP server |
| `/key [provider]` | add or replace an API key in one step (active provider by default) |
| `/copy [last\|all]` | copy the last answer or the whole transcript |
| `/memory` | show the AGENTS.md memory file and its newest entries |
| `/runs` | recent assessments |
| `/findings [runId]` | review findings for the last or a specific run |
| `/preview <path> [--start N] [--end N]` | read-only preview panel: numbered lines, scrollable, never writes |
| `/report [runId] [format]` | write markdown, json, sarif, csv or html reports |
| `/tools` | external adapter inventory and install hints |
| `/install [tool...] [--all] [--yes]` | plan platform-specific adapter installs; `--yes` runs only user-level plans |
| `/web <query>` / `/web read <url>` | keyless web search or one public page, with SSRF and size checks |
| `/http <url> ...` | send one request; scope follows the URL |
| `/jwt <token>` | decode a JWT locally and flag session risks without sending it anywhere |
| `/scope [path\|init\|target]` | show, derive or validate the active scope |
| `/config` | effective configuration, with key names but never key values |
| `/authorize` | one-time authorized-use agreement (`accept <name>`, `revoke`, status) |
| `/vim [file]` | edit a file (or the project) in the embedded terminal, using Kali's vim when WSL is present |
| `/terminal [cmd]` | open an interactive shell or run a command in the embedded terminal |
| `/clear`, `/quit` | clear the transcript, exit |

Scan flags: `--profile quick|recon|web|api|network|deep|repo`, `--scope <file>`,
`--passive`, `--intrusive`, `--no-external`, `--formats md,json,sarif`, `--retries 0-5`.
Scope is derived from the target you name; a manual `--scope` file is still honored.

### Preflight

Run `/doctor` before a session when something looks wrong. It checks the active provider's
`/models` endpoint and reports whether the key was rejected, the server is down, the base
URL is missing, or the selected model is absent from the live catalog. It also validates
the active scope, reports the AGENTS.md path and entry count, checks that the data directory
is writable, inventories external adapters, reports the web-research mode, and lists
configured MCP servers. By default
it never sends a chat completion, so a preflight does not spend credits. Add `--chat` to
send one minimal completion and prove the exact chat endpoint, model and key work; that
option uses a small amount of credit and reports the round-trip latency. Status lines use plain ASCII tags: `[+]` ok,
`[!]` warning, `[-]` error, `[..]` in progress. No emoji or Nerd Font glyph is required.

### Providers and models

`/providers` covers OpenAI, OpenRouter, Groq, DeepSeek, Together, Mistral, xAI, NVIDIA
NIM, local Ollama and LM Studio, plus any custom OpenAI-compatible endpoint
(`/providers url https://host/v1`). `/models` renders every provider as a group with
its models underneath, puts the active provider first, queries the active endpoint's
`/models` API, and keeps a known catalog as fallback. Typing filters both provider
names and model ids; `Up`/`Down` select, `enter` switches provider and model. Queries are
skipped when the provider still needs a key, so the picker never stalls on a request
that cannot succeed.

Adding a key takes one command: `/key` opens key entry for the active provider and
`/key nvidia` for a named one. From `/connect`, pressing `enter` on a provider that
has no key opens the same entry; on a provider that has a key it activates it
immediately. Paste with `ctrl+v` (or your terminal's paste shortcut), or type the key,
then press `enter` - it is saved to
`<dataDir>/credentials.json` with owner-only permissions, applied to the current
process, and the provider is activated in the same step. Key entry shows the
provider's key page (`https://platform.openai.com/api-keys`, `https://build.nvidia.com/settings/api-keys`,
and so on) so you can create one without leaving the flow. Keys render as bullets and
never enter the transcript. You can still export the environment variable named in
the config (`OPENAI_API_KEY` and friends) before launching. Use `r` on a provider
detail only if you want a manual endpoint check; activation itself does no network
request, so switching providers is instant. No secret value is ever printed by the
harness.

NVIDIA NIM is included as a first-class provider at
`https://integrate.api.nvidia.com/v1` (`NVIDIA_API_KEY`). Its `GET /v1/models`
endpoint exposes the whole hosted catalog - Nemotron, Llama, DeepSeek, Mistral, GLM,
Kimi and more - so `/models` lists the live set when NVIDIA is active, with a curated
fallback of chat/coding/reasoning ids before the key exists.

Selections persist to `argus.config.json` (or the file named by `ARGUS_CONFIG`).

### The agent

Plain text starts a grounded loop - no magic words. "check example.com", "is my site
safe?", "look at this repo for bugs", "what is broken here?" and "harden this" are all
assessment requests. The interpreter understands:

- a literal domain, URL, IP, `localhost:port` or existing path;
- "my site", "this app" or "the target" when the active scope has exactly one entry;
- "my code", "this repo", "the code base", "the source tree" or "this project" as the workspace;
- a whole-codebase request such as "scan the whole code base and rank the vulns" without a target;

Scope is **prompt-derived**. When you name a URL, host, IP, CIDR, `localhost:port` or
existing path, Argus records exactly that surface and starts. A generated scope grows as
you name new targets; a manual scope file is preserved in place and a prompt-derived
sibling is used instead. `passive` / `read-only` / `offline` suppress active requests;
`full` / `aggressive` / `intrusive` widen checks; `no external` disables registry, OSV
and subdomain intelligence. A local-only request is reviewed as the workspace without
pretending it authorized a network target. A pure factual question with no target is
answered as conversation, not a scan.

A greeting, a question or an ordinary coding request needs no authorization at all:
that turn runs **unscoped** - reading, search, edits and shell keep working - and no
scope file is written. Naming a target, or asking for an assessment, derives the scope
for that turn. An existing scope file is reused as-is and is never rewritten for an
ordinary prompt, so "Hi" can no longer mint or update an authorization record.

Unambiguous natural-language shortcuts run locally, without a model call: `check
example.com`, `scan my app`, `find bugs in this repo`, `show findings`, `dashboard`,
`preview src/core/http.ts`, `add nvidia api key`, `search the web for a CVE`,
`jwt <token>` and `http <url>`.
That keeps common actions fast and lets them work before a key is configured. Local
scans derive scope from the target and start immediately; anything that needs reasoning
goes to the model.

If no provider key is configured, a free-form prompt now explains how to add one with
`/key` and lists the no-key actions instead of failing silently. If the model endpoint
is unreachable and the prompt maps to a local action, Argus runs that action instead of
dead-ending.

If the target is genuinely ambiguous (for example two scope rules and "the target"),
the agent asks one short question instead of guessing. The model gets thirty-one real
tools: the assessment tools `scan_target`, `get_findings`, `list_runs`, `web_search`,
`read_url`, `http_request`, `http_history`, `browser`, `analyze_jwt` and
`security_tools`; the
workspace tools `list_dir`, `glob`, `read_file`, `preview`, `search_code`, `write_file`,
`edit_file`, `apply_patch` and `run_command`; the package tools `install_package` and
`install_tool`; plus `todo_write`, `spawn_subagents`, `report_finding`, `remember` and
`load_skill`. It can scan, read findings, inspect and
edit source, run tests, install a dependency, list missing security adapters, research
current advisories, probe an authorized endpoint, load a per-class playbook, review the
traffic it already sent, review a token and run a second pass
where coverage was weak. On Windows it can also drive the host's Kali Linux through
`wsl`, including installing missing Kali tooling, and it asks for approval first when
the policy requires it. Its system prompt carries an explicit attacker-mindset layer:
start from trust boundaries and trace input to sink, work in falsifiable hypotheses,
compare account/role/request pairs, chain primitives instead of listing issues, and
rank by exploitability rather than count.
There is no fixed tool-step budget. The loop continues until the model finalizes, the
operator aborts, or it repeats the same call or produces invalid output. Failed probes
are still retried (three extra attempts for agent scans).

The read-only `preview` tool is a UI surface as well: when the model previews a file or
the exact diff a write would create, the preview panel opens on top with line numbers,
add/remove colouring and a short staggered reveal, and the transcript keeps the same
path. `/preview <path> [--start N] [--end N]` opens the same panel by hand. Nothing in it
writes, it is confined to the workspace and the authorized local roots, and `esc` closes
it.

Workspace tools behave like a normal terminal agent. Reads and writes are confined to
the workspace plus directories named in the active prompt scope; `.git`, `.ssh`, `.aws`
and `.gnupg` are never writable. `run_command` executes non-interactive `bash -lc`
inside an authorized root with a 120-second cap and truncated output. Privilege
escalation and host-destructive commands are refused. A command that can delete or
rewrite (`rm -rf`, `git reset --hard`, `git clean -fd`, a publish or a piped remote
script) opens an approval prompt: `y` allows once, `a` allows that action for the rest
of the run (high-risk actions still ask), `n` or `esc` denies. Approval is interactive
in the TUI and defaults to deny when no operator is attached.

The default posture is prompt-independent. Scoped network work follows the authorization
derived from the target; local writes, shell commands and package installs ask the
operator. The agent does not guess from words like "fix", "scan" or "review". Only an
explicit operator directive changes the posture: `read-only`, `don't change anything`
or `explain only` refuses local changes; `just do it`, `without asking` or `no questions`
pre-approves them for that turn. The policy is printed as `- perm | ...` at the start of
the run, and hard blocks still win: privilege escalation and host-destructive commands
are never available.

`install_package` detects the repository's manager from its lockfile, validates the
package name and version, and runs an argv-only install (`bun add`, `npm install`,
`pnpm add`, `yarn add`, `uv add`, `pip`, `cargo add`, `go get`, `composer require` or
`bundle add`). It never interpolates a shell string. `security_tools` returns installed
and missing adapters with versions and install commands; `scan_target` automatically
uses the installed ones for the selected profile.

The plan is visible while the agent works. `todo_write` publishes `[done]`, `[active]`
and `[queued]` rows above the status bar, and the same plan is included in the final
answer. A write or edit returns a unified diff so the transcript shows exactly what
changed, and the approval prompt for a write, edit or patch shows the same diff before
the operator decides.

`preview` is the read-only counterpart: `{"path":"src/a.ts"}` returns numbered lines,
and `{"path":"src/a.ts","content":"..."}` or `{"path":"src/a.ts","patch":"..."}`
returns the exact unified diff the change would produce with an `unchanged` flag when
there is nothing to do. It never writes and needs no approval, so the agent can inspect
a change - or show a file to the operator - before touching anything.

Transcript status lines use terminal marker glyphs instead of bracketed tags: `::` for
steps, `>` for a running tool or subagent, `+` for done, `!` for failed or refused, `-`
for notes, and `$` for the `argus resume -session` command. Everything is plain ASCII:
no emoji and no Nerd Font glyphs.

`spawn_subagents` runs one to three focused agents in parallel with explicit roles:
`recon`, `auth`, `input`, `secrets`, `deps`, `config`, `web` and `verify`. Each child
gets a role checklist, its parent's scope, permission posture and tools, and no fixed
step budget of its own. A child that needs to write or install raises the same operator
approval prompt as the parent. Duplicate assignments are rejected,
nested subagents are refused, and overlapping findings are deduped by title, target,
category and CWE before merging.
A timed-out child returns its partial verified findings and a gap instead of stalling
the whole run.

The agent talks to the provider the way a normal coding harness does: the tool list is
sent as native function schemas, and `tool_calls` in the reply are executed directly,
several per turn, with the results returned as `role: "tool"` messages. A model that
answers in plain text with no tool call is finished — that text is the answer. If a
provider rejects function calling (400/404/405/415/422/501 mentioning tools or
functions), the client downgrades itself to the JSON protocol for the rest of the
session and retries, so text-only servers, Ollama builds and gateways keep working.

Every model response is checked. If a provider ignores the JSON protocol, the raw
reply is shown immediately, and after a second prose reply it is rendered as the
answer (with its finding ids still passed through the anti-hallucination gate) rather
than dead-ending. Transient provider failures (429 and 5xx) are retried with backoff,
and errors name the endpoint and explain whether the key, URL or model is the problem.

### Web research

Agents can search the web without a separate API key. `web_search` uses DuckDuckGo's
public HTML results; set `ARGUS_SEARCH_URL` to a SearXNG-compatible JSON endpoint for
a private or rate-limit-free instance. `read_url` reads a page through DNS,
private-address, redirect, content-type and size checks, so it cannot be pointed at
localhost, link-local metadata or a private network. Search snippets and page text
are explicitly marked untrusted: they can guide research, but they can never create a
finding or override the scope. The operator shortcuts are `/web <query>` and
`/web read <url>`.

### Manual request testing

`/http` sends one request you specify, without spending a model call. The URL you name
is the authorization; a manual `--scope` file is still honored and redirects cannot
leave the active scope. Examples:

```text
/http https://staging.example.com/api/me --bearer $TOKEN
/http https://staging.example.com/api/items --method POST --json '{"name":"x"}' --header "X-Trace: 1"
```

Supported options: `--method GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS`, `--header "Name: value"`,
`--bearer <token>`, `--json <body>`, `--form <body>`, `--body <text>` and `--scope <file>`.
`POST` runs with prompt-derived active mode; `PUT`, `PATCH` and `DELETE` additionally
need `intrusive` / `full` language or a manual scope that allows them. Port rules and
deny rules are enforced on every hop. The
response prints status, latency, size, redirect chain, headers, TLS facts and a 12-line
body preview. `set-cookie` values are hidden. The agent exposes the same capability as
its `http_request` tool.

`/jwt <token>` decodes a JWT locally with no network call or provider key. It reports
`alg`, expiry, remote-key headers (`jku`/`x5u`/`jwk`), missing `iss`/`aud`/`sub`, and
sensitive claims with their values redacted. It never verifies the signature - confirm
each flag against the live service. Add `--json` for a machine-readable analysis.

### Adapter installation

`/install` builds a platform-aware plan for every missing adapter. It prefers user-level
managers (`go install`, `pip`, `gem`, `brew`, `winget`) and prints admin plans
(`apt-get`, `dnf`, `pacman`, `choco`) with the exact `sudo` command but never executes
them. `/install --yes` alone shows the plan and refuses a mass install; add `--all` or
name the tools. `/install subfinder nuclei --yes` runs only those available user-level
plans, sequentially, with a five-minute cap per plan. Afterward, run `/tools` to confirm
and restart the shell if `PATH` changed.

### Memory

Argus maintains `AGENTS.md` in the working directory. It is created automatically on
first launch, read before every agent turn, and appended after a run that produced
scans or verified findings. The agent can also add a durable note with `remember`.
The file is capped and pruned, credentials are redacted before writing, and the
content is injected as untrusted data explicitly above the hard rules, so a memory
entry can never override scope or authorization. Use `/memory` to inspect it or edit
it by hand to give the agent durable project context; never put secrets in it.

Hallucination is blocked deterministically, not by asking the model nicely:

- a scan target must be literally named or unambiguously inferred from a single active scope entry / the workspace;
- every claimed vulnerability must cite a finding id returned by a tool this turn;
- unknown ids and invented citations in the prose are removed and counted;
- if the model cites no finding ids, all real tool-observed findings are still shown with a warning;
- tool output is the only evidence source; web pages are untrusted research, never evidence;
- failures are reported as gaps; a named-target assessment must use at least one real tool before it may answer;
- subagents inherit the same allowed targets, are deduped, and merge through the same gate.

Source excerpts returned by `read_file` and `search_code` are sent to the configured
model provider. Keep that in mind when auditing code you cannot share; API keys stay
local and are never included in prompts.

### Ruthless execution

Assessments are meant to be thorough: `/scan` defaults to the `deep` profile, retries
each failed probe twice with backoff, prints every retry and failure instead of hiding
it, streams phases and findings into the transcript as they land (not just at the end),
and reports the run directory and generated reports. The agent has no fixed step
ceiling; it must produce a final report from the evidence it already has instead of
stopping without an answer. An optional per-run cap can still be supplied by callers,
and it warns before that cap is reached. Findings are ordered
by a transparent risk score (severity, confidence and high-impact category), and the
terminal output shows that score. After the findings, a `FIXES` plan groups findings
that share a remediation, orders them P1/P2/P3 and names the concrete change to make;
`/findings` and markdown reports include the same summary. Scope is derived from the
request: a named target is authorization enough. Passive-only, intrusive and external
behavior follow plain-English switches (`passive`, `full`, `aggressive`, `offline`),
and a manual scope file is still honored and never overwritten.

The active web pass covers more than headers and CORS. In scope, it reviews client
JavaScript bundles for committed credentials, path traversal and local file disclosure,
error-based SQL injection, command injection (arithmetic echo plus an intrusive timing
check), SSRF against cloud metadata endpoints, CRLF and Host header injection, login
forms that submit credentials over GET/HTTP or lack CSRF protection, and default
administrator credentials with login-throttling checks. Default-credential and timing
checks require both `allowIntrusive` and an explicit `full`/`aggressive` request; the
ordinary pass is read-only and sends one request per payload. The credential check is
limited to three well-known default pairs, and the throttling check uses only a
non-existent account name - there is no credential dictionary. Every detected issue
arrives with a concrete remediation, and the `FIXES` plan groups related issues into
P1/P2/P3 actions.

### Context and resume

Each successful or aborted agent turn is written to a per-workspace session file under
`<dataDir>/sessions/`. Source reviews are also folded into `AGENTS.md`, so a fresh
process remembers what was already inspected. Every turn ends with its session id and
the exact command to continue: `$ argus resume -session ses-...`. That command
reopens the recorded workspace, reloads the last objective, targets, verified findings,
gaps and next steps, and asks the agent to continue from the captured state. Inside the
TUI, `continue`, `resume`, `keep going` or `carry on` do the same thing without leaving
the process. The agent is told to call `get_findings` or `list_runs` before repeating a
completed scan. Session notes are untrusted historical data, never evidence, and
credentials are redacted before they are written.

`/dashboard` visualises what has been found so far: a weighted risk gauge, severity
and category bars, confidence split, probe coverage per phase, the dependency graph,
outdated direct packages, a prioritized fix plan and the finding list. It uses the live
session findings, or loads the most recent stored run. Bars are plain ASCII gaugessuch as `[=========-----]` with percentage labels and `+` / `!` status markers; no emoji,
hashtags or Nerd Font glyphs are required.

Dependency inventory is built locally from `package.json`, `package-lock.json`,
`bun.lock`, `requirements.txt`, `go.mod`, `Cargo.toml`, Maven and Gradle manifests.
The dashboard shows direct and transitive node counts, graph edges and a compact tree.
When the scope allows external intelligence, direct npm packages are compared with the
npm registry and version drift becomes a low/info finding with an upgrade command. With
`allowExternal: false`, the graph is still built and the latest-version check is marked
skipped; Argus never bypasses the scope to reach the registry.

## Scope

There is no setup step. Name the target in plain English and Argus derives the active
scope from that sentence:

```text
check example.com
scan the whole code base
review C:\work\api for auth bugs
full assessment of staging.example.com and its subdomains
```

Argus writes the derived scope to `scope.json` (or `scope.prompt.json` when an operator
file already exists) and updates it as new targets are named. `prompt` mode is active
by default; say `passive`, `read-only` or `offline` to suppress active requests, or
`full`, `aggressive` or `intrusive` to widen checks. `no external` disables registry,
OSV and subdomain intelligence.

A manual scope file is still supported and is never overwritten:

```json
{
  "version": 1,
  "name": "Example authorized assessment",
  "authorizedBy": "Security Team",
  "authorizationRef": "TICKET-SEC-0001 / signed rules of engagement",
  "expiresAt": "2026-12-31T00:00:00.000Z",
  "allow": ["https://staging.example.com", "*.example.com", "10.0.0.0/24"],
  "deny": ["https://example.com/account/delete"],
  "maxRps": 20,
  "allowedPorts": [80, 443],
  "allowActive": true,
  "allowIntrusive": false,
  "allowExternal": false
}
```

`--scope <file>` uses that file strictly. Without it, the target you name is the scope.
Cloud metadata endpoints remain hard-blocked and deny rules still win for a manual
scope; those are safety boundaries, not configuration puzzles.

## CLI

```bash
argus init [--force]
argus authorize [--accept <name> | --revoke | --status]
argus scope init [path]
argus scope validate scope.json [target]
argus scan <target> [--scope scope.json] [--profile deep] [--retries 2]
argus resume --session <id>
argus tools [--json]
argus runs [--json]
argus report <runId> [--format md|json|sarif|csv|html] [--stdout]
argus mcp serve | tools | call <server> <tool> [json]
argus connectors list | send <runId>
argus config show | path
```

## Assessment pipeline

Every run is reported through the same stages, and the state is derived from real
evidence rather than declared:

```
vulnerability discovery  -> candidate findings
dynamic validation       -> validated reports (evidence + confirmed/likely)
exploitability           -> confirmed impact (and LPEs when the surface is local)
patch generation         -> candidate patches (never applied)
human researchers        -> final review gate
```

Candidate patches are concrete for validated repository findings: each carries the
file, the line and the exact change, with a one-line unified diff where the fix is
mechanical (for example `innerHTML -> textContent`, `privileged: true -> false`).
Rules that need design work are listed as file/line instructions instead of invented
code, and nothing is written to disk.

`/pipeline [runId] [--all]` prints the stages for a stored run, the dashboard shows
a compact summary, and the markdown/JSON/HTML/SARIF reports include the full block.
Findings that never reach validation stay labelled as candidates.

### Skill packs and traffic history

Two capabilities come from the open-source agentic-pentest landscape (Strix, PentAGI,
CAI): a per-class playbook the agent loads on demand, and structured access to the
traffic it already produced.

`load_skill` returns a concrete, non-destructive playbook for one vulnerability class -
IDOR, SQL injection, XSS, SSRF, authentication, JWT, path traversal, command
injection, file upload and secrets - with the smallest proof, the differential that
confirms it, and what not to touch. The playbooks live in `src/core/skills.ts`; aliases
such as `bola`, `rce`, `lfi` and `blind sqli` resolve to the same pack. A skill is a
plan, never evidence: the finding still needs a tool-observed reproduction and
`report_finding`.

`browser` drives a Chrome, Edge or Chromium that is already installed on the
machine, over its DevTools protocol - no Playwright dependency and no browser
download. Actions are `open`/`navigate`, `snapshot` (title, visible text, links,
forms, buttons), `click`, `type` (with optional submit), `screenshot` (PNG inside
the workspace) and `evaluate`. This is the authenticated-UI path: log in, walk a
JS-rendered route, then record what only the browser can see. URLs go through the
same prompt-scope host check as `http_request`, `ARGUS_BROWSER` can point at a
specific executable, and the process is closed at the end of every turn. The
`playwright`, `chrome` and `headless` aliases resolve to the same tool.

Findings accept CVSS. `report_finding` takes `cvss` as a v3.1 vector or a 0-10
score; base, temporal (`E`/`RL`/`RC`) and environmental (`CR`/`IR`/`AR` and the
modified metrics) scores are computed locally (`src/core/cvss.ts`), stored on the
finding, shown in `get_findings`, and rendered in the markdown and HTML reports.
Severity, confidence and the risk score are unchanged - CVSS is an additional,
standardised number rather than a replacement.

`sandbox` runs offensive tooling in an opt-in Docker container instead of on the
host. It mounts the workspace at `/work`, turns the network off by default, adds
`NET_RAW`/`NET_ADMIN` and `host.docker.internal` only when a network is requested,
and bounds container logs and PIDs so a runaway tool cannot take the machine down.
`status` reports Docker and the image, `pull` is an explicit (confirmed) action,
and `exec` is permission-gated like `run_command`. The image defaults to
`kalilinux/kali-rolling` and can be set with `ARGUS_SANDBOX_IMAGE` or per call.

`wsl` uses a real WSL distribution when Argus runs on Windows, so the host's own
Kali toolchain is available without Docker. `status` reports WSL availability,
every installed distro and whether Kali is present; `exec` runs any command inside
the Kali distro (nmap, sqlmap, nuclei, ffuf, impacket, netexec, msfconsole, or an
`apt-get install` of something missing) as the operator's WSL user. Set `root: true`
when a command must install packages or run privileged tooling; then the command runs
as root inside the distro without a sudo prompt. There is no fixed tool list - the
agent installs whatever the mission needs and uses it. `install` runs
`wsl --install -d kali-linux` only after the install approval prompt. Kali is
detected by name (`kali-linux` first, then any distro containing "kali"), a distro
can be forced per call, and `ARGUS_WSL_DISTRO`/`ARGUS_WSL` override the default and
the `wsl.exe` path. WSL commands share the operator's privileges, so the prompt
scope - not a container - is what bounds which hosts they may touch.

While an agent turn runs, the right-hand `LIVE` panel shows a `TERMINAL` section with
stdout/stderr streamed from `run_command` and `wsl exec` as the process writes it, so
a long nmap, sqlmap or install run is visible instead of arriving only at the end.
The full output is still returned to the model. The tail keeps the last lines; the
complete text stays in the tool result and the transcript.

The agent gets a dedicated scratch folder, `argus-workspace/`, created inside the
project on the first turn. Its system prompt tells it to keep scripts, wordlists,
payloads and generated artifacts there in subfolders (`recon/`, `payloads/`,
`notes/`) instead of dropping scratch files at the project root. The folder is inside
the authorized workspace root, so reads, edits and command `cwd` work there without a
second permission, and it can be inspected or deleted like any project directory.
`ARGUS_SCRATCH_DIR` renames it.

`/vim [file]` and `/terminal [command]` open a real interactive PTY inside Argus,
rendered with OpenTUI's embedded terminal: vim (Kali's vim through WSL when it is
installed, otherwise the host's), less, msfconsole or a plain login shell all get
full keyboard input, colours and resizing. While the terminal is focused every key
belongs to the program, so Enter, Esc and arrows work exactly as they do in a normal
terminal; leave the program (`:q`, `exit`) to return to Argus. `ctrl+shift+q` closes
the panel as an emergency escape.

`proxy` starts a loopback intercepting proxy (`http://127.0.0.1:<port>`). Point
curl, a scanner or the browser at it, then read `history`, and with `intercept`
on held requests wait for `allow` (which can rewrite the URL, headers or body) or
`drop`. Plain HTTP is fully inspectable; HTTPS is tunnelled with `CONNECT` and
recorded as metadata only - Argus does not install a CA or decrypt TLS. The
proxy stops with the turn, and captures stay in memory.

`vuln_lookup` researches packages and toolchains: it queries OSV.dev (no key) for a
package/version in npm, PyPI, crates.io, Go, Maven, NuGet, Packagist, RubyGems,
Hex, Pub or SwiftURL, and returns published advisories with CVE aliases, CVSS
vectors and fixed versions. `packagesFromLockfile` extracts `package@version`
pairs so a lockfile audit is one pass, not guesswork from model memory.

`export_report` writes a report for the current (or a named) run. `format:
"research"` is the narrative deliverable: executive summary, engagement facts,
validation state, supply chain, per-finding evidence and CVSS, coverage limits and
a finding index. It is also available as `argus report <runId> --format research`
and through MCP.

### Authorized-use agreement and operator mode

Before the first network assessment, the agent shows a one-time agreement: written
permission for every target you name, no third parties or cloud metadata, no
destructive or persistence actions, and responsibility for what runs. Accept it
once with `/authorize accept <your name>` in the TUI or
`argus authorize --accept <your name>` from a shell; `--status` shows the record
and `--revoke` removes it. Acceptance is stored locally in
`<dataDir>/authorization.json` with a timestamp and turns on operator mode: local
writes, shell, installs, network and subagents run without confirmation prompts,
and the agent is told the agreement is in force. It does **not** widen scope — a
host you did not name is still refused, and read-only instructions still win.

Aggression is a setting, not a mystery: saying "do anything", "full hands",
"ruthless" or "no confirmation" switches the run to the auto approval policy
(write/shell/install/network/agents), while the prompt-scope guard and deny rules
still decide which hosts are reachable. The agent is told to chain tools, install
what it needs, run offensive tooling in the sandbox or WSL, push confirmed weaknesses
to real impact, and finish with the research report. It works toward the goal rather
than a checklist: scans are only the map, and it keeps going until the goal is reached
or a concrete blocker is named.

Every tool call is recorded automatically in an attack journal (tool, target or
package, and whether it worked). Confirmed breaks are pushed to `report_finding` the
moment they happen, and the research report appends a journal section listing tools
used, surfaces/packages touched and every attempt with its result - so the deliverable
names exactly what made the target break, not just the final finding count.

`recall` is local vector memory: verified notes and recorded findings are
indexed with hashed TF-IDF vectors and searched by cosine similarity. It is
lexical, not an embedding service, and a hit is a lead from earlier work rather
than new evidence.

`http_history` is the session's traffic record. Every `http_request` result is stored
with method, URL, host, path, status, size, duration and content type, and the tool
serves either a filtered list (host, status, method, substring, limit) or a per-host
sitemap of observed endpoints. It prevents blind re-firing of requests and gives the
model the endpoint map that a proxy-backed agent gets from its intercepting proxy. It
is in-memory for the session, not a capture file.

The agent drives the same pipeline. It works the kill chain
(map -> hypothesize -> probe -> validate -> exploit -> patch), and `report_finding`
records a reproduced vulnerability on the current run so it gets a real finding id,
appears in `get_findings`, `/pipeline` and the reports, and can be cited in the final
answer. After a scan the loop enforces one continuation when candidates are still
unvalidated or no exploit path was attempted, instead of accepting the first scan
as the answer.

## Output

Each run is stored under `<dataDir>/runs/<runId>/` with `run.json`, `events.jsonl`,
`findings.jsonl` and reports. `dataDir` defaults to `~/.argus` and can be overridden
with `argus.config.json` or `ARGUS_DATA_DIR`.
