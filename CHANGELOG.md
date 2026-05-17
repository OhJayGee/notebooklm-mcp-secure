# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2026.3.9] - 2026-05-17

### Docs — bring all user-facing surfaces in line with v2026.3.8

v2026.3.7 (`NLMCP_AUTH_KEEP_ENV`) and v2026.3.8 (`NLMCP_STDIO_TRANSPORT
_AUTH`) shipped the code fix but only updated `CHANGELOG.md`. Anyone
following `README.md`, `SECURITY.md`, or the operator banner the
server prints on first-run token generation would still land in the
chicken-and-egg those releases closed. This release closes that
documentation gap.

**Per-site map:**

- `README.md`:
  - "With Authentication + Gemini (Recommended)" Claude Code example
    — switch from `NLMCP_AUTH_ENABLED=true` to
    `NLMCP_STDIO_TRANSPORT_AUTH=true`, with a one-paragraph
    explanation of why both env vars are needed
  - New "MCP auth modes (stdio)" reference section (table covering
    the four modes: default per-call / stdio transport-auth admin /
    stdio transport-auth read / legacy keep-env escape hatch) +
    trust-model rationale
  - Cursor JSON config example — same swap, plus link to the modes
    section
  - "Configuration" section env-var reference — expand from 2 lines
    to 6, covering all auth-related flags with their semantics
- `SECURITY.md`:
  - "Secure-by-Default Auth" feature-matrix row — mention the stdio
    transport-auth model
  - New "MCP Authentication → Trust model" subsection — explains the
    stdio-pipe-is-the-trust-boundary reasoning + the HTTP/SSE
    counterpoint (anyone-on-network → per-call mandatory)
  - New "MCP Authentication → Modes" subsection — same four-mode
    table as README, mirrored for the security-audience reader
  - Update the auto-generated-token printed-banner example to show
    the new format (NLMCP_STDIO_TRANSPORT_AUTH in the recommended
    config block)
  - Claude Code Configuration example — swap to transport-auth +
    note about the optional read-only-scope downgrade
  - Rate Limiting note — clarify that lockouts are bypassed in
    transport-auth mode (no per-call token validation = nothing to
    lock out on)
  - Quick Start example — swap to transport-auth, add `--` separator
    that was missing
- `src/auth/mcp-auth.ts` (`printTokenInstructions()`):
  - The TTY-mode operator banner the server prints when it auto-
    generates a token now shows the `NLMCP_STDIO_TRANSPORT_AUTH=true`
    recommendation alongside `NLMCP_AUTH_TOKEN`, and the example
    `claude mcp add` invocation includes both flags
  - Pointer line `Why both env vars? See README → MCP auth modes
    (stdio).` so operators know where to read the trust-model writeup
- `AGENTS.md`:
  - New "MCP auth modes — how the token reaches the server"
    subsection in the trust-boundaries area — distinguishes "which
    tools require auth" (the existing scope-classification rule) from
    "how the MCP client authenticates per call" (the new
    transport-auth mode)
  - Pointer to the short-circuit location in
    `MCPAuthenticator.validateTokenScope()` with a warning to
    preserve its ordering relative to the lockout check
  - Explicit "always prefer transport-auth for new stdio deployments"
    so future agent sessions don't recommend the legacy keep-env
    escape hatch by default

**Not touched.** `docs/SECURITY_IMPLEMENTATION_PLAN.md` (historical
planning doc) and `docs/security-reviews/*.md` (verbatim external
reviewer reports) are left as-is.

### Build

- `dist/` rebuilt (banner change in src/auth/mcp-auth.ts).
- `npx tsc --noEmit` — clean.
- Test count: **853** (unchanged — docs-only release).

---

## [2026.3.8] - 2026-05-17

### Stdio transport-auth — a principled fix for the stdio-auth gap

v2026.3.7 introduced `NLMCP_AUTH_KEEP_ENV` as a quick fix: keep
`NLMCP_AUTH_TOKEN` in `process.env` so the per-call fallback at
`src/index.ts:446` resolves to the configured token. It works, but
leaves the bearer token sitting in the subprocess env for the lifetime
of the process — visible to any `spawn()` inheritance, any diagnostic
dump of `process.env`, any third-party library that reads env.

This release adds the principled alternative: **the parent process
proves knowledge of the token at startup, the server records that the
stdio connection is trusted, scrubs the env unconditionally, and the
per-call auth check short-circuits to authenticated.** The threat model
matches reality: for stdio transport, the pipe between parent and child
IS the trust boundary — only the spawning parent can write to that FD,
and re-validating a token per call adds no security against any
attacker the design defends against.

**New env flags:**
- `NLMCP_STDIO_TRANSPORT_AUTH=true` — opt in to the trusted-stdio
  model. Requires `NLMCP_AUTH_TOKEN` to be present at startup (init
  refuses otherwise). Requires `NLMCP_AUTH_DISABLED=true` to NOT be
  set (init refuses otherwise). Default scope: admin.
- `NLMCP_STDIO_TRANSPORT_AUTH_SCOPE=read` — optional downgrade. Trust
  the connection but pin to read-only scope; admin-scope tool calls
  are rejected with `insufficient_scope`. Valid values: `admin`
  (default) or `read`. Init rejects any other value.

**Trust model.** With `NLMCP_STDIO_TRANSPORT_AUTH=true`:
- At `initialize()`: env token is hashed (validation pre-condition),
  trust flag is set in-memory, both `NLMCP_AUTH_TOKEN` and
  `NLMCP_AUTH_READONLY_TOKEN` are deleted from `process.env`.
- On every subsequent tool call: the auth check short-circuits at the
  start of `validateTokenScope()`, returning `{ valid: true, scope:
  <configured> }` without inspecting the per-call token argument.
- The trust flag is in-memory only; it dies with the process. A
  restart re-runs init and re-validates that the parent still has the
  token.
- `NLMCP_AUTH_KEEP_ENV` is overridden: transport-auth scrubs env
  unconditionally because the trust no longer depends on the env-var
  fallback surviving.

**Relationship to v2026.3.7's `NLMCP_AUTH_KEEP_ENV`.** Both flags
remain functional. Stdio deployments SHOULD prefer
`NLMCP_STDIO_TRANSPORT_AUTH` — same operational fix without the
env-leak surface. `NLMCP_AUTH_KEEP_ENV` is retained as an escape hatch
for unusual deployments (e.g., a custom stdio MCP client that does
inject `_meta.authToken` but wants env-fallback for debugging).

**Per-site map (src/auth/mcp-auth.ts):**
- New private fields on `MCPAuthenticator`: `connectionTrusted: boolean`
  and `connectionTrustedScope: MCPAuthScope`.
- `initialize()`: new validation block at the top — reject misconfig
  combos with clear errors. Token-loading branch now scrubs env
  unconditionally when transport-auth is on (overriding keepEnv).
- `validateTokenScope()`: new short-circuit after the lockout check,
  honouring the scope-downgrade pin.

**Tests added (`tests/mcp-auth.test.ts`):** 8 new tests covering:
- env scrubbed AND `connectionTrusted` set when flag enabled
- transport-auth wins over keep-env (env still scrubbed)
- SCOPE=read pin allows read-scope calls, rejects admin-scope calls
  with `insufficient_scope`
- explicit SCOPE=admin works identically to default
- flag without token → init throws (clear error message)
- flag with auth disabled → init throws (clear error message)
- invalid SCOPE value → init throws (clear error message)
- flag unset → connectionTrusted stays false, per-call auth required

**Deployment migration.** For users on v2026.3.7 with
`NLMCP_AUTH_KEEP_ENV: "true"`, swap to:

```json
"env": {
  "NLMCP_AUTH_TOKEN": "...",
  "NLMCP_STDIO_TRANSPORT_AUTH": "true"
}
```

For cautious deployments wanting read-only scope:

```json
"env": {
  "NLMCP_AUTH_TOKEN": "...",
  "NLMCP_STDIO_TRANSPORT_AUTH": "true",
  "NLMCP_STDIO_TRANSPORT_AUTH_SCOPE": "read"
}
```

### Build

- `dist/` rebuilt against current `src/`.
- `npx tsc --noEmit` — clean.
- Test count: **845 → 853** (+8 new tests).

---

## [2026.3.7] - 2026-05-17

### Fix — stdio MCP clients can finally authenticate

**The problem this fixes.** The README documents an `env`-block deployment
pattern for stdio MCP clients (Claude Code, Codex CLI, Claude Desktop):

```json
"env": { "NLMCP_AUTH_TOKEN": "..." }
```

The server's request handler at `src/index.ts:446` falls back to
`process.env.NLMCP_AUTH_TOKEN` when the per-call `_meta.authToken` is
absent — which it always is from naive stdio clients, since the MCP
protocol has no standard mechanism for a client to attach a bearer
token to each tool call over stdio.

But `mcp-auth.ts:155` (I236 — "credential isolation") deleted
`process.env.NLMCP_AUTH_TOKEN` during `initialize()`, which the server
calls at startup. By the time any tool call arrived, the env var was
gone, the fallback returned `undefined`, and every authenticated call
failed with `"Authentication required"`. The two halves of the design
contradicted each other.

In practice this meant: **the entire admin-tool surface (`setup_auth`,
`re_auth`, all mutating ops) was unreachable from Claude Code with auth
enabled, including the bootstrap `setup_auth` call required to do the
initial Google login.** `NLMCP_AUTH_DISABLED=true` did not rescue it,
because `index.ts:454` and `mcp-auth.ts:457` force admin-scope auth
even when auth is globally disabled.

This is a latent bug in this fork's full lineage (visible in
`@pan-sec/notebooklm-mcp@2026.3.3` as well) — never surfaced because
users either ran without auth (`NLMCP_AUTH_DISABLED=true` + read-only
use) or did the initial `setup_auth` from a custom MCP client that
forwarded `_meta.authToken`.

**The fix.** New env flag `NLMCP_AUTH_KEEP_ENV` (default `false`,
preserves the I236 scrubbing behaviour). When `true`, the three
`delete process.env.NLMCP_AUTH_TOKEN` / `NLMCP_AUTH_READONLY_TOKEN`
calls in `initialize()` are skipped, so the env-var fallback at request
time resolves to the configured token and per-call auth succeeds.

**Security tradeoff.** With the flag enabled, the token stays in the
server subprocess's env for its lifetime. Any subsequent `spawn()`
from inside that process inherits it; any diagnostic dump of `process
.env` includes it. The flag is opt-in precisely because some deploy-
ments (HTTP/SSE servers behind a reverse proxy) genuinely don't need
the env-var fallback and benefit from the scrubbing. Stdio MCP
deployments where the server subprocess is fully under the user's
control (Claude Code spawning the server as a child) are the intended
audience for the opt-in.

**Per-site map (3 sites in `src/auth/mcp-auth.ts`):**
- `initialize()` token branch — `delete process.env.NLMCP_AUTH_TOKEN`
  now `if (!keepEnv) delete …`
- Same branch's readonly-token sub-clause — same conditional
- Standalone readonly-token branch — same conditional

**Tests added (`tests/mcp-auth.test.ts`):**
- Default behaviour preserved: `NLMCP_AUTH_TOKEN` scrubbed from env
  after `initialize()`
- `NLMCP_AUTH_KEEP_ENV=true` keeps it, and a subsequent
  `validateToken` call succeeds
- `NLMCP_AUTH_KEEP_ENV=true` also preserves
  `NLMCP_AUTH_READONLY_TOKEN`
- `NLMCP_AUTH_KEEP_ENV=false` (explicit) behaves identically to the
  default (env scrubbed)

**Deployment migration.** Existing `~/.claude.json` / `.codex/...`
entries that already include `NLMCP_AUTH_TOKEN` in their `env` block
need one additional key:

```json
"env": {
  "NLMCP_AUTH_TOKEN": "...",
  "NLMCP_AUTH_KEEP_ENV": "true"
}
```

Without this, the server starts and the MCP handshake (`initialize`,
`list_tools`) succeeds, but every actual tool call returns the
`"Authentication required"` error.

### Build

- `dist/` rebuilt against current `src/`.
- `npx tsc --noEmit` — clean.
- Test count: **841 → 845** (+4 new tests).

---

## [2026.3.6] - 2026-05-17

### Sanitizer-coverage follow-up to v2026.3.4 finding #11

v2026.3.4 finding #11 introduced `getSanitizedErrorMessage` (strips
absolute paths and stack-frame fragments before client-visible error
text leaves the process). v2026.3.5 wired it through the per-handler
early-return path in three handler files plus the compliance dispatcher.
This release closes the remaining client-visible sites so the invariant
"every code path that constructs a client-visible `error:` field from a
caught Error routes the message through `getSanitizedErrorMessage`"
holds repo-wide.

**Per-site map (8 sites across 3 files):**

- `src/compliance/health-monitor.ts` (6 sites) — `error` field in the
  `ComponentHealth` shape returned to the client by every health probe
  (data_directory, config_directory, audit_logging, compliance_logging,
  encryption, and the top-level per-check catch wrapper). Surfaced via
  the `run_health_check` compliance tool and the `get_health` MCP tool.
- `src/compliance/retention-engine.ts:384` — `result.error` returned by
  retention-policy execution and surfaced via the compliance retention
  tools.
- `src/webhooks/webhook-dispatcher.ts:634` — `delivery.error` recorded
  on each webhook delivery attempt and surfaced via webhook status
  tools. The cause-chain walk used for DNS-pattern retry classification
  remains unsanitised (internal-only, never returned to the client) and
  is annotated as such.

**Tests added (`tests/v2026.3.6-sanitizer-fixes.test.ts`):**

- Source-grep coverage that every affected file imports the helper and
  contains no leftover raw `error instanceof Error ? error.message :
  String(error)` pattern feeding a client-visible field.
- One end-to-end runtime test that invokes `handleComplianceToolCall`
  against a stubbed `getDashboardCLI` that throws an Error containing
  both an absolute path and a stack-frame fragment, and asserts both
  the returned TextContent text AND the audit-log argument have been
  stripped to `[path]` with no `at func (file:line:col)` remnant.

The misfiled `V2026.3.4 follow-up` describe that landed in
`tests/external-review-round3-fixes.test.ts` in the in-flight v2026.3.5
work has been relocated to the new file above.

### Build

- `dist/` rebuilt against current `src/`.
- `npx tsc --noEmit` — clean.
- Test count: **837 → 841** (+4 net).

---

## [2026.3.5] - 2026-05-10

### Whole-Repo External Review (Round 4) — Three independent reviewers

Three independent reviewers ran the toned-down Template 2 prompt
against the v2026.3.4 codebase. Verbatim reports preserved in
`docs/security-reviews/`:

- `CLAUDE-FULL-REVIEW-V2026.3.4.md` (Claude Opus 4.7) — 5 findings
- `CODEX_FULL_FINDINGS-V2026.3.4.md` (Codex GPT-5) — 2 findings, both
  pre-addressed by Codex itself before this release
- `GEMINI31Pro_FULL_FINDINGS-V2.md` (Gemini 3.1 Pro) — 3 findings,
  including one CRITICAL SSRF in audio download

After deduplication, **8 distinct findings** ship in v2026.3.5. All
addressed below with regression tests pinning each fix.

**By the numbers:**
- Tests: **804 → 837** (+33 regression tests in
  `tests/external-review-round4-fixes.test.ts`)
- `npx tsc --noEmit` — clean
- `npm audit` — 0 high/critical vulnerabilities

### Security — Critical / High Findings

- **CRITICAL — AudioManager SSRF via `page.goto` on scraped URL**
  (Gemini #1, conf 10). `audio-manager.ts:downloadAudio` previously
  passed a URL scraped from the NotebookLM page DOM (a download
  button's `href` or an `<audio src>`) directly to `page.goto`. A
  prompt-injection chain through a malicious source document the
  user added to a notebook could plant `<a download href="file:///
  etc/passwd">` and the authenticated browser would navigate the
  Playwright context to it, reading the local file into
  `response.body()` for the attacker to retrieve. Cloud-metadata
  SSRF (`https://169.254.169.254/`) was equally reachable.
  Fixed: new shared `src/utils/url-validation.ts` module exporting
  `validateNotebookLMMediaUrl(url)` that enforces (a) HTTPS only,
  (b) no private/loopback/link-local IP, (c) hostname suffix on a
  hard-coded NotebookLM media-download allowlist (`*.google.com`,
  `*.googleusercontent.com`, `*.googleapis.com`). Called immediately
  before `page.goto(downloadInfo.url)`.

- **HIGH — AuditLogger hash-chain concurrency race** (Gemini #2,
  conf 10). Pre-fix, `log()` captured `this.previousHash` before
  enqueueing the event. Two concurrent `log()` calls would both
  read `previousHash = X`, compute hashes against the same
  predecessor, and write events whose hashes branched rather than
  chained. `verifyIntegrity()` reported the resulting break as
  tampering. Fixed: hash + previousHash are now stamped INSIDE
  `flushEvent` under the per-day file lock, so the chain link
  reflects actual write order regardless of how many `log()` calls
  are in flight. Two regression tests in the new round-4 file
  exercise a 25-event burst and assert chain verification + per-
  event predecessor linkage.

### Security — Medium Findings

- **MEDIUM — Library mutations are audit-logged** (Claude L1, conf
  9). `add_notebook`, `update_notebook`, `remove_notebook`, and
  `select_notebook` are admin-scope tools that mutate persistent
  state which is itself a privilege boundary (URLs persisted in the
  library are later trusted for browser navigation). Pre-fix none
  of the four handlers called `audit.tool` despite every other
  admin-scope tool surface auditing. Fixed: each handler now emits
  `audit.tool(...)` with the notebook id and host (host only, never
  the full URL — same pattern as `recordWebhookChange`). Updates
  also record `url_host_before` / `url_host_after`. Removals
  record the closed-session count. Failed lookups still audit so
  probes for non-existent IDs are visible.

- **MEDIUM — Shutdown handler flushes audit + query loggers**
  (Claude L2, conf 8). Pre-fix, `src/index.ts:shutdown` called
  `process.exit(0)` after `server.close()` without awaiting
  `getAuditLogger().flush()` or `getQueryLogger().flush()`.
  `process.exit()` does NOT trigger `beforeExit` (Node docs
  explicit), so audit / query events queued in the final ms could
  be lost — a missing event silently breaks hash-chain verification
  on the next run. Fixed: shutdown now awaits both flushes (each
  wrapped in try/catch so a flush failure doesn't block the rest of
  the teardown) before `wipeGlobalCredentials()` and `process.exit`.

### Security — Low Findings

- **LOW — `alert-manager.ts` and `siem-exporter.ts` validate outbound
  URLs** (Claude L3, conf 8). Pre-fix both used `https.request`
  directly without applying the SSRF defence pipeline that
  `webhook-dispatcher.ts` got in v2026.3.4. Env-var trusted, so
  practical impact is small — but the codebase-consistency argument
  matters for a security-claiming fork. Fixed: both modules now
  call the new shared `validateOutboundUrlSync` helper before
  issuing the request; rejected URLs are logged and the delivery is
  soft-failed.

- **LOW — Quota state schema validation on load** (Claude L4, conf
  7). Pre-fix `quota.json` was loaded with `JSON.parse(data) as
  QuotaSettings` — no schema check, no integrity guard. A local
  user (or malware running as the user) could edit the file to
  reset `queriesUsedToday: 0` and bypass rate limits. Fixed: new
  `QuotaManager.isValidQuotaSettings(loaded)` static validator
  checks tier enum, limits structure, usage counter ranges (0 to
  1M / 10M ceilings), and ISO-format date fields. Records that
  fail validation fall through to `getDefaultSettings()` (the safest
  state) and a warning is logged.

- **LOW — `SettingsManager.saveSettings` serialised** (Gemini #3,
  conf 9). Pre-fix, two concurrent `saveSettings` calls could read
  the same `this.settings`, merge their respective deltas, and race
  on the final write — the second writer's merge could lose
  anything the first writer added. Fixed: new `saveQueue: Promise<
  void>` chain serialises the read-merge-write cycle, mirroring
  the pattern `WebhookDispatcher` uses for its JSON store.

- **LOW — `get_health.deep_check` requires
  `NLMCP_DEEP_HEALTH_ENABLED=true`** (Claude L5, conf 7). Pre-fix
  `get_health` was read-scope but `deep_check: true` spawned a real
  browser session and probed the chat UI — a side effect that
  doesn't belong in a read-scope tool. Fixed: the deep-check path
  is now gated on an explicit env-var opt-in
  (`NLMCP_DEEP_HEALTH_ENABLED=true`). Without it, `deep_check: true`
  is logged-as-warning and ignored. Makes the side effect visible
  in deployment configuration rather than hidden in an optional
  tool argument.

### Codex Round-4 Findings (Pre-addressed)

The Codex pass found two additional consistency gaps and addressed
them in the same run before reporting:

- **LOW — `handleComplianceToolCall` error sanitisation** (Codex
  #1, conf 9). The compliance dispatcher now routes its catch-block
  errors through `getSanitizedErrorMessage` so absolute paths and
  stack-frame fragments are stripped before they reach the MCP
  client.

- **LOW — `PathPolicyError` branches use the sanitiser** (Codex
  #2, conf 9). Every client-visible `PathPolicyError` return in
  `system.ts`, `audio-video.ts`, and `gemini.ts` now goes through
  `getSanitizedErrorMessage(err)` before being returned.

### Added

- **`src/utils/url-validation.ts`** — shared SSRF defence helpers
  (`isPrivateIPv4`, `isPrivateIPv6`, `isPrivateHost`,
  `validateOutboundUrl` async, `validateOutboundUrlSync`,
  `validateNotebookLMMediaUrl`). Factored from
  `webhook-dispatcher.ts` so the same defences can be applied
  uniformly to every outbound HTTP code path.
- **`tests/external-review-round4-fixes.test.ts`** — 33 regression
  tests organised by finding number with cross-references to the
  three round-4 review reports.

### Changed

- **`AuditLogger.flushEvent`** stamps `previousHash` and `hash`
  inside the file-lock critical section instead of in the
  pre-enqueue `log()` method. Public API unchanged.
- **`SettingsManager.saveSettings`** now returns a serialised promise
  via the `saveQueue` chain. Public API unchanged.
- **`QuotaManager.loadSettings`** validates the parsed record
  against a schema before trusting it.
- **`audio-manager.ts:downloadAudio`** validates `downloadInfo.url`
  through `validateNotebookLMMediaUrl` before `page.goto`.

## [2026.3.4] - 2026-05-10

### Whole-Repo External Review — Codex + Gemini 3.1 Pro

Two whole-repository review rounds (Codex + Gemini 3.1 Pro) using the
toned-down Template 2 prompt in `docs/security-reviews/REVIEW_PROMPT_TEMPLATE.md`
landed alongside this release. The verbatim reports live in
`docs/security-reviews/CODEX_FULL_FINDINGS.md` and
`docs/security-reviews/GEMINI31Pro_FULL_FINDINGS.md`. After
deduplication the two reviewers surfaced 11 distinct findings, all
confidence ≥ 8, all addressed below with regression tests pinning each
fix.

**By the numbers:**
- Tests: **777 → 806** (+29 regression tests in
  `tests/external-review-round3-fixes.test.ts`, plus
  `tests/tool-file-safety.test.ts` adjusted for the export_library
  realpath canonicalisation)
- `npx tsc --noEmit` — clean
- `npm audit` — 0 high/critical vulnerabilities

### Security — External Review Fixes

- **MEDIUM** — `list_webhooks` exposed credential-bearing webhook URLs
  (Slack / Discord / Teams embed secret tokens in the URL path) and
  any legacy persisted `secret` field to read-scope callers (Codex #2,
  conf 9). Fixed:
  - New `WebhookConfigPublic` DTO (id, name, host, format, events,
    enabled, hasSecret, retry settings, timestamps) — never the full
    URL or the secret value.
  - New `WebhookDispatcher.listWebhooksPublic()` returns the redacted
    DTO; the read-scope MCP `list_webhooks` handler now uses it.
  - On `loadStore()`, any persisted `secret` field is migrated into
    the in-memory `webhookSecrets` SecureCredential map and scrubbed
    from the persisted record. Cleaned store is re-persisted so
    subsequent loads see no plaintext secrets.
- **MEDIUM** — `run_health_check` (and other compliance tools that are
  not in `TOOL_NAMES`) defaulted to read-scope auth even though
  `run_health_check` writes a probe file to disk, logs a compliance
  event, and may dispatch outbound alert webhooks (Codex #3, conf 9).
  Fixed: new `COMPLIANCE_TOOLS_REQUIRING_AUTH` set in `src/index.ts`
  containing `run_health_check`. The auth gate now requires admin
  scope when the tool name is in EITHER `TOOLS_REQUIRING_AUTH` (for
  `TOOL_NAMES` members) OR `COMPLIANCE_TOOLS_REQUIRING_AUTH` (for
  compliance tools outside that union type).
- **MEDIUM** — MCP `resources/read`, `resources/list`,
  `resources/templates/list`, `completion/complete`, `prompts/list`,
  and `prompts/get` bypassed authentication entirely. The notebook
  library's IDs / names / descriptions / topics / use-cases / URLs /
  usage counts were reachable to any unauthenticated MCP caller
  (Codex #4, conf 10). Fixed: new `assertReadScopeAuthorized` helper
  in `src/resources/resource-handlers.ts` runs read-scope auth at the
  start of every registered resource / completion / prompt handler.
  When global auth is disabled the helper passes through.
- **MEDIUM** — `export_library` still used a local lexical
  `resolveExportPath()` helper instead of the shared
  `resolveExportFilePath` from `src/utils/path-policy.ts`, so writes
  could follow symlinked parents inside the export base (Codex #5,
  conf 10). Fixed: deleted the local helper, routed through the
  shared module. The local handler also now returns `data: null` on
  the rejection path to preserve the I330 error contract.
- **MEDIUM** — Gemini and chat-history responses bypassed
  `response-validator.ts` (only `ask_question` ran model output
  through the validator). A pattern that would be blocked when
  surfaced via NotebookLM round-tripped unsanitised when surfaced via
  Gemini (Codex #6, conf 8). Fixed: factored the validation block
  into a shared `applyValidationToModelOutput(text)` helper; applied
  to `deep_research`, `gemini_query`, `query_document`,
  `query_chunked_document`, and the per-message validation in
  `get_notebook_chat_history`. Each result type gained a
  `security_warnings?: string[]` field that surfaces detector hits.
- **LOW** — `close_session` and `reset_session` skipped
  `validateSessionId` (Gemini #2, conf 10). Fixed: `withSessionOp`
  now calls `validateSessionId` at the top and refuses any caller
  that fails the regex (`^[a-zA-Z0-9_-]+$`, max 64 chars).
- **LOW** — `deep_research` and `gemini_query` reimplemented
  validation inline (different empty/length rules from
  `validateQuestion`) (Gemini #3, conf 9). Fixed: extended
  `validateQuestion(question, maxLength?)` with an optional
  `maxLength` parameter; the deep_research handler passes 10000, the
  gemini_query handler passes 30000.
- **MEDIUM** — `gemini_query.urls` accepted `http://` and any other
  HTTPS-looking string via an inline `startsWith` check (Gemini #4,
  conf 10). Fixed: each url is run through `validateSourceUrl`
  (HTTPS-only + dangerous-scheme block).
- **MEDIUM** — `WebhookDispatcher` initialised env-driven webhooks
  asynchronously (DNS lookup) without holding the promise; events
  fired during the very first tick could miss their env-configured
  delivery target (Gemini #5, conf 9). Fixed: store the init promise
  in `initFromEnvPromise`, expose `whenInitialized()` for callers,
  and `await this.initFromEnvPromise` at the top of `dispatch()`.
  The MCP `list_webhooks` handler also awaits it before returning so
  a fresh-start `list_webhooks` call sees the env-configured set.
- **LOW** — `getSanitizedErrorMessage` in
  `src/tools/handlers/error-utils.ts` only stripped absolute paths;
  stack-frame fragments (`at funcName (file.ts:42:11)`) survived,
  contradicting the global MCP exception handler in `src/index.ts`
  which strips both (Gemini #6, conf 9). Fixed: copied the
  stack-frame regex into `sanitizeErrorMessage` so per-handler error
  paths get the same treatment.
- **MEDIUM** — `LOGIN_PASSWORD` and `GEMINI_API_KEY` were wrapped in
  `SecureCredential` but never `.wipe()`'d on shutdown (Gemini #7,
  conf 10). Fixed: new `wipeGlobalCredentials()` exported from
  `src/config.ts`; the shutdown handler in `src/index.ts` calls it
  on every signal path (SIGINT, SIGTERM, uncaughtException,
  unhandledRejection) — and on the error-recovery path within
  `shutdown()` itself.
- **LOW** — V2026.3.4 follow-up review found two residual
  client-visible error hygiene gaps (Codex follow-up #1-#2, conf 9):
  compliance tool failures stringified raw exceptions, and several
  `PathPolicyError` branches returned raw path-policy messages with
  host-specific absolute paths. Fixed: `handleComplianceToolCall`,
  `system.ts`, `audio-video.ts`, and `gemini.ts` now route these
  error paths through `getSanitizedErrorMessage`; two source-text
  regression tests pin the behaviour.

### Added

- **`tests/external-review-round3-fixes.test.ts`** — 27 regression
  tests pinning the 11 fixes above, organised by finding number with
  cross-references to the verbatim review reports.
- **`WebhookDispatcher.whenInitialized()`** — public helper for
  observers that need to wait for env-driven init.
- **`WebhookDispatcher.listWebhooksPublic()`** — redacted DTO list.
- **`applyValidationToModelOutput(text)`** in
  `src/utils/response-validator.ts` — shared helper for any handler
  that returns model-generated or page-scraped text.
- **`wipeGlobalCredentials()`** in `src/config.ts`.
- **`security_warnings?: string[]`** field on `DeepResearchResult`,
  `GeminiQueryResult`, `QueryDocumentResult`, the inline
  `query_chunked_document` result type, and the
  `get_notebook_chat_history` result type.

### Changed

- **`validateQuestion(question, maxLength?)`** now accepts a
  per-caller maxLength. Default is unchanged at 32000.
- **`tests/tool-file-safety.test.ts`** — the
  "allows export_library relative paths inside the export base" test
  now `realpathSync`-resolves its tmpdir to match the canonicalised
  path that `resolveExportFilePath` returns (macOS firmlinks
  `/var` → `/private/var`).

## [2026.3.3] - 2026-05-10

### Adversarial Security Review — High and Medium Findings Resolved

This release closes the findings from two independent adversarial reviews of the
codebase (one performed via this repository's `CLAUDE_REVIEW.md`, one via
`CODEX_REVIEW.md`). Both reviews converged on the same critical / high findings;
this release also picks up the medium and low findings that only one review
flagged. Marketing claims in `package.json` have been trimmed to honest scope at
the same time — see "Claims" section below.

**By the numbers:**
- Tests: **643 → 747** across 59 test files (+104 regression tests pinning every fix)
- `npx tsc --noEmit` — clean
- `npm audit` — 0 high/critical vulnerabilities

### Security — Vulnerabilities Patched

- **HIGH `get_notebook_chat_history` arbitrary file write via `output_file`** —
  the `output_file` parameter was passed to `fs.writeFile` with no path
  validation. Reachable from a *read-scope* MCP token (or with auth disabled),
  which let a prompt-injected MCP call overwrite e.g. `~/.ssh/authorized_keys`,
  `~/.zshrc`, or crontab files with attacker-influenced JSON. Routed through
  the new shared `resolveExportFilePath` (NLMCP_EXPORT_DIR / $HOME containment,
  dotfile + sensitive-dir denylist, `0o600` perms, `flag: "w"`). Tool also
  moved into `TOOLS_REQUIRING_AUTH` (admin scope).
- **CRITICAL Notebook URL poisoning of the library** — `add_notebook` /
  `update_notebook` accepted any URL and persisted it; later code paths
  (`ask_question`, `get_notebook_chat_history`) treated stored URLs as
  trusted and navigated the authenticated browser to them. Fixed by running
  `validateNotebookUrl` at every library write *and* defensively re-validating
  every persisted entry on `loadLibrary` (poisoned entries are dropped and the
  cleaned library is re-persisted).
- **CRITICAL sessionStorage written into attacker origin from poisoned URL**
  — `BrowserSession.restoreSessionStorage` derived its target origin from
  `this.notebookUrl`, so a poisoned library entry would cause the saved
  NotebookLM sessionStorage to be written into the attacker's origin where
  their page could read it back. Fixed: target origin is now pinned to a
  hard-coded NotebookLM allowlist (public static `NOTEBOOKLM_RESTORE_ORIGINS`
  for test pinning); the listener refuses to arm if `notebookUrl` itself is
  not on the allowlist.
- **CRITICAL `add_source` / `create_notebook` arbitrary local-file upload**
  — the `type:"file"` source path bypassed the allowlist/denylist that
  `add_folder` already had. A read-scope tool call could upload `~/.ssh/id_rsa`,
  cloud credential files, `.env`, etc. to NotebookLM. Fixed by routing every
  file source through the shared `assertSafeLocalReadPath`, which symlink-
  resolves and re-checks against the same denylist used by `add_folder`.
- **HIGH read-only token can mutate state and emit outbound requests** —
  `add_notebook`, `update_notebook`, `remove_notebook`, `select_notebook`,
  `create_notebook`, `batch_create_notebooks`, `sync_library`, `add_source`,
  `remove_source`, `generate_audio_overview`, `generate_video_overview`,
  `generate_data_table`, `set_quota_tier`, `close_session`, and `reset_session`
  were classified as read-scope. All moved into `TOOLS_REQUIRING_AUTH`. The
  read-scope set now contains only tools that read state.
- **HIGH `add_folder` symlink-bypass of denylist** — the lexical denylist
  check ran against the user-supplied folder path, but `scanDir` followed
  symlinks during traversal. An attacker who controlled a directory the user
  later passed could plant `evil/link → ~/.ssh` and exfiltrate keys. Fixed:
  `scanDir` now `realpath`-resolves every entry and re-checks against the
  shared denylist before recursing or uploading.
- **MEDIUM `download_audio` arbitrary write via `output_path`** — admin-gated
  but unbounded. Routed through the same `resolveExportFilePath` policy.
- **MEDIUM `upload_document` arbitrary local-file read** — admin-gated but
  unbounded. Routed through `assertSafeLocalReadPath`.
- **MEDIUM SecureStorage fails open to plaintext** — when encryption was
  disabled or no key was available, `save()` silently fell back to writing
  plaintext credential files. Now throws a `secure storage refusing to write
  plaintext for …` error and emits a `plaintext_save_refused` audit event,
  unless the operator explicitly opts in via
  `NLMCP_ALLOW_PLAINTEXT_CREDENTIAL_STORAGE=true`.
- **MEDIUM webhook SSRF only validated at config time** — DNS-rebinding
  could move a previously-validated host into RFC 1918 / cloud-metadata space
  before delivery. `sendWithRetry` now re-runs `validateWebhookUrl` at
  delivery time and refuses to call `fetch` if validation fails.
- **MEDIUM `updateWebhook` persisted secret to disk** — contradicted the
  explicit `// secret never persisted to disk` invariant honoured by
  `addWebhook`. Update path now writes `secret: undefined` to the persisted
  store and routes the new value through the in-memory `SecureCredential`
  map; clearing the secret wipes and removes the credential.
- **LOW auth tokens written to logs and stdout** — `printTokenInstructions`
  and the `token rotate` CLI both unconditionally printed the bearer token.
  Now TTY-gated: tokens print only when stderr/stdout is interactive,
  otherwise written to a `0o600` file with only the path logged. Override
  available via `NLMCP_PRINT_TOKEN_TO_STDERR=true`.
- **LOW `validateFilePath` `startsWith` containment bug** — accepted
  `base="/tmp/base"` + `resolved="/tmp/base-evil/file"` because the prefix
  check was true. Replaced with `path.relative(base, resolved)` containment.
- **LOW auth-failed response broke I330 contract** — when a tool failed
  authentication, the response body omitted `data: null` and
  `structuredContent`. Now the auth-failure body matches every other
  error path.

### Security — Supply-Chain Hardening

- **Patchright pin tightened** — `patchright` and `patchright-core` added
  to `overrides` so the transitive resolution cannot drift away from the
  reviewed `1.57.0` tarball.
- **CI pins are enforced** — new `scripts/check-exact-pins.cjs` fails the
  build if any direct dep in `dependencies` / `devDependencies` /
  `peerDependencies` uses a range specifier (`^`, `~`, `>=`, `*`, `latest`).
- **CI signature verification** — `npm audit signatures` runs on every
  build, catching a compromised mirror or maintainer-key takeover before
  the dep gets baked into a build.
- **CI vulnerability ratchet** — `npm audit --audit-level=high` now fails
  the build on any known high or critical CVE in the dep tree.
- **CI lockfile-drift detection** — `git diff --exit-code package-lock.json`
  after `npm ci` fails the build if the lockfile is out of sync.
- **Dockerfile `--ignore-scripts` everywhere** — both the builder and
  runtime stages now use `npm ci --ignore-scripts`, defeating the standard
  install-script attack class. The browser install (`npx patchright install
  chromium`) is the only sanctioned lifecycle step.
- **Documented chromium-binary mitigations** — the Dockerfile now spells
  out the supply-chain levers for the chromium download (`PATCHRIGHT_DOWNLOAD_HOST`,
  `PATCHRIGHT_SKIP_BROWSER_DOWNLOAD`, COPY-from-base-image patterns).

### Added

- **`src/utils/path-policy.ts`** — single source of truth for filesystem
  path containment and credential-directory denylist. Three exports:
  `resolveExportFilePath`, `assertSafeLocalReadPath`, `resolveAndCheckFolderPath`,
  plus `isDeniedReadPath` for per-entry recursive checks. Denylist now
  covers macOS / Windows credential paths the previous per-handler
  implementations missed (`Library/Application Support/Google/Chrome`,
  `.config/op`, `.config/Code/User`, `.cargo/credentials`, …).
- **`scripts/check-exact-pins.cjs`** — pin-enforcement gate for CI.
- **104 regression tests across 7 new files** — `path-policy.test.ts`,
  `library-url-validation.test.ts`, `session-manager-url-validation.test.ts`,
  `sessionstorage-origin-pin.test.ts`, `webhook-security-fixes.test.ts`,
  `crypto-fail-closed.test.ts`, `auth-scope-classification.test.ts`. Plus
  five new `validateFilePath` tests appended to `security.test.ts`.
- **`AGENTS.md`** — single source of truth for AI-agent project memory.
  Documents threat model, trust boundaries, how to add a new tool /
  persisted store, path-policy usage rules, credential lifecycle,
  fail-closed crypto invariant, audit-log conventions, supply-chain
  rules, fork lineage, and common foot-guns. The thin pointer files
  `CLAUDE.md`, `GEMINI.md`, and `CODEX.md` exist so each tool's
  auto-loader finds something — they all delegate to `AGENTS.md`.
- **`docs/security-reviews/`** — verbatim review reports moved out of
  the repo root, indexed by `docs/security-reviews/README.md`. The
  reusable prompt templates (module-scoped + whole-repo) live in
  `docs/security-reviews/REVIEW_PROMPT_TEMPLATE.md` and have been
  drafted to avoid offensive-security keywords that trip safety
  classifiers on the more aggressive reviewers.

### Changed

- **`BrowserSession.NOTEBOOKLM_RESTORE_ORIGINS`** promoted from
  `private static` to `public static readonly` so the regression test can
  pin its contents. Set is still immutable; only the visibility changed.
- **`add_folder` `resolveFolderPath`** delegates to the shared
  `resolveAndCheckFolderPath` instead of duplicating the allowlist /
  denylist logic.

### Removed

- **`Dockerfile`, `.dockerignore`, `smithery.yaml`** — moved out of the
  repo to a sibling archive (`<parent-dir>/notebooklm-mcp-secure-archive/
  docker-deploy/`) on 2026-05-10. The fork is now stdio-only; Docker
  adds no security benefit for local subprocess use, and Smithery's
  hosted path would need an HTTP-transport variant of the server we
  don't ship. The artifacts are kept (out-of-repo) so a future
  hosted-deployment effort can reuse them as a starting point.

### Security — External Review Findings Addressed

After v2026.3.3's initial path-policy module landed, the same toned-
down review prompt was run against two further reviewers (Codex and
Gemini). They converged on nine real findings, all addressed below
with regression tests pinning each fix.

**Tests: 747 → 775 (+28 regression tests pinning every external finding)**

- **HIGH symlink in export base lets writes escape**
  (`resolveExportFilePath`). Pre-fix, the lexical containment check
  did not realpath-resolve intermediate symlinks. An attacker who
  could plant a symlink inside the export base — e.g. `<base>/escape →
  ~/.ssh` — could make a chat-history export write `<base>/escape/
  authorized_keys`, which `fs.writeFile` followed through the symlink
  to land at `~/.ssh/authorized_keys`. Fixed: both the export base
  AND the candidate's parent directory are now `realpath`-resolved
  before containment, the resolved parent is re-checked for both
  containment and denylist membership, and an existing symlink at the
  leaf path is refused outright (no write-through-symlink).

- **MEDIUM `add_folder` symlinks bypassed the allowlist** (only the
  denylist was re-checked per entry). An attacker who controlled a
  directory the user later passed could plant `evil/link → /tmp/
  outside/leak.md` and `add_folder` would upload the out-of-allowlist
  target because `/tmp/outside` happens not to match any denied
  segment. Fixed: new `assertSafeFolderEntryPath(realTarget,
  allowedBases)` enforces both the allowlist AND the denylist on every
  symlink-resolved entry; `scanDir` calls it before stat'ing.

- **MEDIUM read policy accepted non-regular files**
  (`assertSafeLocalReadPath`). A FIFO at `/tmp/trap.pdf`, a character
  device at `/dev/zero`, or a UNIX socket all passed the policy check
  and could cause the upload layer to hang, consume entropy, or
  block. Fixed: the helper now requires the path to exist, resolve
  via `realpath`, and stat as a regular file. `/dev`, `/run`,
  `/var/run` added to `DENIED_ABSOLUTE` as defence-in-depth.

- **HIGH case-insensitive denylist bypass** on macOS APFS / Windows
  NTFS. An MCP caller with `file_path: ".SSH/id_rsa"` or `output_file:
  ".ZSHRC"` would resolve to the same file as `.ssh` / `.zshrc` on
  case-insensitive filesystems while bypassing the literal-equality
  comparison. Both reviewers flagged this independently with confidence
  10/10. Fixed: every segment compared against the denylist is
  normalised through `policySegment` (NFC Unicode + lowercase + on
  Windows trailing-dot/space stripping). The denylist constants are
  pre-lowercased at module load.

- **MEDIUM Windows-specific basename quirks** were unhandled. NTFS
  alternate data streams (`.zshrc:hidden`), NTFS trailing-dot
  stripping (`.zshrc.`), and reserved device names (`CON`, `PRN`,
  `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`) all bypassed the basename
  denylist. Fixed: `policyBasename` strips alternate-stream
  specifiers, `policySegment` strips trailing `.` / space on Windows,
  and reserved device basenames are refused outright.

- **MEDIUM denylist missing modern credential stores.** Concrete
  additions: `.azure`, `.config/gh`, `.config/hub`, `.config/stripe`,
  `.config/Cursor`, `.config/Code - Insiders`, `.config/JetBrains`,
  `.github_token`, `.gem/credentials`, `.gradle/gradle.properties`,
  `.terraformrc`, `application_default_credentials.json`, the
  Library/Application Support equivalents on macOS, the AppData/
  Roaming equivalents on Windows, plus
  `AppData/{Roaming,Local}/Microsoft/Credentials`.

- **HIGH `DENIED_ABSOLUTE` was Unix-only.** On Windows or for cross-
  mounted Windows volumes, `C:\Windows\System32\config\SAM`,
  `C:\Documents and Settings\…\NTUSER.DAT`, and similar were
  accepted. Fixed: Windows entries added (`C:\Windows\System32\
  config`, `C:\Windows\System32\drivers\etc`, `C:\Windows\repair`,
  `C:\Windows\security`, `C:\Documents and Settings`).

- **MEDIUM `.env` variants accepted.** Pre-fix, only the literal
  basename `.env` was on the write-denylist; `.env.local`,
  `.env.production`, `.env.development`, `.env.test` all slipped
  through. Fixed: `isEnvVariantBasename` matches `^\.env(\..+)?$` on
  both write paths and read paths.

- **LOW macOS APFS case-insensitive containment false-rejection**
  (`isWithinBase`). On case-insensitive platforms, `/Users/olv` and
  `/users/olv` name the same directory, but `path.relative` is case-
  sensitive. Fixed: `isWithinBase` lowercases both sides on darwin /
  win32 before computing the relative path; case-sensitive Linux
  ext4 keeps the original strict comparison.

- **MEDIUM `NLMCP_FOLDER_ALLOWLIST` parser used hard-coded `":"`.**
  On Windows where `path.delimiter === ";"`, splitting on `:` would
  misparse `C:\foo` as `["C", "\foo"]`. Fixed: `getFolderAllowedBases`
  uses `path.delimiter`, exposed as a public helper for testing.

### Claims (package.json)

The `securityHardening` and `enterpriseCompliance` blocks have been rewritten
in honest scope. Each entry is now a short string describing the actual
mechanism (e.g. `"localAtRestEncryption": "ChaCha20-Poly1305 + ML-KEM-768
hybrid; both keys live on the same host (offline-disk-theft scope only)"`)
rather than a boolean implying full coverage. The `enterpriseCompliance`
block is now `complianceControls` with explicit `_doc` text noting that
"compliance is an organisational property — these features are necessary,
not sufficient." Specific changes:

- `postQuantumEncryption` → `localAtRestEncryption` with a scope caveat
- `memoryScrubbing` annotated with the JS-string heap caveat
- `responseValidation` annotated as defence-in-depth, not silver bullet
- `enterpriseCompliance` → `complianceControls` with the necessary-vs-sufficient
  caveat surfaced in `_doc`
- New: `webhookSsrfProtection`, `supplyChainGates`

## [2026.3.1] - 2026-04-25

### Security Audit Complete — All 334 Issues Resolved

This release closes the full 334-item security audit end-to-end. v2026.3.0 closed every
critical, high, and medium issue. This release closes all remaining low-severity issues,
the three intentionally-deferred items (I171, I281, I305), and cleans internal process
documents out of the repository.

**By the numbers:**
- Tests: **609 → 643** across 52 test files
- `npx tsc --noEmit` — clean
- `npm audit` — 0 vulnerabilities

### Security & Validation

- **Notebook ID validation centralised** — inline regex in `resource-handlers.ts` replaced with `validateNotebookId()` from `security.ts`; path-segment guard added to URI template handler (I107, I108)
- **`delete_document` confirm guard** — destructive tool now requires `confirm: true` explicit param; request without it returns `{ success: false }` (I078, I331)
- **Auth startup transparency** — `getAuthConfig()` logs effective auth state for all three configuration cases at startup (I118, I314)
- **Token rotation** — optional periodic token rotation via `NLMCP_AUTH_ROTATION_INTERVAL_HOURS` env var; unref'd timer does not prevent clean shutdown (I119)
- **Login retry** — `page.goto` timeout now retries once before throwing instead of warning and proceeding (I126)
- **Startup tool coverage check** — startup asserts every registered tool appears in `TOOLS_REQUIRING_AUTH` or explicit opt-out; phantom entries removed (I313)
- **Secrets scanner** — Bearer token pattern broadened from JWT-only (`A.B.C`) to any opaque token ≥ 20 chars (I189)
- **Audit hash chain** — `previousHash` advanced only after write succeeds; silent kill on flush failure eliminated (I228)
- **File lock liveness** — `forceUnlock` treats `EPERM` as "process alive" rather than unlocking erroneously (I296)

### Protocol & API

- **Error body shape aligned** — all error paths include `data: null`; callers can safely check `payload.data` on both success and failure (I095, I330)
- **Annotation drift fixed** — duplicate `title` fields removed from all `annotations` blocks (I041)
- **Prompt definitions** — empty `arguments: []` removed from all 4 prompt definitions (I109)
- **`parseArray` delimiter** — now splits on both comma and semicolon (I028)
- **`AuthenticationError`** — unused `suggestCleanup` field removed (I017)
- **URL sanitization** — `"unexpected URL: ${url}"` throw replaced with sanitized message that never leaks raw notebook URLs to MCP client (I173, I332)
- **Webhook error classification** — catch block in `webhook-dispatcher.ts` now walks the Node `fetch` cause chain and classifies errors as `timeout`, `dns_or_connect`, or `network`; DNS/connect failures skip retries; `errorKind` included in all log messages and delivery records (I281)

### Code Quality

- **Non-null assertion eliminated** — `toolRegistry!` replaced with `= new Map()` field initialiser (I020)
- **Startup log emoji stripped** — `\p{Extended_Pictographic}` removed from tool descriptions before substring truncation (I018)
- **`close_session` / `reset_session` deduplicated** — `withSessionOp` helper extracted; both handlers delegate to it (I077)
- **Notebook URL resolution deduplicated** — 7× repeated resolution blocks in `audio-video.ts` and 3× in `notebook-creation.ts` replaced with `resolveNotebookUrl()` in `error-utils.ts` (I093, I094)
- **`findElement` / `waitForElement` relocated** — moved from `selectors.ts` to `src/utils/page-utils.ts` (I149)
- **Dialog submit merged** — `clickSubmitButton` and `clickInsertButton` unified as `clickDialogSubmit()`: JS-eval first, selector second, Enter fallback (I148)
- **`clickAddSource` extracted** — 145-line method split into `tryAddSourceByAria`, `tryAddSourceByClass`, `tryAddSourceByJs` helpers (I166)
- **`addFileSource` extracted** — 116-line method split into `tryFileUploadViaTrigger` helper; three strategies are 3 one-liners (I167)
- **`clampInteger` exported** — pure clamping function now testable without module reload (I304)
- **`skipLibCheck` comment** — tsconfig annotated explaining patchright broken `.d.ts` (I311)
- **Compliance language** — README distinguishes code-level controls from organisational process controls required for formal certification (I265)
- **Discovery scripts relocated** — `run-discovery.ts` and `selector-discovery.ts` moved from `src/notebook-creation/` to `scripts/`; `npm run discover-selectors` added to `package.json` (I171)

### Test Coverage

New and expanded assertions:
- `validateNotebookId` — 8 acceptance/rejection cases in `security.test.ts` (I329)
- `data: null` in error response body — integration test in `mcp-server.integration.test.ts` (I330)
- `delete_document` confirm guard — `gemini-handler.test.ts` covers `confirm: false` and `confirm: undefined` (I331)
- Sanitized throw — `notebook-creator.test.ts` asserts raw URL never surfaces in error message (I332)
- Log rotation/retention — `audit-logger.test.ts` verifies files older than `retentionDays` are deleted (I302)
- `RateLimiter` memory bound — `security.test.ts` asserts map size ≤ 10 000 under 10 001 distinct keys (I303)
- `clampInteger` boundaries — 4 direct unit tests in `config.test.ts` (I304)
- **Handler smoke tests** — `tests/session-management.test.ts` (6 tests), `tests/ask-question.test.ts` (3 tests), and `tests/notebook-creator.test.ts` extensions (+3 tests) covering all handler entry points via injected mocks; no browser required (I305)
- **Webhook error classification** — test verifies cause-chain DNS classification and single-attempt behaviour on `ENOTFOUND` (I281)

### Repository Cleanup

- Removed internal process documents (`CODEX_BATCH*.md`, `ISSUES.md`, `OUTSTANDING.md`, `medusa-fp-analysis.md`) — never relevant to end users
- `.gitignore` extended to cover tooling artifacts (`graphify-out/`, `.stryker-tmp/`) and internal document patterns

---

## [2026.3.0] - 2026-04-25

### The Security Audit Release

We commissioned a parallel deep-audit of main @ `2973097` (v2026.2.11) using four specialised AI code reviewers, each independently focused on a different attack surface: security vulnerabilities, MCP protocol correctness, architecture quality, and testing gaps. Operating independently so findings wouldn't influence each other, they produced a 334-item master issue list across four severity tiers. This release closes the full high and medium tiers — every protocol correctness issue, every security gap identified, and every coverage hole — across three multi-day resolution sessions.

**By the numbers:**
- 334 issues audited across critical / high / medium / low / nit tiers
- ~115 issues closed (all highs and mediums resolved; lows/nits triaged)
- Tests: **139 → 609** across **50 test files** (4.4× increase)
- `npx tsc --noEmit` — clean
- `npm audit` — 0 vulnerabilities
- Live smoke test — `create_notebook` with text source: `sourceCount: 1, partial: false`

---

### Security — Critical & High Fixes

- **Auth token salt persisted** — `TOOLS_REQUIRING_AUTH` and `TOOLS_EXEMPT` converted to `Set<string>` for O(1) lookups; token hash salt now persisted across restarts so tokens survive server restart (I007, I110)
- **`forceAuth` bypass closed** — `validateToken()` accepts `forceValidation` flag; filesystem tools (`add_folder`, `cleanup_data`, `export_library`) now require auth even when auth is globally disabled (I069)
- **Webhook SSRF** — webhook dispatcher validates target URLs against SSRF blocklist before delivery; HMAC signing covers all delivery attempts (I269)
- **Webhook delivery persistence** — dispatcher retries failed deliveries with exponential backoff; results persisted across server restarts (I279)
- **Per-page mutex** — browser page operations now serialised per-page to prevent race conditions on concurrent tool calls (I163)
- **Login cancellation resilience** — auth flow handles user cancelling the Google login dialog without crashing or corrupting state (I123)
- **Headless session guard** — browser tools validate `headless` option before use; passing invalid values now returns a typed error instead of silently misbehaving (I131)
- **Selector timeout budget** — all `waitForSelector` calls use a deadline-based timeout budget shared across retries so no single selector can hang indefinitely (I145)

### Security — Audit Integrity

- **Hash chain verification on read** — audit log reader now recomputes the chain on every load and rejects tampered entries (I216)
- **Log rotation integrity** — chain anchor preserved across daily rotation boundaries; no gap in hash continuity (I217)
- **Concurrent write serialisation** — audit logger uses a write lock to prevent interleaved entries corrupting the JSONL file under concurrent tool calls (I218)

### MCP Protocol Compliance

- **Response shape** — all tool handlers now return `structuredContent` alongside `content`; error responses use `isError: true`; transport-layer tags stripped before delivery; server sends `notifications/cancelled` on shutdown (I010, I011, I012, I013, I014)
- **Annotation correctness** — `readOnlyHint`, `idempotentHint`, `destructiveHint` set correctly for all 48 tools — read-only tools no longer claim mutating side effects (I035, I036, I037, I038, I039)
- **Schema bounds** — all numeric and string tool parameters have explicit min/max constraints: `deep_research` depth (1-10), `list_documents` limit (1-100), query/chat history limits (1-500), browser timeout (5000-300000), batch size (1-10) (I050-I057)
- **Retired model names** — deprecated `gemini-2.5-*` model IDs replaced; deprecation messages corrected to past tense (I059)

### Architecture

- **Handler split** — 3,611-line `handlers.ts` decomposed into 9 domain modules: `ask-question`, `session-management`, `auth`, `notebook-management`, `notebook-creation`, `system`, `audio-video`, `webhooks`, `gemini`
- **HandlerContext DI** — all domain functions receive dependencies via `HandlerContext` instead of importing singletons directly; enables full unit testing without process-level mocks
- **Tool registry** — `Map<string, ToolHandler>` built once at startup replaces 500-line `switch/case` dispatch; O(1) lookup
- **Advanced tools env gate** — `generate_video_overview`, `generate_data_table`, and related Studio tools hidden behind `NLMCP_ADVANCED_TOOLS_ENABLED` flag (I069, I154)
- **Notebook creator split** — creation flow extracted from `handlers.ts` into dedicated `src/notebook-creation/` module with typed domain errors (I159, I161)

### Compliance Wiring

- **ChangeLog integration** — `ChangeLog.recordChange()` called at every config mutation site; audit trail covers all configuration state transitions (I243)
- **BreachDetector subscription** — `BreachDetector.checkEvent()` subscribes to the audit event bus; security events automatically trigger breach detection analysis (I244)

### Config & Types Cleanup

- **`getConfig()` alias** — `CONFIG` singleton now exported via `getConfig()` factory; consumers updated to use the factory (I024)
- **`followUpReminder` typing** — config field typed correctly; `parseBoolean`/`parseInteger` used consistently throughout config parsing (I025)
- **`BrowserOptions` extraction** — browser option type extracted to `src/types/browser-options.ts` and re-exported from `src/types/index.ts` (I026)
- **Tool re-export** — `Tool` type re-exported from `src/types/index.ts` so downstream consumers have a stable import path (I029)
- **`as any` reduction** — source tool contracts tightened; 30+ `as any` casts replaced with proper typed interfaces (I063, I064, I015)

### Test Coverage

Total: **139 → 609 tests across 50 files** — full breakdown of new test suites:

| New Test File | Coverage Target |
|---|---|
| `browser-session.test.ts` | BrowserSession lifecycle, page navigation, auth state |
| `shared-context-manager.test.ts` | Profile strategy, cloning, concurrent session coordination |
| `prompt-injection.test.ts` | 40+ prompt injection and payload patterns |
| `notebook-library.test.ts` | CRUD, search, persistence, concurrent access |
| `settings-manager.test.ts` | Parse, validate, merge, env override |
| `cleanup-manager.test.ts` | Selective deletion, preserve_library, cross-platform |
| `file-permissions.test.ts` | Linux/macOS chmod, Windows ACL, failure logging |
| `audit-logger.test.ts` | Hash chain, concurrent writes, rotation, tamper detection |
| `change-log.test.ts` | Before/after tracking, impact levels |
| `retention-engine.test.ts` | 7-year retention, purge scheduling |
| `incident-manager.test.ts` | Severity classification, notification dispatch |
| `dsar-handler.test.ts` | Race condition fix, export, erasure |
| `compliance.test.ts` | Full compliance stack integration |
| `mcp-auth.test.ts` | Token validation, lockout escalation, salt persistence |
| `webhook-dispatcher.test.ts` | SSRF block, HMAC, retry, persistence |

Security-critical module coverage (vitest --coverage):
- `mcp-auth.ts`: 75.7% lines
- `webhook-dispatcher.ts`: 71.4% lines
- `data-erasure.ts`: 72.0% lines
- `dsar-handler.ts`: 59.0% lines

### Selector & Browser Reliability (post-audit)

- **Notebook name selector** — removed `input[type='text']` from DOM fallback candidates (titles are always `contenteditable`); added `inSearch()` exclusion to skip candidates inside `[role='search']` ancestors (I162)
- **Text source flow** — `clickSourceTypeByText()` now validates the target textarea is a real "Pasted text" input before typing; fallback click restricted to button/chip targets; `findValidTextInputSelector` skips any textarea whose `aria-label` or `placeholder` suggests a search context (post-audit smoke test fix)
- **Video tile detection** — mat-icon text scan added as fallback in `clickVideoTile`; detection no longer relies solely on `.green` CSS class
- **Studio panel** — `[class*='create-artifact']` added to `ensureStudioPanelOpen` selectors for resilience against class renames

### MEDUSA CI Gate

- GitHub Actions workflow updated to run `medusa scan . --fail-on high` on every push to `main` and every PR; high-severity findings now block merge (I308, I333)

### Accuracy / Claims Alignment

- **Certificate pinning retracted** — cert pinning implementation removed from all source paths; `NLMCP_CERT_PINNING` env var removed; documentation updated to remove pinning claims (I174-I180, I331)
- **PQ encryption scope** — SECURITY.md already honest ("local at-rest only, not Harvest-Now-Decrypt-Later"); README badge language and architecture diagram aligned with the documented scope
- **Compliance language** — all references updated to "compliance-ready architecture (controls implemented)" — does not imply formal SOC2 Type II report, GDPR registration, or CSSF submission

---

## [2026.2.11] - 2026-03-28

### Fixed — UI Selector Hardening

- **`video-manager.ts`**: Added mat-icon text scan as fallback in `clickVideoTile` (same locale-independent pattern used by data-table). Video tile is now found by icon exclusion (`!= "table_view"`) rather than relying solely on the `.green` CSS class
- **`video-manager.ts` + `data-table-manager.ts`**: Added `[class*='create-artifact']` to `ensureStudioPanelOpen` waitForSelector and querySelector — Studio panel detection no longer breaks if Google renames `.create-artifact-button-container`
- **`selectors.ts`** `chooseFileButton`: Added 3 new fallbacks (`[class*="file-dialog-button"]`, `button[class*="upload"][class*="trigger"]`, `span[class*="file-dialog"]`) for resilience against Dropzone class renames
- **`selectors.ts`** `closeDialogButton`: Added US spelling `button[aria-label="Close dialog"]` alongside British `"Close dialogue"` — survives if Google normalises to US English
- **`selectors.ts`** `chatInput`: Removed hardcoded German `aria-label="Feld für Anfragen"` fallback; replaced with locale-agnostic chain (`textarea[aria-label]`, `textarea[class*="query"]`, `.chat-input textarea`)

### Docs

- Compliance language updated throughout README and `package.json` to accurately reflect "compliance-ready architecture" (controls implemented) vs formal certification (requires third-party audit)

---

## [2026.2.10] - 2026-03-15

### Added — 3 New Security Layers (14 → 17)
- **Secure-by-Default Auth**: MCP authentication enabled by default — no configuration needed. Explicit opt-out via `NLMCP_AUTH_DISABLED=true`
- **Exponential Backoff Lockout**: Failed auth lockouts escalate 5min → 15min → 45min → 4hr (capped). `lockoutCount` persists across resets
- **Credential Isolation**: `LOGIN_PASSWORD` and `GEMINI_API_KEY` wrapped in `SecureCredential` with 30-min TTL. Original env vars scrubbed from `process.env`

### Added — Architecture Overhaul
- Split 3,611-line `handlers.ts` into 9 domain modules: ask-question, session-management, auth, notebook-management, notebook-creation, system, audio-video, webhooks, gemini
- `HandlerContext` dependency injection pattern for testable domain functions
- Tool registry `Map` replaces 500-line switch/case — built once at startup, O(1) dispatch
- Filesystem tools (`add_folder`, `cleanup_data`, `export_library`) gated behind auth even when globally disabled
- `forceValidation` parameter on `validateToken()` prevents auth bypass on sensitive tools

### Added — Token Management CLI
- `npx notebooklm-mcp token show` — check token status
- `npx notebooklm-mcp token rotate` — generate new token, invalidate old
- First-run token display shows copy-pasteable commands with actual token value

### Added — Reliability
- Gemini API retry with exponential backoff (429/500/502/503, 3 retries)
- Configurable response timeout: `NLMCP_RESPONSE_TIMEOUT_MS` (default: 120s)
- Configurable follow-up reminder: `NLMCP_FOLLOW_UP_ENABLED` / `NLMCP_FOLLOW_UP_REMINDER`
- Config value range clamping: `maxSessions` (1-50), `sessionTimeout` (60-86400), `browserTimeout` (5000-300000)
- File permission failures now logged and audited (no longer silently swallowed)

### Added — CI/CD & Docker
- `npm test` step added to CI pipeline
- Multi-stage Docker build (~40-60% smaller image)
- `.dockerignore` created

### Added — Testing
- 57 new tests: security utilities (`validateNotebookUrl`, `validateQuestion`, `RateLimiter`) and config parsing (`parseBoolean`, `parseInteger`, `parseArray`, `applyBrowserOptions`)
- 168 total tests passing across 6 test files

### Fixed
- Locale-agnostic browser selectors — removed hardcoded German `textarea[aria-label="Feld für Anfragen"]`
- `parseBoolean` used consistently for auth disable check (case-insensitive)
- `parseInteger` used consistently in mcp-auth (NaN-safe)
- Backoff comment corrected: "3rd: 1hr" → "3rd: 45min"

### Security Fixes (found during 4-agent review)
- **CRITICAL**: `forceAuth` bypass — `validateToken()` now accepts `forceValidation` to skip `!enabled` short-circuit
- **CRITICAL**: Plaintext credentials removed from `CONFIG` — consumers use `getSecureLoginPassword()` / `getSecureGeminiApiKey()`

## [2026.2.9] - 2026-03-01

### Fixed — performSetup No Longer Destroys Auth Before Chrome Opens
- **Root cause identified**: `performSetup()` was calling `clearAllAuthData()` unconditionally before launching Chrome
- If Chrome failed to open for any reason (display issue, profile lock, timeout), credentials were already gone
- **Fix**: Removed `clearAllAuthData()` from `performSetup()` — auth is only cleared if Chrome successfully opens and the user re-authenticates
- Added stack trace logging to `clearAllAuthData()` so any future caller can be traced in logs

## [2026.2.8] - 2026-03-01

### Fixed — cleanup_data No Longer Destroys Auth Credentials
- **Root cause identified**: `browser_state/` and `chrome_profile/` directories were included in all `cleanup_data` deletion paths
- Sessions following `get_health` troubleshooting tips ran `cleanup_data` and wiped Google auth cookies
- **Fix**: Both auth directories permanently excluded from ALL cleanup paths (both `preserve_library=true` and `preserve_library=false`)
- **Fix**: `get_health` troubleshooting tip updated — no longer suggests running `cleanup_data`
- Auth credentials now survive all cleanup operations

## [2026.2.7] - 2026-03-01

### Fixed — Headless setup_auth Blocked
- `setup_auth` without `show_browser: true` now returns an error immediately instead of attempting headless auth (which would fail silently)
- Consistent with existing `re_auth` headless guard added in v2026.2.4

### Added — Standalone auth-now.mjs Script
- New `auth-now.mjs` in project root bypasses MCP protocol entirely
- Handles Chrome profile lock (kills existing Chrome processes before launch)
- Saves `state.json.pqenc` via SecureStorage with plain JSON fallback
- Verifies file exists on disk after save with size check
- Stays open 60s after success so user can confirm

## [2026.2.6] - 2026-03-01

### Added — Bulk Folder Upload Tool
- **`add_folder`** — New tool to upload all PDFs/files from a local directory to a notebook
- Supports `dry_run` mode, `recursive` traversal, `file_types` filter, and progress callbacks
- Collects per-file errors and reports a summary instead of failing the whole batch
- Handles large folders (90+ files) with sequential upload and per-file error recovery

### Fixed — Tier Detection for NotebookLM Plus
- `detectTierFromPage()` now detects "NOTEBOOKLM PLUS", "ONE AI PREMIUM", and "GOOGLE ONE AI" branding
- Falls back to inferring tier from source limit shown in UI (50→free, 300→pro, 600→ultra)
- Resolves issue where tier was stuck on "unknown" defaulting to free tier limits

## [2026.2.5] - 2026-03-01

### Fixed — show_browser Silently Ignored in setup_auth
- `setup_auth` handler received `show_browser` parameter but never passed it to `performSetup()`
- Chrome stayed headless even when `show_browser: true` was explicitly set
- **Fix**: `performSetup()` now accepts and uses `show_browser` (overrideHeadless) parameter
- Browser now reliably opens for user authentication when requested

## [2026.2.4] - 2026-03-01

### Fixed — Auth State Expiry Extended to 7 Days
- State expiry extended from 24 hours to 7 days — matches real Google cookie lifetimes (2-4 weeks)
- `touchStateFile()` method added: resets the expiry clock on every successful auth validation so active sessions never expire
- Called in both `validateWithRetry()` fast path and retry success path

### Fixed — Headless re_auth Blocked
- `re_auth` without `show_browser: true` now returns a clear error instead of wiping auth state and failing silently
- Prevents the silent credential destruction loop caused by automated/headless `re_auth` calls

### Added — clearAllAuthData Caller Tracing
- `clearAllAuthData()` now logs a stack trace excerpt so any future unexpected caller can be identified in logs

## [2026.2.3] - 2026-02-20

### Fixed — Studio Panel Tools Fully Restored
- **`generate_data_table` and `generate_video_overview`** now work correctly end-to-end, confirmed on macOS M4 (French locale, headless mode)
- **Dead tile selector**: `clickDataTableTile` used `.mat-icon, [class*='icon']` which matched `SPAN.icon-container` before `<mat-icon>`, so `=== "table_view"` always failed silently. Fixed to `mat-icon` element tag (textContent is exactly `"table_view"`)
- **False failure on slow shimmer**: after clicking the tile, if `shimmer-blue` didn't appear within 15s the tools returned `success: false`. Generation was triggering server-side but headless DOM update lagged. Now returns `{ success: true, status: "generating" }` so callers can poll
- **`data-create-button-type` removed by Google** (Feb 2026): replaced with `mat-icon` text check and `jslog` numeric ID (`282298`) as locale-independent fallback
- **Studio panel timeout** increased from 10s to 30s for slower machines and larger notebooks
- **Full i18n pass**: all browser automation uses locale-independent signals first (CSS classes, Material icon names, element structure, `jslog` IDs) with English text as last-resort fallback only

### Added — CI / Branch Protection
- GitHub Actions CI (`.github/workflows/ci.yml`) runs TypeScript build on every PR and push to `main`
- `main` branch protection: force pushes blocked, branch deletion blocked, `Build` check required before merge

## [2026.2.2] - 2026-02-19

### Fixed — Studio Panel Reliability on Slower Machines
- **`generate_data_table` and `generate_video_overview`** no longer fail with "Could not find Studio panel toggle button" when the Studio panel loads collapsed or the DOM hasn't fully rendered
- Added `waitForSelector` before Studio panel checks — blocks until either the panel tiles or toggle button appear (up to 10s), preventing race conditions on slower machines
- Added `waitForSelector` for the generating artifact shimmer state after tile click — replaces fixed 3-4s delay, so generation is confirmed reliably regardless of machine speed
- Multi-selector fallback chain retained for future-proofing against NotebookLM DOM changes

## [2026.2.1] - 2026-02-18

### Fixed — Standard Profile Missing Key Tools
- **Standard profile expanded** from 14 to 33 tools — all browser-based features now visible by default
- Previously hidden tools now in standard: `create_notebook`, `batch_create_notebooks`, `add_source`, `remove_source`, `list_sources`, `generate_audio_overview`, `get_audio_status`, `download_audio`, `sync_library`, `remove_notebook`, `get_notebook_chat_history`, `get_query_history`, `re_auth`, `close_session`, `reset_session`, `get_quota`, `cleanup_data`
- **Root cause**: The `standard` profile was never updated as new features were added, so key advertised features (notebook creation, source management, audio) were only available with `NOTEBOOKLM_PROFILE=full`
- Gemini API tools remain in `full` profile only — keeps standard aligned with the "no API key required" promise
- Full profile (`NOTEBOOKLM_PROFILE=full`) still includes all 47 tools (adds Gemini API, webhooks, compliance, export)

## [2026.2.0] - 2026-02-17

### Added — Gemini 3 Model Support
- **Gemini 3 models** — `gemini-3-flash-preview` and `gemini-3-pro-preview` now available as default models
- **Deprecation warnings** — Using `gemini-2.5-flash` or `gemini-2.5-pro` now returns a warning that these models retire March 31, 2026
- **Incomplete status handling** — Deep Research now handles `"incomplete"` status from the API as a terminal state with partial results

### Added — Thinking Level Control
- **`thinking_level` parameter** — New optional parameter for `gemini_query` and `deep_research` tools
- Supports `minimal`, `low`, `medium`, and `high` levels for controlling response thoroughness vs speed

### Added — Structured JSON Output
- **`response_schema` parameter** — New optional parameter for `gemini_query` tool
- Pass a JSON schema to get structured, validated JSON responses from Gemini 3
- Automatically sets `responseMimeType: "application/json"` when schema is provided

### Added — Video Overview Generation
- **`generate_video_overview`** — Generate AI-powered Video Overviews through NotebookLM's Studio panel
- **`get_video_status`** — Check Video Overview generation progress
- 10 visual styles: auto-select, custom, classic, whiteboard, kawaii, anime, watercolour, retro-print, heritage, paper-craft
- 2 formats: explainer (full, 5-15 min) and brief (summary, 1-3 min)

### Added — Data Table Extraction
- **`generate_data_table`** — Generate structured Data Tables from notebook sources via Studio panel
- **`get_data_table`** — Extract generated table data as structured JSON (headers + rows)

### Changed
- **Default model** changed from `gemini-2.5-flash` to `gemini-3-flash-preview`
- **@google/genai SDK** upgraded from 1.38.0 to 1.41.0
- **Server banner** updated to reflect Gemini 3

## [2026.1.12] - 2026-02-15

### Security — Code Review & Medusa Scan Remediation
- **Constant-time auth token comparison** using `secureCompare` (prevents timing attacks)
- **Command injection fix** in `file-permissions.ts` — replaced `execSync()` with `execFileSync()` (array args)
- **MCP SDK updated** to 1.26.0 — patches HIGH severity cross-client data leak (GHSA-345p-7cg4-v4c7)
- **Audit hash chain** increased from 64-bit to 128-bit truncation for stronger collision resistance
- **Settings JSON validation** — parsed settings now validated before merge (prevents property injection)
- **Error message sanitization** — internal identifiers removed from error responses
- **Dockerfile hardened** with `--no-install-recommends`
- **Config env var validation** — `NOTEBOOK_PROFILE_STRATEGY` validated against allowed values

### Fixed — Memory Leaks & Concurrency
- **CONFIG mutation race condition eliminated** — removed all 6 `Object.assign(CONFIG, ...)` call sites that could corrupt global state during concurrent requests
- **RateLimiter memory leak** — empty keys now evicted from Map to prevent unbounded growth
- **FinalizationRegistry self-reference** — fixed held value that prevented GC of secure buffers
- **Event listener leak** — `framenavigated` listener now cleaned up after 30s timeout
- **SecureCredential timer** — `.unref()` added so auto-wipe timer doesn't prevent process exit

### Performance
- **Regex precompilation** in `sanitizeForLogging` — 5 patterns + email regex moved to module scope
- **Response validator** — eliminated regex recompilation in `detectSuspiciousUrls` loop
- **Rate limit detection** — consolidated 8+ IPC round-trips into single `page.evaluate()` call
- **ESM import fix** — removed inline `require('path')` in favor of module-level import
- **O(n) dedup** — notebook extraction uses Set-based deduplication instead of O(n^2)

### Code Quality
- **Version strings unified** — MCP server and audit log now use `package.json` version
- **Debounced library save** — `incrementUseCount` no longer writes to disk on every query
- **Data URI pattern** — tightened false-positive-prone `data:` regex in response validator
- **Quota storage** — moved from `configDir` to `dataDir` for consistency with directory lifecycle

## [2026.1.11] - 2026-02-02

### Fixed - Notebook Sync Extraction for New Angular UI
- **sync_library** now correctly extracts notebook UUIDs from NotebookLM's Angular Material UI
  - Automatically switches to grid view where notebook UUIDs are available in DOM element IDs
  - Primary strategy: extract from `project-button` card elements in grid view
  - Fallback: click-navigation through table rows to capture URLs
  - Last resort: basic table row extraction with placeholder URLs
- **quota_manager** updated to detect notebooks via `project-button` (grid) and `project-action-button` (table)
- Resolves issue reported in PR #3 — thanks @robert-merrill for identifying the UI change

### Added - Disable Gemini Tools Environment Variable
- **NOTEBOOKLM_NO_GEMINI** - New environment variable to disable all Gemini API tools
  - Set `NOTEBOOKLM_NO_GEMINI=true` to hide 8 Gemini tools from tool list
  - Useful for clients with context window limitations (e.g., OpenCode)
  - Reduces tool count for clients that don't need Gemini features
  - Disabled tools: `deep_research`, `gemini_query`, `get_research_status`, `upload_document`, `query_document`, `list_documents`, `delete_document`, `query_chunked_document`

## [2026.1.10] - 2026-01-28

### Fixed - Tool Description Clarity for Multi-LLM Compatibility
- **ask_question** - Removed "Gemini" references that confused LLMs into thinking API key was needed
  - Now clearly states "Browser-Based • NO API KEY REQUIRED"
  - Added "PREFER THIS TOOL" guidance for notebook queries
- **deep_research** - Added prominent warning "⚠️ REQUIRES GEMINI_API_KEY"
  - Added "When NOT to Use" section directing to ask_question
- **gemini_query** - Added prominent warning "⚠️ REQUIRES GEMINI_API_KEY"
  - Added "When NOT to Use" section directing to ask_question
- **upload_document** - Added note about alternatives that don't need API key

This fix addresses feedback from OpenCode users where the LLM was incorrectly choosing Gemini API tools over browser-based tools.

## [2026.1.9] - 2026-01-28

### Changed - Documentation & UX Improvements
- **TL;DR Feature Summary** - Quick bullet list at top of README for instant understanding
- **Updated "What's New in 2026"** - Shows all recent releases at a glance
- **Full Feature List** - Collapsible section listing all 43 tools by category
- **Gemini API Optional Callout** - Prominent messaging that core features need no API key
- **Architecture Diagram** - Updated to show "NO API KEY NEEDED" vs "OPTIONAL"

### Security
- Fixed 1 moderate vulnerability in hono dependency via `npm audit fix`

## [2026.1.8] - 2026-01-27

### Changed - Major Dependency Updates
- **@noble/post-quantum** 0.2.1 → 0.5.4 (FIPS 203/204/205 post-quantum cryptography updates)
- **dotenv** 16.6.1 → 17.2.3
- **env-paths** 3.0.0 → 4.0.0
- **globby** 14.1.0 → 16.1.0
- **zod** 3.25.76 → 4.3.6
- **@types/node** 20.19.21 → 20.19.30

### Fixed
- **@noble/post-quantum import path** - Updated import from `@noble/post-quantum/ml-kem` to `@noble/post-quantum/ml-kem.js` (API change in v0.5.4)

## [2026.1.7] - 2026-01-27

### Added - MCP Protocol UX Enhancements
- **Tool Icons** - All 43 tools now have SVG icons for visual identification in compatible MCP clients
- **Human-Friendly Titles** - Tools have proper display titles (e.g., "Ask NotebookLM" instead of "ask_question")
- **Tool Behavior Annotations** - Tools include hints for client decision-making:
  - `readOnlyHint` - Indicates if tool only reads data
  - `destructiveHint` - Warns about data deletion operations
  - `idempotentHint` - Indicates if repeated calls are safe
  - `openWorldHint` - Shows if tool interacts with external services
- **Task Support for Deep Research** - `deep_research` tool now declares `execution.taskSupport: "optional"` for proper long-running operation handling
- **Resource Icons & Annotations** - Resources now include:
  - SVG icons for visual identification
  - `title` field for human-friendly display
  - `annotations` with `audience`, `priority`, and `lastModified` hints
- **Predefined Prompts** - New prompts available via `prompts/list`:
  - `notebooklm.auth-setup` - Initial authentication guide
  - `notebooklm.auth-repair` - Authentication troubleshooting
  - `notebooklm.quick-start` - Getting started guide
  - `notebooklm.security-overview` - Security features documentation

### Changed
- Updated `@modelcontextprotocol/sdk` from 1.25.2 to 1.25.3
- Updated `@google/genai` from 1.36.0 to 1.38.0
- Updated `patchright` from 1.55.0 to 1.57.0
- Updated `tsx` from 4.19.0 to 4.21.0

### Security
- Fixed 3 npm audit vulnerabilities (body-parser, hono, qs)

## [2026.1.4] - 2026-01-23

### Security
- **Defense-in-Depth Path Validation** - Added input validation for Windows `icacls` command
  - `isPathSafeForShell()` - Blocks shell metacharacters (`;&|`$` etc.) and path traversal (`..`)
  - `isUsernameSafe()` - Validates username format before shell use
  - Path normalization before execution
  - Addresses Medusa security scan finding (false positive but hardened anyway)

### Notes
- Medusa scan showed 11 findings, 10 were false positives
- This release hardens the one legitimate concern even though it wasn't exploitable

## [2026.1.3] - 2026-01-15

### Changed
- Updated `@modelcontextprotocol/sdk` from 1.0.0 to 1.25.2

## [2026.1.2] - 2026-01-15

### Added - Multi-Session Authentication Coordination
- **Auth Lock System** - Global `.auth-in-progress` lock prevents race conditions when multiple Claude Code sessions authenticate simultaneously
- **Wait for Auth** - Isolated profiles now wait for any in-progress authentication before cloning base profile
- **Automatic State Reuse** - If another session completes auth while waiting, shared state is automatically reused

### Configuration
New environment variables for multi-session support:
```bash
export NOTEBOOK_PROFILE_STRATEGY=isolated  # isolated|single|auto
export NOTEBOOK_CLONE_PROFILE=true         # Clone auth from base profile
```

### How It Works
1. Session A starts auth → acquires lock → clears old auth → opens browser
2. Session B starts → needs isolated profile → detects lock → waits
3. Session A completes login → saves state → releases lock
4. Session B continues → clones now-authenticated profile → works immediately

## [2026.1.1] - 2026-01-14

### Added
- **Deep Health Check** - `get_health` tool now supports `deep_check: true` parameter to verify NotebookLM chat UI actually loads
- Catches stale sessions where cookies exist but UI won't load

## [2026.1.0] - 2026-01-13

### Added
- **Chat History Context Management** - New `get_notebook_chat_history` tool for extracting conversation history from NotebookLM notebooks
- **CalVer Versioning** - Switched to Calendar Versioning (2026.MINOR.PATCH)
- Preview mode, pagination, and file export options for chat history

## [1.6.0] - 2025-12-18

### Added - Enterprise Compliance Module

Major release adding comprehensive enterprise compliance support for GDPR, SOC2 Type II, and CSSF (Luxembourg) regulations.

#### Core Compliance Infrastructure (Phase 1)
- **Compliance Logger** - Hash-chained audit logs with SHA-256 integrity verification
  - Tamper-evident logging with cryptographic chain
  - 7-year retention support (CSSF requirement)
  - Structured compliance events with actor tracking
- **Data Classifier** - Automatic data sensitivity classification
  - 5 classification levels: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, REGULATED
  - Pattern-based detection for PII, credentials, financial data
- **Data Inventory** - GDPR Article 30 Records of Processing Activities
  - Automatic discovery and cataloging of all data stores
  - Processing purpose and legal basis tracking
- **Consent Manager** - User consent tracking and management
  - GDPR Article 6 legal basis support
  - Consent versioning and expiration handling

#### Data Subject Rights - GDPR (Phase 2)
- **DSAR Handler** - Data Subject Access Request processing (Article 15)
  - Automated data collection and response generation
  - 30-day deadline tracking
- **Data Erasure Manager** - Right to be forgotten (Article 17)
  - Verified secure deletion with audit trail
  - Scope-based erasure (categories, date ranges)
- **Data Exporter** - Data portability (Article 20)
  - Machine-readable JSON export format
  - Checksum verification for integrity
- **Retention Engine** - Automatic data retention enforcement
  - Configurable policies per data type
  - CSSF 7-year retention for audit logs

#### Security Monitoring & Incident Response (Phase 3)
- **Incident Manager** - Security incident lifecycle management
  - Severity-based workflow (low/medium/high/critical)
  - 72-hour notification deadline tracking (GDPR breach notification)
  - Root cause analysis and remediation tracking
- **Alert Manager** - Multi-channel security alerting
  - Console, file, webhook, and email channels
  - Severity-based routing and rate limiting
- **Breach Detector** - Pattern-based breach detection
  - Configurable detection rules
  - Automatic incident creation and alerting
- **Health Monitor** - System availability monitoring (SOC2)
  - Component health checks
  - Uptime tracking and SLA reporting
- **SIEM Exporter** - Enterprise SIEM integration
  - CEF (ArcSight), LEEF (QRadar), Syslog, Splunk HEC formats
  - Real-time event streaming

#### Compliance Reporting & Documentation (Phase 4)
- **Report Generator** - Compliance report generation
  - 10 report types: compliance_summary, gdpr_audit, soc2_audit, cssf_audit, security_audit, incident_report, dsar_report, retention_report, change_management, full_audit
  - JSON, CSV, HTML output formats
- **Evidence Collector** - Audit evidence packages
  - Verifiable evidence with SHA-256 checksums
  - Regulation-specific collection (GDPR, SOC2, CSSF)
- **Compliance Dashboard** - Real-time compliance status
  - Per-regulation status (compliant/at_risk/non_compliant)
  - Compliance score calculation (0-100)
  - CLI-formatted dashboard output
- **Change Log** - Configuration change tracking (SOC2)
  - Before/after value tracking
  - Impact assessment (low/medium/high/critical)
  - Approval workflow support
- **Policy Doc Manager** - Policy documentation management
  - 6 policy types: privacy, retention, access control, encryption, incident response, acceptable use
  - Version control and review scheduling
- **16 MCP Compliance Tools** - Claude integration
  - Full compliance functionality exposed via MCP tools
  - Real-time compliance status queries

### Technical Details
- **23 new TypeScript modules** in `src/compliance/`
- **13,147 lines of code** for compliance functionality
- **All modules use singleton pattern** for consistent state management
- **Full type safety** with comprehensive TypeScript interfaces
- **Zero external dependencies** for compliance code

### Documentation
- Added `docs/COMPLIANCE-SPEC.md` - Full 4-phase implementation specification
- Added MEDUSA scan response documenting false positive analysis

## [1.2.0] - 2025-11-21

### Added
- **Tool Profiles System** - Reduce token usage by loading only the tools you need
  - Three profiles: `minimal` (5 tools), `standard` (10 tools), `full` (16 tools)
  - Persistent configuration via `~/.config/notebooklm-mcp/settings.json`
  - Environment variable overrides: `NOTEBOOKLM_PROFILE`, `NOTEBOOKLM_DISABLED_TOOLS`

- **CLI Configuration Commands** - Easy profile management without editing files
  - `npx notebooklm-mcp config get` - Show current configuration
  - `npx notebooklm-mcp config set profile <name>` - Set profile (minimal/standard/full)
  - `npx notebooklm-mcp config set disabled-tools <list>` - Disable specific tools
  - `npx notebooklm-mcp config reset` - Reset to defaults

### Changed
- **Modularized Codebase** - Improved maintainability and code organization
  - Split monolithic `src/tools/index.ts` into `definitions.ts` and `handlers.ts`
  - Extracted resource handling into dedicated `ResourceHandlers` class
  - Cleaner separation of concerns throughout the codebase

### Fixed
- **LibreChat Compatibility** - Fixed "Server does not support completions" error
  - Added `prompts: {}` and `logging: {}` to server capabilities
  - Resolves GitHub Issue #3 for LibreChat integration

- **Thinking Message Detection** - Fixed incomplete answers showing placeholder text
  - Now waits for `div.thinking-message` element to disappear before reading answer
  - Removed unreliable text-based placeholder detection (`PLACEHOLDER_SNIPPETS`)
  - Answers like "Reviewing the content..." or "Looking for answers..." no longer returned prematurely
  - Works reliably across all languages and NotebookLM UI changes

## [1.1.2] - 2025-10-19

### Changed
- **README Documentation** - Added Claude Code Skill reference
  - New badge linking to [notebooklm-skill](https://github.com/PleasePrompto/notebooklm-skill) repository
  - Added prominent callout section explaining Claude Code Skill availability
  - Clarified differences between MCP server and Skill implementations
  - Added navigation link to Skill repository in top menu
  - Both implementations use the same browser automation technology

## [1.1.1] - 2025-10-18

### Fixed
- **Binary executable permissions** - Fixed "Permission denied" error when running via npx
  - Added `postbuild` script that automatically runs `chmod +x dist/index.js`
  - Ensures binary has executable permissions after compilation
  - Fixes installation issue where users couldn't run the MCP server

### Repository
- **Added package-lock.json** - Committed lockfile to repository for reproducible builds
  - Ensures consistent dependency versions across all environments
  - Improves contributor experience with identical development setup
  - Enables `npm ci` for faster, reliable installations in CI/CD
  - Follows npm best practices for library development (2025)

## [1.1.0] - 2025-10-18

### Added
- **Deep Cleanup Tool** - Comprehensive system cleanup for fresh NotebookLM MCP installations
  - Scans entire system for ALL NotebookLM files (installation data, caches, logs, temp files)
  - Finds hidden files in NPM cache, Claude CLI logs, editor logs, system trash, temp backups
  - Shows categorized preview before deletion with exact file list and sizes
  - Safe by design: Always requires explicit confirmation after preview
  - Cross-platform support: Linux, Windows, macOS
  - Enhanced legacy path detection for old config.json files
  - New dependency: globby@^14.0.0 for advanced file pattern matching
- CHANGELOG.md for version tracking
- Changelog badge and link in README.md

### Changed
- **Configuration System Simplified** - No config files needed anymore!
  - `config.json` completely removed - works out of the box with sensible defaults
  - Settings passed as tool parameters (`browser_options`) or environment variables
  - Claude can now control ALL browser settings via tool parameters
  - `saveUserConfig()` and `loadUserConfig()` functions removed
- **Unified Data Paths** - Consolidated from `notebooklm-mcp-nodejs` to `notebooklm-mcp`
  - Linux: `~/.local/share/notebooklm-mcp/` (was: `notebooklm-mcp-nodejs`)
  - macOS: `~/Library/Application Support/notebooklm-mcp/`
  - Windows: `%LOCALAPPDATA%\notebooklm-mcp\`
  - Old paths automatically detected by cleanup tool
- **Advanced Browser Options** - New `browser_options` parameter for browser-based tools
  - Control visibility, typing speed, stealth mode, timeouts, viewport size
  - Stealth settings: Random delays, human typing, mouse movements
  - Typing speed: Configurable WPM range (default: 160-240 WPM)
  - Delays: Configurable min/max delays (default: 100-400ms)
  - Viewport: Configurable size (default: 1024x768, changed from 1920x1080)
  - All settings optional with sensible defaults
- **Default Viewport Size** - Changed from 1920x1080 to 1024x768
  - More reasonable default for most use cases
  - Can be overridden via `browser_options.viewport` parameter
- Config directory (`~/.config/notebooklm-mcp/`) no longer created (not needed)
- Improved logging for sessionStorage (NotebookLM does not use sessionStorage)
- README.md updated to reflect config-less architecture

### Fixed
- **Critical: envPaths() default suffix bug** - `env-paths` library appends `-nodejs` suffix by default
  - All paths were incorrectly created with `-nodejs` suffix
  - Fix: Explicitly pass `{suffix: ""}` to disable default behavior
  - Affects: `config.ts` and `cleanup-manager.ts`
  - Result: Correct paths now used (`notebooklm-mcp` instead of `notebooklm-mcp-nodejs`)
- Enhanced cleanup tool to detect all legacy paths including manual installations
  - Added `getManualLegacyPaths()` method for comprehensive legacy file detection
  - Finds old config.json files across all platforms
  - Cross-platform legacy path detection (Linux XDG dirs, macOS Library, Windows AppData)
- **Library Preservation Option** - cleanup_data can now preserve library.json
  - New parameter: `preserve_library` (default: false)
  - When true: Deletes everything (browser data, caches, logs) EXCEPT library.json
  - Perfect for clean reinstalls without losing notebook configurations
- **Improved Auth Troubleshooting** - Better guidance for authentication issues
  - New `AuthenticationError` class with cleanup suggestions
  - Tool descriptions updated with troubleshooting workflows
  - `get_health` now returns `troubleshooting_tip` when not authenticated
  - Clear workflow: Close Chrome → cleanup_data(preserve_library=true) → setup_auth/re_auth
  - Critical warnings about closing Chrome instances before cleanup
- **Critical: Browser visibility (show_browser) not working** - Fixed headless mode switching
  - **Root cause**: `overrideHeadless` parameter was not passed from `handleAskQuestion` to `SessionManager`
  - **Impact**: `show_browser=true` and `browser_options.show=true` were ignored, browser stayed headless
  - **Solution**:
    - `handleAskQuestion` now calculates and passes `overrideHeadless` parameter correctly
    - `SharedContextManager.getOrCreateContext()` checks for headless mode changes before reusing context
    - `needsHeadlessModeChange()` now checks CONFIG.headless when no override parameter provided
  - **Session behavior**: When browser mode changes (headless ↔ visible):
    - Existing session is automatically closed and recreated with same session ID
    - Browser context is recreated with new visibility mode
    - Chat history is reset (message_count returns to 0)
    - This is necessary because NotebookLM chat state is not persistent across browser restarts
  - **Files changed**: `src/tools/index.ts`, `src/session/shared-context-manager.ts`

### Removed
- Empty postinstall scripts (cleaner codebase)
  - Deleted: `src/postinstall.ts`, `dist/postinstall.js`, type definitions
  - Removed: `postinstall` npm script from package.json
  - Follows DRY & KISS principles

## [1.0.5] - 2025-10-17

### Changed
- Documentation improvements
- Updated README installation instructions

## [1.0.4] - 2025-10-17

### Changed
- Enhanced usage examples in documentation
- Fixed formatting in usage guide

## [1.0.3] - 2025-10-16

### Changed
- Improved troubleshooting guide
- Added common issues and solutions

## [1.0.2] - 2025-10-16

### Fixed
- Fixed typos in documentation
- Clarified authentication flow

## [1.0.1] - 2025-10-16

### Changed
- Enhanced README with better examples
- Added more detailed setup instructions

## [1.0.0] - 2025-10-16

### Added
- Initial release
- NotebookLM integration via Model Context Protocol (MCP)
- Session-based conversations with Gemini 2.5
- Source-grounded answers from notebook documents
- Notebook library management system
- Google authentication with persistent browser sessions
- 16 MCP tools for comprehensive NotebookLM interaction
- Support for Claude Code, Codex, Cursor, and other MCP clients
- TypeScript implementation with full type safety
- Playwright browser automation with stealth mode
