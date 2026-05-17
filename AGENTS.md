# AGENTS.md — Project memory for AI agents

This file is the single source of truth for AI agents working in this
repo. `CLAUDE.md`, `GEMINI.md`, and `CODEX.md` are thin pointers that
exist so each tool's auto-loader finds something — they all delegate
here.

If you are an AI agent (Claude Code, Codex CLI, Gemini CLI, Cursor,
etc.) reading this for the first time, read it end-to-end. The
sections are ordered roughly by how often you'll need them.

---

## What this repo is

`@ohjaygee/notebooklm-mcp-secure` is a security-hardened fork of an
MCP (Model Context Protocol) server that wraps Google's NotebookLM
via browser automation. It runs as a stdio subprocess of an MCP
client (Claude Code, Codex CLI, Claude Desktop). It is **not** a
hosted service; the Docker / Smithery deployment artifacts have been
moved out of the repo (see "Deployment artifacts" below).

Fork chain: `PleasePrompto/notebooklm-mcp` → `Pantheon-Security/
notebooklm-mcp-secure` (`@pan-sec/notebooklm-mcp`) → this fork. The
machine-readable form of this chain lives in `package.json._lineage`.

## Threat model — what this fork defends against, and what it doesn't

**Actively defended:**

- Prompt-injection chains through malicious notebook sources, web
  pages, or uploaded documents that try to coerce the host LLM into
  emitting tool calls that exfiltrate local files, overwrite system
  files, or navigate the authenticated browser to attacker origins.
- An MCP client that has accumulated bad context and is now emitting
  unintended tool calls.
- A caller with read-scope authentication (or in an
  `NLMCP_AUTH_DISABLED=true` deployment) trying to mutate library
  state, trigger remote NotebookLM mutations, or upload local
  credentials to Google.
- Supply-chain compromise of a transitive dependency at install time
  (Sigstore signature verification, `--ignore-scripts`, lockfile-drift
  detection, exact-version pins).
- Offline theft of individual encrypted credential / state files
  (local at-rest encryption with ChaCha20-Poly1305 + ML-KEM-768).

**NOT defended:**

- A caller with admin-scope authentication. Admin scope can read any
  file the process can read and write any path within the export
  base. Treat the admin token as equivalent to your shell.
- A caller who has compromised the Google account whose session is in
  use.
- A caller who can read or modify files in the data directory while
  the server is running. The "encryption at rest" is local — the
  unwrap key lives on the same disk.
- Browser-level exploits in Chrome / Chromium.
- A compromised Google bidding for the NotebookLM domain (the URL
  allowlist trusts that `notebooklm.google.com` is operated by Google).

This fork is **NOT a compliance certification.** GDPR / SOC2 / CSSF
are organisational properties; the compliance code in this repo
provides necessary primitives but is not sufficient on its own.

`SECURITY.md` has the full threat-model section.

## Trust boundaries — read-scope vs admin-scope

Tool calls are gated by `TOOLS_REQUIRING_AUTH` and
`TOOLS_EXEMPT_FROM_AUTH` in `src/index.ts`. The classification rule:

- **Read-scope** is for tools that **only read state** — answering
  questions, listing, getting status, retrieving history.
- **Admin-scope** is for anything that mutates persistent local
  state, mutates remote NotebookLM state, makes outbound HTTP, writes
  to the filesystem, or affects rate-limit decisions for other tools.

When you add a new tool, classify it explicitly. The startup
assertion in `src/index.ts` warns about unclassified tools, and
`tests/auth-scope-classification.test.ts` enforces the rule by
reading `src/index.ts` and asserting that every mutating tool is in
`TOOLS_REQUIRING_AUTH`. **If you're tempted to put a mutating tool
in `TOOLS_EXEMPT_FROM_AUTH` "for convenience", don't.** That mistake
is the entire root cause of the v2026.3.3 "read-only token can
mutate" finding.

## MCP auth modes — how the token reaches the server

The scope classification above is about WHICH tools require auth.
This section is about HOW the MCP client authenticates per call.
Three modes, picked by env vars at server startup:

- **default (per-call)** — `NLMCP_AUTH_TOKEN` only. Server reads the
  token at init, hashes it, scrubs the env var. Every tool call
  thereafter must present the token in `request.params._meta
  .authToken`. **Will NOT work with Claude Code / Codex CLI / Claude
  Desktop over stdio** — those clients have no per-call token
  injection mechanism. Use for HTTP/SSE deployments or custom MCP
  clients only.
- **stdio transport-auth (recommended for stdio)** — `NLMCP_AUTH_TOKEN`
  + `NLMCP_STDIO_TRANSPORT_AUTH=true`. At init, the server validates
  that the parent provided a token (proof of knowledge), records the
  connection as trusted, scrubs the env unconditionally, and short-
  circuits per-call auth in `validateTokenScope()` thereafter. Trust
  model: the stdio pipe IS the trust boundary — only the spawning
  parent can write to that FD. Default scope: admin.
- **stdio transport-auth (read-only)** — Above +
  `NLMCP_STDIO_TRANSPORT_AUTH_SCOPE=read`. Same trust establishment,
  but pinned to read scope; admin-scope tools rejected with
  `insufficient_scope`. Use for cautious deployments where you want
  read access but not the ability to mutate (e.g., a notebook-search
  helper that never modifies the library).

The transport-auth short-circuit lives in `MCPAuthenticator
.validateTokenScope()` (src/auth/mcp-auth.ts) right after the lockout
check and before the no-token check. When you change anything in that
method, preserve the short-circuit ordering — moving it later would
either break the lockout invariant or re-introduce the chicken-and-
egg that v2026.3.8 closed.

Legacy escape hatch `NLMCP_AUTH_KEEP_ENV=true` (v2026.3.7) keeps the
token in `process.env` so the request-handler fallback at `src/index
.ts:446` resolves to it at call time. Same operational fix as
transport-auth but with the env-leak surface. **Always prefer
transport-auth for new stdio deployments.**

## How to add a new tool — checklist

1. Schema: define the tool in `src/tools/definitions/<area>.ts`.
   Constrain inputs with JSON Schema (`pattern`, `minLength`,
   `maxLength`, `enum`, `format`). Wide-open `string` fields are a
   smell.
2. Handler: implement in `src/tools/handlers/<area>.ts`. Wrap the
   body in try/catch and return the standard `ToolResult` shape with
   `success`, `data`, and (on failure) `error`. Always include
   `data: null` on the failure path — the I330 contract requires it.
3. Validate every input through `src/utils/security.ts` or
   `src/utils/path-policy.ts` before using it. Specifically:
   - Notebook URLs → `validateNotebookUrl`
   - Notebook IDs → `validateNotebookId`
   - Session IDs → `validateSessionId`
   - Free-text questions → `validateQuestion`
   - Output file paths → `resolveExportFilePath` (path-policy)
   - Input file paths (read-from-disk) → `assertSafeLocalReadPath`
   - Source URLs (any HTTPS) → `validateSourceUrl`
4. Audit-log the call with `audit.tool(name, args, success,
   duration_ms, error?)`. Sanitise large or sensitive args before
   logging — `summarizeArgs` in `audit-logger.ts` does this.
5. Register the handler in the `toolRegistry` Map in `src/index.ts`.
6. Classify the tool: add to `TOOLS_REQUIRING_AUTH` or
   `TOOLS_EXEMPT_FROM_AUTH` in `src/index.ts`. Default is
   "uncertain — assume admin until proven otherwise".
7. Write at least one regression test under `tests/` that exercises
   the validator for this tool's most adversarial input.
8. If the tool is destructive, require an explicit `confirm: true`
   in the schema and refuse otherwise (see `delete_document` for
   the pattern).

## How to add a new persisted store — checklist

Persisted state is a trust boundary: data read from disk must be
re-validated, not assumed clean. The notebook library was the
canonical "got this wrong, then fixed it" example.

1. On read, re-validate every record. Drop / quarantine invalid
   records with a logged warning and persist the cleaned form. See
   `NotebookLibrary.loadLibrary()` for the pattern.
2. Use `getSecureStorage()` (`src/utils/crypto.ts`) for any record
   that contains credentials / session state / tokens. The save
   helper is **fail-closed** — it throws if encryption is disabled
   and `NLMCP_ALLOW_PLAINTEXT_CREDENTIAL_STORAGE` is not `true`.
3. File permissions: 0o600 for files, 0o700 for directories. Use
   `writeFileSecure` and `mkdirSecure` from
   `src/utils/file-permissions.js` rather than raw `fs.writeFileSync`.
4. Hash-chain the records if integrity matters (see `audit-logger.ts`
   for the pattern).

## Path policy — when to use which helper

`src/utils/path-policy.ts` is the single source of truth for
filesystem path containment and the credential-directory denylist.
Three exported helpers, each with a specific purpose:

- `resolveExportFilePath(userPath, defaultName)` → for **outbound
  writes**. Confines to `NLMCP_EXPORT_DIR` (or `$HOME`),
  realpath-resolves the parent so symlinks can't escape, refuses
  symlink leafs, and refuses `.bashrc`/`.zshrc`-style basenames.
  Use for any `output_file` / `output_path` parameter.
- `assertSafeLocalReadPath(userPath)` → for **single-file reads**.
  Realpath-resolves, requires the path to exist and be a regular
  file, refuses anything in the denylist, refuses `.env*` variants.
  Use for any `file_path` parameter that names a file the server
  will read and forward to a third-party API.
- `resolveAndCheckFolderPath(userPath)` + `assertSafeFolderEntryPath
  (realTarget, allowedBases)` → for **recursive folder scans**.
  The first validates the entry point against the
  `NLMCP_FOLDER_ALLOWLIST`; the second is called per-entry inside the
  scan loop after `fs.realpath` to guard against symlinks that
  escape the allowlist or land in denied paths.

Adding a new credential location to defend? Edit `DENIED_SEGMENTS_RAW`
in `src/utils/path-policy.ts`. Each entry is forward-slash separated
and case-insensitively matched against any consecutive path-segment
sequence. Use the `Library/Application Support/...` form for macOS
paths, `.config/...` for Linux, `AppData/Roaming/...` or
`AppData/Local/...` for Windows.

## URL validation conventions

Three modules, three layers:

`src/utils/security.ts`:

- `validateNotebookUrl(url)` → for navigation URLs. Allowlists the
  `notebooklm.google.*` family. **Use at every persistence boundary
  AND every navigation site**, not just at MCP input. The browser
  navigation in `SessionManager.getOrCreateSession` re-validates,
  even when the URL came from "trusted" persisted state.
- `validateSourceUrl(url)` → for content source URLs. Blocks
  dangerous schemes (`javascript:`, `data:`, `file:`, `vbscript:`,
  `about:`), enforces HTTPS, but otherwise permissive on host (a
  "source" can legitimately be any third-party page).

`src/utils/url-validation.ts` (shared SSRF defence helpers, factored
in v2026.3.5 from the webhook-dispatcher's inline logic):

- `isPrivateIPv4(addr)` / `isPrivateIPv6(addr)` / `isPrivateHost(host)`
  — synchronous lexical checks. Cover loopback, link-local (incl.
  AWS/GCP metadata 169.254/16), RFC 1918, RFC 6598 CGNAT, multicast,
  IPv4-mapped IPv6, and the `localhost` / `*.local` / `*.internal`
  family.
- `validateOutboundUrl(url, { allowHttp?, resolveDns?, dnsTimeoutMs? })`
  — async URL gate. Parses, enforces scheme, applies the private-host
  check lexically, and (when `resolveDns: true`) resolves the host
  and re-checks every resulting IP. Use this for code paths that can
  await; webhook-dispatcher uses it with `resolveDns: true` at both
  config time and send time (DNS rebinding defence).
- `validateOutboundUrlSync(url, { allowHttp? })` — synchronous
  variant for code paths that can't await. Used by `alert-manager.ts`
  and `siem-exporter.ts` before `https.request`.
- `validateNotebookLMMediaUrl(url)` — strictest variant. Use ONLY for
  URLs scraped from the browser DOM that the server is about to
  navigate to via `page.goto(...)`. HTTPS only + no private/loopback
  IPs + hostname suffix on a hard-coded NotebookLM media-download
  allowlist (`*.google.com`, `*.googleusercontent.com`,
  `*.googleapis.com`). Calling `page.goto` on a DOM-scraped URL
  without this gate is an SSRF — a prompt-injection chain through a
  malicious source document can plant `<a download href="file:///
  etc/passwd">` and the authenticated browser will follow it. See
  v2026.3.5 CRITICAL fix in `audio-manager.downloadAudio`.

**Rule:** every code path that issues outbound HTTP (or navigates a
browser context to an attacker-influenced URL) MUST go through one
of the helpers above. Never issue `https.request`, `fetch`, or
`page.goto` against a string the server didn't originate or fully
validate.

## Credential lifecycle

`LOGIN_PASSWORD` and `GEMINI_API_KEY` are read once from `process.env`
into a `SecureCredential` (5-min TTL) at config-load time, then the
env vars are deleted via `delete process.env.X`. Consumers go
through `getSecureLoginPassword()` / `getSecureGeminiApiKey()` and
must `.wipe()` on shutdown / error paths.

The shutdown handler in `src/index.ts` calls
`wipeGlobalCredentials()` (exported from `src/config.ts`) on every
exit path — SIGINT, SIGTERM, uncaughtException, unhandledRejection,
and the error-recovery path inside `shutdown()` itself. This is
mandatory; `SecureCredential.wipe()` is idempotent so over-calling
is safe.

If you add a new credential env var:

1. Read it into a `SecureCredential` in `src/config.ts`'s
   `applyEnvOverrides`.
2. `delete process.env.X` immediately after.
3. Expose a `getSecure<Name>()` accessor.
4. Audit-log a `secrets_*` event when the credential is consumed.
5. Add the env var name to the secrets-scanner pattern set if it
   matches a recognisable token shape.
6. Extend `wipeGlobalCredentials()` in `src/config.ts` to wipe the
   new holder.

## Crypto invariants

`SecureStorage.save()` is **fail-closed**. If encryption is disabled
and `NLMCP_ALLOW_PLAINTEXT_CREDENTIAL_STORAGE` is not exactly
`"true"`, the save throws and emits a `plaintext_save_refused`
security audit event. Do not "improve" this by silently falling
back; the regression test
`tests/crypto-fail-closed.test.ts` will catch any reintroduction.

The encryption is local-at-rest only. Both the wrap key and the
encrypted blob live on the same host. The threat model section
above spells this out.

## Audit logging

Hash-chained per-day file with cross-day chain linkage. Tampering is
detected on read (`AuditLogger.verifyIntegrity()`).

**Hash-chain invariant (v2026.3.5):** the chain link
(`previousHash` → `hash`) is stamped INSIDE `flushEvent` under the
per-day file lock — NOT in `log()` before enqueueing. This ensures
two concurrent `log()` calls produce events whose chain reflects
actual write order, not the order of the now-asynchronous `log()`
invocations. Pre-fix this race surfaced as confusing "Hash chain
broken" errors that weren't actually tampering. **Don't move the
hash computation back into `log()` — the regression test
`tests/external-review-round4-fixes.test.ts` will catch it.**

Rules of thumb:

- Every tool call: `audit.tool(name, args, success, duration_ms,
  error?)`. **All admin-scope tools must audit, including library
  mutations** (`add_notebook`, `update_notebook`, `remove_notebook`,
  `select_notebook`). Pre-v2026.3.5 the four library handlers were
  silent; now they're not.
- Every auth event: `audit.auth(event, success, details?)`.
- Every security event: `audit.security(event, severity, details?)`.
- Sanitise free-text inputs before logging via `sanitizeForLogging`.
- Never log a literal token, password, or auth header value.
  `summarizeArgs` and the secrets-scanner are defence-in-depth, not a
  license to be careless.
- **URL fields in audit records: log host only, never the full URL.**
  Slack/Discord/Teams webhook URLs embed credential tokens in the
  path; `recordWebhookChange` and `safeNotebookHost` (in
  `notebook-management.ts`) are the canonical patterns.

**Shutdown flush is mandatory.** The shutdown handler in
`src/index.ts` awaits `getAuditLogger().flush()` AND
`getQueryLogger().flush()` before `process.exit(0)`. Without this,
events queued in the final ms are lost (the loggers' own
`beforeExit` handlers don't fire on `process.exit`). Don't remove
either flush.

## Webhooks

`src/webhooks/webhook-dispatcher.ts` validates URLs at **two**
points: at config time (`validateWebhookUrl` in `addWebhook` /
`updateWebhook`) and at send time (re-runs `validateWebhookUrl`
inside `sendWithRetry`). Both are needed — DNS rebinding can move a
host between RFC 1918 and public space between config and send.

`list_webhooks` returns a redacted `WebhookConfigPublic` DTO (host
only + `hasSecret` boolean), never the full `WebhookConfig`. The
full URL would leak Slack/Discord/Teams credential tokens to
read-scope callers. `WebhookDispatcher.loadStore()` migrates any
legacy persisted `secret` field into the in-memory
`webhookSecrets` SecureCredential map and scrubs the persisted
record (idempotent). `WebhookDispatcher.whenInitialized()` is
exposed so callers (and the MCP `list_webhooks` handler) can wait
for env-driven init to settle before observing the store.

**Outbound HTTP rule (v2026.3.5):** every code path that issues
outbound HTTP — webhook delivery, alert-manager, SIEM exporter,
audio-download navigation — uses one of the helpers from
`src/utils/url-validation.ts`. `alert-manager.ts` and
`siem-exporter.ts` use `validateOutboundUrlSync` even though their
URLs come from env vars (defence-in-depth + codebase consistency).
When adding any new outbound HTTP surface, do the same.

## Build / test / verify

```bash
npm ci --ignore-scripts          # install deps without lifecycle scripts
npx tsc --noEmit                 # type-check (must produce no output)
npx vitest run                   # full test suite (837+ tests, all must pass)
npx vitest run --coverage        # coverage report under coverage/
node ./scripts/check-exact-pins.cjs  # pin-enforcement gate
npm run build                    # tsc + chmod
```

Before committing any change:

1. `npx tsc --noEmit` clean.
2. `npx vitest run` — all tests pass.
3. If you added or changed validation logic, add a regression test
   under `tests/` that pins the new behaviour.

## Supply-chain rules

- **Every direct dep in `package.json` is exact-version pinned.** No
  `^`, no `~`, no `>=`, no `*`, no `latest`. The CI gate
  (`scripts/check-exact-pins.cjs`) refuses to build otherwise.
- `overrides` in `package.json` pins transitive packages that need a
  specific version. Don't widen these to ranges either.
- `npm ci --ignore-scripts` everywhere except the one sanctioned
  install step (`npx patchright install chromium` in the archived
  Dockerfile). Lifecycle scripts of transitive deps must not run.
- Before adding any new dep:
  1. Confirm it's signed (Sigstore — `npm audit signatures`).
  2. Confirm it has more than one maintainer (or accept the bus-factor
     risk explicitly).
  3. Pin to an exact version in `dependencies` AND in `overrides` if
     it has install scripts.

## Commits, signing, lineage

- Commits are SSH-signed using `~/.ssh/id_ed25519`. Repo-local git
  config is already set; `git commit` will sign automatically.
- The same key is registered as a "Signing Key" on GitHub.
- When making an onward fork (someone forks this fork), update the
  `_lineage` block in `package.json` to extend the chain. The block
  is structured: each entry has `name`, `author`, `repository`, and
  `role`.

## Documentation conventions

- `README.md` — user-facing, install + how-to.
- `SECURITY.md` — threat model + per-mechanism description.
- `CHANGELOG.md` — Keep-a-Changelog format. Every release MUST have
  an entry. Security fixes go under "Security — …" subsections; trim
  the noise.
- `docs/security-reviews/` — verbatim review reports, indexed by
  `docs/security-reviews/README.md`. Use
  `docs/security-reviews/REVIEW_PROMPT_TEMPLATE.md` as the starting
  template for any future review round.
- `docs/COMPLIANCE-SPEC.md`, `docs/SECURITY_IMPLEMENTATION_PLAN.md`,
  `docs/SECURITY-FORK-OPPORTUNITIES.md` — reference docs from earlier
  phases. Update if you significantly change the relevant area.

## Deployment artifacts

The `Dockerfile`, `.dockerignore`, and `smithery.yaml` were moved out
of this repo on 2026-05-10 to a sibling archive directory:
`<parent-dir>/notebooklm-mcp-secure-archive/docker-deploy/`. The
README inside that archive explains why and what would have to
change to put them back. **Don't reintroduce them to this repo
without first adding an HTTP transport to `src/index.ts`** —
shipping a Dockerfile that's not actually used confuses operators.

## When external review findings come in

Process:

1. Save the verbatim report into `docs/security-reviews/` as
   `<REVIEWER>_<ROUND>.md` or `<REVIEWER>-FULL-REVIEW-V<version>.md`.
   Don't paraphrase or "tidy up" the report — verbatim is the point.
2. Add a row to `docs/security-reviews/README.md` indexing the new
   report.
3. Deduplicate findings across reviewers, filter to confidence ≥ 7.
4. For each genuine finding, write the code fix AND a regression
   test that pins the fix.
5. Cut a new minor release (e.g. v2026.3.X+1). Append a "Whole-Repo
   External Review (Round N)" subsection to the new CHANGELOG entry,
   listing every fix with severity, finding source, conf, and a
   one-paragraph mechanism description.
6. Verify with `npx tsc --noEmit` and `npx vitest run` after every
   batch of fixes.

The four prior rounds (v2026.3.3 — initial CLAUDE_REVIEW + CODEX_REVIEW,
v2026.3.4 — first whole-repo round CODEX_FULL_FINDINGS +
GEMINI31Pro_FULL_FINDINGS, v2026.3.5 — second whole-repo round
CLAUDE-FULL-REVIEW-V2026.3.4 + CODEX_FULL_FINDINGS-V2026.3.4 +
GEMINI31Pro_FULL_FINDINGS-V2) are the canonical examples of this
process. Each round produces fewer findings than the last, but
every round has produced at least one real bug — including
v2026.3.5's CRITICAL audio-SSRF that three rounds missed.

**Commit structure for a review round** (battle-tested across four
releases):

1. `fix(security): <CRITICAL/HIGH bundle>` — the highest-severity
   findings as one commit each or grouped by area.
2. `fix(security): <medium bundle>` — medium-severity findings
   bundled by area (e.g. "library audit + shutdown flush").
3. `fix(security): <low bundle>` — low-severity findings bundled.
4. `test+docs: regression tests + verbatim review reports` — the
   regression tests file plus the verbatim review reports + any
   `docs/security-reviews/README.md` index update.
5. `release: vX.Y.Z — <round summary>` — package.json + server.json
   version bump + CHANGELOG entry + README "What's New" update.

Then `git tag -s vX.Y.Z`, `git push origin main`, `git push origin
vX.Y.Z`, `gh release create vX.Y.Z --repo OhJayGee/...`.

**Note on `gh release create`:** pass `--repo OhJayGee/notebooklm-mcp-secure`
explicitly. Without it, `gh` defaults to the upstream remote
(`Pantheon-Security/...`) which fails with "tag does not exist".

## Common foot-guns to avoid

- **Don't** introduce a range specifier in `package.json`. Use exact
  versions. CI will fail.
- **Don't** put a mutating tool in `TOOLS_EXEMPT_FROM_AUTH`. The
  source-text-driven `tests/auth-scope-classification.test.ts` will
  fail.
- **Don't** silently fall back to plaintext writes in `crypto.ts`.
  The fail-closed regression test will fail.
- **Don't** call `fs.writeFile` / `fs.writeFileSync` in a tool
  handler with a caller-supplied path. Route through
  `resolveExportFilePath` first.
- **Don't** call `fs.readFile` / `fs.createReadStream` /
  `setInputFiles` in a tool handler with a caller-supplied path.
  Route through `assertSafeLocalReadPath` first.
- **Don't** call `page.goto(...)` / `fetch(...)` / `https.request(...)`
  with an attacker-influenced URL. Route through the appropriate
  `url-validation.ts` helper:
    - DOM-scraped URLs the browser will navigate to →
      `validateNotebookLMMediaUrl`
    - User-configured webhook URL → `validateWebhookUrl` (in
      webhook-dispatcher.ts) at config AND send time
    - Env-configured outbound URLs → `validateOutboundUrlSync`
- **Don't** capture `this.previousHash` in `AuditLogger.log()` and
  pass it through to `flushEvent`. The hash chain link MUST be
  stamped inside `flushEvent` under the file lock — otherwise
  concurrent `log()` calls produce a branched chain. The regression
  tests in `tests/external-review-round4-fixes.test.ts` (Finding
  G2) will catch a regression here immediately.
- **Don't** return raw `err.message` to MCP clients. Route through
  `getSanitizedErrorMessage` from `src/tools/handlers/error-utils.ts`.
  This strips both absolute paths AND stack-frame fragments.
  Especially important for `PathPolicyError` returns.
- **Don't** `process.exit(0)` from a shutdown handler without first
  awaiting `getAuditLogger().flush()` and `getQueryLogger().flush()`.
  `process.exit` doesn't trigger `beforeExit` (Node docs explicit),
  so events queued in the final ms get lost — and a missing event
  silently breaks hash-chain verification on the next run.
- **Don't** add a new admin-scope tool without `audit.tool(...)`.
  The library handlers (add/update/remove/select_notebook) were the
  canonical "missed audit" example before v2026.3.5.
- **Don't** `https.request` directly anywhere. Use
  `validateOutboundUrlSync` (from `src/utils/url-validation.ts`)
  before issuing the request, even for env-trusted URLs.
- **Don't** trust persisted data without re-validating it on read.
  Examples that DO this: notebook library, webhook config (legacy
  secret scrub), audit log (hash chain), quota state (schema
  validator). When you add a new persisted store, follow the same
  pattern.
- **Don't** widen the `enterpriseCompliance` or `securityHardening`
  blocks in `package.json` with marketing-grade booleans. Each entry
  must describe its actual mechanism.
- **Don't** edit `docs/security-reviews/*.md` to "tidy them up".
  They're verbatim reports and lose value if they're paraphrased.
  If you spot something wrong, append a footnote rather than editing
  the body.
- **Don't** delete the `// Added by Pantheon Security for hardened
  fork.` source comments. They're historical attribution under the
  MIT licence.
- **Don't** issue `gh release create` without `--repo
  OhJayGee/notebooklm-mcp-secure`. The default uses the upstream
  remote and fails with "tag does not exist".

## Patterns that have proved load-bearing

These are conventions established across the v2026.3.3 → v2026.3.5
review rounds. Don't change them without first checking that the
corresponding regression test still passes:

- **Persisted-state validation on read.** Every store re-validates
  on load and falls through to a safe default on rejection.
  `NotebookLibrary.loadLibrary`, `WebhookDispatcher.loadStore`,
  `QuotaManager.loadSettings`, and the audit log's hash-chain
  verification all follow this shape.
- **Two-tier URL validation: config-time + send-time.** Webhook
  URLs are validated when added AND before each delivery (DNS
  rebinding defence). Notebook URLs are validated at every library
  write AND at every browser navigation.
- **Hash chain inside the lock.** Audit-log chain links are stamped
  inside the file-lock critical section, not pre-enqueue.
- **Response validation factored shared.**
  `applyValidationToModelOutput(text)` from
  `src/utils/response-validator.ts` is the single helper used by
  `ask_question`, all four Gemini handlers, and per-message inside
  `get_notebook_chat_history`. New handlers that return model
  output go through this.
- **Audit URL fields are host-only.** Every audit record that
  references a URL logs the host, not the full URL.
  `safeNotebookHost` (in `notebook-management.ts`) and
  `safeHost` (in `webhook-dispatcher.ts`) are the two helpers.

## When in doubt

The four prior review rounds in `docs/security-reviews/` are the
authoritative record of what's been considered. The CHANGELOG
entries for v2026.3.3, v2026.3.4, and v2026.3.5 have the per-finding
fix maps. When in real doubt about a security-shaped change, run
the toned-down Template 2 prompt from
`docs/security-reviews/REVIEW_PROMPT_TEMPLATE.md` against an
external reviewer before shipping.
