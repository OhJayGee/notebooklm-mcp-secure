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

## Credential lifecycle

`LOGIN_PASSWORD` and `GEMINI_API_KEY` are read once from `process.env`
into a `SecureCredential` (5-min TTL) at config-load time, then the
env vars are deleted via `delete process.env.X`. Consumers go
through `getSecureLoginPassword()` / `getSecureGeminiApiKey()` and
must `.wipe()` on shutdown / error paths.

If you add a new credential env var:

1. Read it into a `SecureCredential` in `src/config.ts`'s
   `applyEnvOverrides`.
2. `delete process.env.X` immediately after.
3. Expose a `getSecure<Name>()` accessor.
4. Audit-log a `secrets_*` event when the credential is consumed.
5. Add the env var name to the secrets-scanner pattern set if it
   matches a recognisable token shape.

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

Rules of thumb:

- Every tool call: `audit.tool(name, args, success, duration_ms,
  error?)`.
- Every auth event: `audit.auth(event, success, details?)`.
- Every security event: `audit.security(event, severity, details?)`.
- Sanitise free-text inputs before logging via `sanitizeForLogging`.
- Never log a literal token, password, or auth header value.
  `summarizeArgs` and the secrets-scanner are defence-in-depth, not a
  license to be careless.

## Webhooks

`src/webhooks/webhook-dispatcher.ts` validates URLs at **two**
points: at config time (`validateWebhookUrl` in `addWebhook` /
`updateWebhook`) and at send time (re-runs `validateWebhookUrl`
inside `sendWithRetry`). Both are needed — DNS rebinding can move a
host between RFC 1918 and public space between config and send.

When adding a new outbound HTTP surface elsewhere in the codebase,
route through the same `validateWebhookUrl` (or factor it into a
shared `validateOutboundUrl` if the use case is a
config-but-not-webhook URL).

`alert-manager.ts` and `siem-exporter.ts` currently take URLs from
env vars (trusted) and skip validation. Don't widen them to
non-env-var sources without adding `validateWebhookUrl` first.

## Build / test / verify

```bash
npm ci --ignore-scripts          # install deps without lifecycle scripts
npx tsc --noEmit                 # type-check (must produce no output)
npx vitest run                   # full test suite (775+ tests, all must pass)
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
   `<REVIEWER>_<ROUND>.md`.
2. Add a row to `docs/security-reviews/README.md` indexing the new
   report.
3. Deduplicate findings across reviewers, filter to confidence ≥ 7.
4. For each genuine finding, write the code fix AND a regression
   test that pins the fix.
5. Append a "Security — External Review Findings Addressed"
   subsection to the current release's CHANGELOG entry, listing every
   fix.
6. Verify with `npx tsc --noEmit` and `npx vitest run`.

The two prior rounds (the v2026.3.3 work, captured in
`docs/security-reviews/`) are the canonical examples of this process.

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
- **Don't** trust persisted data without re-validating it on read.
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

## When in doubt

The two prior review rounds in `docs/security-reviews/` are the
authoritative record of what's been considered. The CHANGELOG entry
for v2026.3.3 has the per-finding map.
