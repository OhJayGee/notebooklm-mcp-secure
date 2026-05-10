# Security Review: notebooklm-mcp-secure

Date: 2026-05-09

Scope: adversarial source review of the current directory as an MCP server intended for Codex/Claude. I reviewed the MCP dispatcher, auth model, browser/session handling, NotebookLM source management, Gemini document upload, webhooks, local storage/encryption, and security utilities. I did not run dynamic exploit tests against Google services.

## Executive Summary

This is materially hardened compared with a typical hobby MCP server, but it still has several high-impact issues. The most serious problems are not in obvious places like webhook SSRF; they are in trust-boundary mismatches:

- Tool-level "read" access can mutate state and upload local files.
- Locally stored notebook URLs are trusted later without revalidation.
- Browser sessionStorage restoration uses the configured notebook origin, so a poisoned notebook URL can receive saved NotebookLM sessionStorage.
- Single-file upload paths lack the folder allowlist/denylist that `add_folder` already added.

In a threat model where the MCP client model can be prompt-injected into calling tools, or where a low-privilege/read-only MCP token is exposed, these are serious.

## Findings

### Critical: Stored Trusted-State Notebook URL Poisoning Can Navigate the Authenticated Browser to Attacker Origins and Leak SessionStorage

Affected code:

- `src/tools/handlers/notebook-management.ts:38-52` adds notebooks without validating `args.url`.
- `src/tools/handlers/notebook-management.ts:125-130` starts update handling without validating replacement URLs.
- `src/tools/handlers/ask-question.ts:203-219` loads notebook URLs from the library and does not re-run `validateNotebookUrl`.
- `src/tools/handlers/gemini.ts:714-737` does the same for `get_notebook_chat_history`.
- `src/session/session-manager.ts:88-95` only checks `targetUrl.startsWith("http")`.
- `src/session/browser-session.ts:107-112` navigates to `this.notebookUrl`.
- `src/session/browser-session.ts:321-345` restores saved sessionStorage into whatever origin was derived from `this.notebookUrl`.

Why this matters:

This is not about the direct `notebook_url` argument to `ask_question`; that path is validated with `validateNotebookUrl`. The vulnerability is that a notebook URL can first be written into the local library through `add_notebook` or `update_notebook`, then later reused as trusted persisted state. A caller with only a read-scoped MCP token can store `https://attacker.example/...`, select it as active, then trigger `ask_question` or `get_notebook_chat_history` without passing a direct `notebook_url`. The server will resolve the active notebook from the library and navigate its persistent browser context to the attacker URL. Worse, `BrowserSession.restoreSessionStorage()` derives the target origin from the poisoned stored URL and writes saved NotebookLM sessionStorage into that page's origin. A malicious page can read its own sessionStorage and exfiltrate those values.

Recommended fix:

- Validate notebook URLs at every write into the library with `validateNotebookUrl`.
- Revalidate every persisted library URL immediately before browser navigation. Treat local library data as untrusted stored input, not as already-safe state.
- Change `SessionManager.getOrCreateSession()` to require `validateNotebookUrl`, not `startsWith("http")`.
- In `BrowserSession.restoreSessionStorage()`, only restore when `targetOrigin === "https://notebooklm.google.com"` or another explicitly allowed NotebookLM origin.
- Add regression tests for poisoned library entries and active notebook URL poisoning.

### Critical: `add_source` and `create_notebook` Can Upload Arbitrary Local Files

Affected code:

- `src/index.ts:126-136` classifies `add_source`, `create_notebook`, and `batch_create_notebooks` as non-admin/read-scope tools.
- `src/tools/handlers/notebook-creation.ts:53-64` validates URL sources but performs no policy validation for `source.type === "file"`.
- `src/tools/handlers/notebook-creation.ts:397-410` repeats the same gap for `add_source`.
- `src/notebook-creation/source-manager.ts:669-696` resolves any file path and uploads it with `setInputFiles`.
- `src/notebook-creation/source-manager.ts:1202-1244` does the same through the notebook-creation path.

Why this matters:

`add_folder` has an allowlist and sensitive-directory denylist, but the single-file path bypasses it entirely. A malicious tool call can upload `~/.ssh/id_rsa`, cloud credential files, `.env`, project source, or other readable local files to NotebookLM. These tools are in the standard profile and are treated as read-scope by the dispatcher.

Recommended fix:

- Move all file uploads through one shared path-policy function.
- Require admin scope and explicit confirmation for local file upload.
- Enforce an allowlist base, sensitive-directory denylist, symlink resolution, file type allowlist, max size, and regular-file checks.
- Consider disabling `source.type: "file"` by default for MCP clients unless the user opts in.

### High: The Read-Only Token Is Not Read-Only

Affected code:

- `src/index.ts:126-136` places mutating and externally side-effecting tools in `TOOLS_EXEMPT_FROM_AUTH`.
- `src/index.ts:397-401` gives every non-admin tool only `"read"` authentication requirements.

Examples currently available to read-scope callers:

- Local library mutation: `add_notebook`, `update_notebook`, `remove_notebook`, `select_notebook`.
- Remote/browser side effects: `create_notebook`, `batch_create_notebooks`, `sync_library`, `add_source`, `remove_source`, audio/video/table generation.
- Quota/state mutation: `set_quota_tier`, session close/reset when advanced tools are enabled.
- Local-file exfiltration through `add_source` and `create_notebook` file sources.

Recommended fix:

- Replace `TOOLS_EXEMPT_FROM_AUTH` with explicit scopes such as `read`, `query`, `write_library`, `browser_write`, `local_file_read`, `admin`.
- Treat all local file reads, remote writes, browser actions, local writes, deletion, and settings mutation as admin or explicit opt-in scopes.
- Add a startup assertion that fails closed for any unclassified tool.

### High: Advanced Chat-History Export Writes Arbitrary Files

Affected code:

- `src/tools/handlers/gemini.ts:678-687` exposes `output_file`.
- `src/tools/handlers/gemini.ts:850-863` writes directly to `args.output_file`.
- `src/index.ts:136` classifies `get_notebook_chat_history` as read-scope; `src/index.ts:180` only hides it unless advanced tools are enabled.

Why this matters:

When `NLMCP_ADVANCED_TOOLS=1`, a read-scope caller can write arbitrary JSON anywhere the server process has permission. This can overwrite user files, poison config, or plant data in a project checkout. The handler also uses unvalidated library URLs as described in the first finding.

Recommended fix:

- Remove arbitrary output paths from this tool, or confine writes to a dedicated export directory using `path.relative` checks like `export_library`.
- Require admin scope for any filesystem write.
- Use secure write permissions and no-clobber semantics unless overwrite is explicitly confirmed.

### Medium: Gemini `upload_document` Is an Admin-Gated Arbitrary Local File Upload

Affected code:

- `src/tools/handlers/gemini.ts:305-314` accepts `file_path`.
- `src/gemini/gemini-client.ts:492-525` checks existence and uploads that exact local file to Gemini.

Why this matters:

This is admin-gated and hidden behind advanced tools by default, so it is less severe than `add_source`. Still, in an MCP setting an admin token is often placed in client config; if the model can be prompt-injected into using this tool, any readable local file can be uploaded to a third-party API.

Recommended fix:

- Reuse the same local-file policy as NotebookLM uploads.
- Require explicit user confirmation naming the exact resolved path and destination.
- Deny sensitive directories by default.

### Medium: Encryption Fails Open to Plaintext Sensitive Files

Affected code:

- `src/utils/crypto.ts:415-440` catches secure-storage initialization errors and sets `this.config.enabled = false`.
- `src/utils/crypto.ts:583-587` writes plaintext when encryption is disabled.
- `src/utils/crypto.ts:602-606` also writes plaintext when no key is available.

Why this matters:

If the encryption key is misconfigured, the PQ key store is corrupted, or initialization otherwise fails, later saves can write browser state and sessionStorage unencrypted. That is a bad failure mode for credentials.

Recommended fix:

- Fail closed for credential-bearing files.
- Only allow plaintext fallback behind an explicit environment variable such as `NLMCP_ALLOW_PLAINTEXT_CREDENTIAL_STORAGE=true`.
- Make `saveBrowserState()` fail if secure storage cannot initialize.

### Medium: Webhook SSRF Protection Is Only Time-of-Configuration

Affected code:

- `src/webhooks/webhook-dispatcher.ts:124-180` validates scheme, host, and DNS resolution.
- `src/webhooks/webhook-dispatcher.ts:858-890` validates only when a webhook is added.
- `src/webhooks/webhook-dispatcher.ts:897-906` validates only when a URL is changed.
- `src/webhooks/webhook-dispatcher.ts:495-510` later sends with plain `fetch(webhook.url)`.

Why this matters:

Validation at add/update time does not protect against DNS rebinding or later DNS changes. A domain can validate to a public IP at configuration time and resolve to `169.254.169.254`, loopback, or private space at delivery time. Redirects are blocked, which is good, but DNS rebinding remains.

Recommended fix:

- Re-run `validateWebhookUrl()` immediately before each delivery.
- For stronger protection, resolve and connect to the validated public IP while preserving TLS SNI/Host, or use an outbound proxy with egress policy.

### Low: Auth Tokens Are Printed Into Logs/Stdout

Affected code:

- `src/auth/mcp-auth.ts:230-243` logs first-run tokens and setup commands containing the token.
- `src/auth/mcp-auth.ts:641-648` prints rotated tokens to stdout.

Why this matters:

MCP servers commonly run under clients that capture stderr/stdout into logs. Printing bearer tokens increases the chance that the token lands in IDE logs, shell scrollback, transcripts, or diagnostics.

Recommended fix:

- Only display tokens when attached to an interactive TTY.
- Prefer writing one-time setup material to a `0600` file and printing the path.
- Mask tokens in logs after initial generation.

### Low: `validateFilePath()` Has an Unsafe Prefix Check

Affected code:

- `src/utils/security.ts:262-274`.

Why this matters:

The helper currently accepts paths like base `/tmp/base` and resolved `/tmp/base-evil/file` because it uses `startsWith(normalizedBase)`. It appears unused today, but it is a security utility and likely to be reused.

Recommended fix:

Use `path.relative(base, resolved)` and require `rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))`, as done in `resolveExportPath()`.

## Positive Notes

- Webhook URLs block obvious localhost/private/link-local targets and redirects.
- `add_folder` has the right shape of local file policy; the issue is that other upload paths do not reuse it.
- Export path confinement in `export_library` uses `path.relative`, which is the safer pattern.
- Authentication is enabled by default and admin tools are forced even when global auth is disabled.
- Audit logs, permission helpers, and response validation show substantial hardening effort.

## Recommended Priority Order

1. Fix notebook URL validation and sessionStorage origin handling.
2. Centralize local-file upload policy and apply it to `add_source`, `create_notebook`, and `upload_document`.
3. Rework tool scopes so read-only cannot mutate state or read local files.
4. Confine all tool-controlled filesystem writes.
5. Change secure storage to fail closed for credential data.
6. Revalidate webhook destinations at send time.
