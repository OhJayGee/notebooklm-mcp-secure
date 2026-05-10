# CLAUDE_REVIEW.md — Adversarial Security Review

**Target:** `notebooklm-mcp-secure` v2026.3.2
**Date:** 2026-05-09
**Scope:** Whole repository (working tree clean; reviewing the project as it would be installed/run, not a single PR diff).
**Methodology:** Adversarial read of every security-claim-bearing module. Trust nothing. Validate that the marketing matches the implementation, then look for real attack vectors a prompt-injected MCP client (Claude/Codex), a co-located local user, or a malicious upstream notebook owner could chain.

---

## TL;DR

The codebase is **substantially better than an unhardened MCP wrapper**. Most of the load-bearing controls are real implementations (token hashing, hash-chained audit logs, webhook SSRF protection with DNS resolution, secrets scanner with sane patterns, secure-by-default auth, file-permission hardening, post-quantum hybrid encryption). It's not pure security theatre.

However, several headline claims oversell what they do, and there is one **concrete, exploitable bug** I'd block a release on:

1. **HIGH — Arbitrary file-write primitive** in `get_notebook_chat_history` via the `output_file` parameter. Reachable from a *read-scope* MCP token (or with auth disabled). Writes attacker-influenced JSON to any path the process can write — `~/.ssh/authorized_keys`, `~/.zshrc`, `~/.bashrc`, etc. This is the kind of bug a prompt-injection chain through a malicious notebook is purpose-built to exploit.

The rest of the findings are advisory — defense-in-depth gaps, claim/reality mismatches, and adversary-relevant context the README doesn't surface.

---

## Findings (high confidence)

### Vuln 1: Path traversal / arbitrary file write — `src/tools/handlers/gemini.ts:862`

* **Severity:** High
* **Category:** `path_traversal` / `arbitrary_file_write`
* **Confidence:** 9/10
* **Auth gate:** None for read-scope. The tool is in `TOOLS_EXEMPT_FROM_AUTH` (`src/index.ts:136`), so the read-only token works, and with `NLMCP_AUTH_DISABLED=true` no token is required at all.

**Description.** `handleGetNotebookChatHistory` does:

```ts
await fs.writeFile(args.output_file, JSON.stringify(exportData, null, 2));
```

`args.output_file` arrives directly from MCP tool input. The JSON schema in `src/tools/definitions/chat-history.ts` constrains only `maxLength: 500` — no `pattern`, no allowlist base, no `path.resolve` + `path.relative` containment check. Compare to `handleExportLibrary` in `src/tools/handlers/system.ts`, which **does** validate via `resolveExportPath` (containment to `NLMCP_EXPORT_DIR` or `os.homedir()`); the same hardening is missing here.

**Exploit Scenario.** This is an MCP server. Its callers are AI agents (Claude/Codex) that routinely process untrusted text — pages they browse, notebooks shared with them, files passed through. A prompt-injection payload embedded in a NotebookLM source — or in any context the agent is asked to summarize — can instruct the model to emit a tool call shaped like:

```json
{
  "name": "get_notebook_chat_history",
  "arguments": {
    "notebook_id": "<any notebook the user owns>",
    "output_file": "/Users/<victim>/.ssh/authorized_keys"
  }
}
```

The chat history JSON is attacker-influenced, because the messages are scraped from a NotebookLM page the attacker controls (any notebook with `class=from-user-container`/`to-user-container` in the DOM). They can plant content of their choosing into the rendered chat. The resulting file write overwrites the SSH `authorized_keys` (or `~/.zshrc`, crontab files, IDE settings, etc.) with content that *contains* attacker-chosen text — wrapped in JSON formatting, but multi-line tools that tolerate JSON noise (or are clobbered to denial-of-state) suffice for many privilege chains. Even just **destroying** SSH or shell config is a high-impact local foothold.

**Why the existing protections do not stop this:**
- `validateNotebookUrl` only validates the notebook source, not the output path.
- `response-validator` only inspects answers, not tool arguments.
- The tool is *exempt* from admin auth, so the "admin token required for sensitive ops" mitigation does not apply.
- `secrets-scanner` runs over webhook payloads and responses, not over filesystem write paths.

**Recommended fix (in priority order):**

1. Resolve `output_file` against `os.homedir()` (or a `NLMCP_EXPORT_DIR`) and reject paths whose `path.relative(base, resolved)` starts with `..` or is absolute. The same `resolveExportPath` helper from `system.ts` can be lifted/shared.
2. Reject overwriting existing files unless an explicit `force: true` is passed (use `fs.writeFile` with flag `wx`).
3. Refuse writes to dotfiles in the home directory (`.ssh`, `.aws`, `.kube`, `.gnupg`, `.bashrc`/`.zshrc`/`.profile`, etc.) — borrow the denylist from `resolveFolderPath` in `notebook-creation.ts`.
4. Move `get_notebook_chat_history` to **admin** scope, since it now performs filesystem writes — read-scope should not be enough.

The same pattern (output-path-controlled-by-caller, no admin gate) does **not** exist in the other tools I reviewed: `handleExportLibrary` validates, `handleDownloadAudio` is admin-gated, `handleUploadDocument` reads (not writes) and is admin-gated.

---

## Other items worth surfacing (lower confidence, included for context, not as PR blockers)

These either don't meet the >80% confidence bar required by the review charter, or are excluded by hard rules (env-vars-are-trusted, secrets-on-disk-are-handled-elsewhere). Recording them so reviewers don't have to re-derive them.

### O-1. `add_folder` symlink-bypass of denylist (admin-only)
The denylist in `resolveFolderPath` (`notebook-creation.ts`) blocks `~/.ssh`, `~/.aws`, etc. `path.resolve` does **not** follow symlinks, but the recursive `scanDir` *does* follow them when reading. An attacker with write access to a directory the user later passes can plant `evil/link → ~/.ssh` and exfiltrate keys via NotebookLM upload. Admin-gated, so this requires a leaked admin token; mitigation would be to call `fs.realpath` per directory entry and re-check the denylist.

### O-2. `updateWebhook` persists secret to disk; `addWebhook` does not
`addWebhook` stores the HMAC secret in an in-memory `SecureCredential` and writes `secret: undefined` to `webhooks.json`. `updateWebhook` (line 897 of `webhook-dispatcher.ts`) writes `input.secret` straight into the persisted store via `saveStore()`. Subsequent restarts load the secret in plaintext from `webhooks.json`. The file is `0o600`, so this is excluded by the hard rule on "secrets on disk if otherwise secured" — flagging only because it contradicts the explicit `// secret never persisted to disk` comment elsewhere in the same file.

### O-3. `audio-manager.downloadAudio` writes to caller-supplied path (admin-only)
Same shape as Vuln 1 (`outputPath` → `fs.writeFileSync`), but the tool is in `TOOLS_REQUIRING_AUTH`. So it's admin-gated. Still worth tightening for parity.

### O-4. `gemini_query.urls` is a partial SSRF surface
The handler validates `url.startsWith("http://" | "https://")` but not the host. The URL is then forwarded to Gemini's `url_context` tool, where Google's servers fetch it — not the local process. So this is *Google's* SSRF surface, not yours. Noting it because the README implies "URL whitelisting" is comprehensive; it isn't for `gemini_query`.

### O-5. `alert-manager` and `siem-exporter` do not run webhook-dispatcher's SSRF validation
Both take URLs from environment variables (`NLMCP_ALERTS_WEBHOOK_URL`, SIEM endpoint) and `https.request` them directly with no DNS-resolve + private-range check. By the review charter this is out of scope (env vars are trusted), but if you ever expose those endpoints via a config file or admin tool, route them through `validateWebhookUrl` from `webhook-dispatcher.ts`.

---

## Are the security claims marketing or real?

You explicitly asked, so here's the unvarnished read against `package.json` `securityHardening` and `enterpriseCompliance`:

| Claim | Verdict | Notes |
|---|---|---|
| `inputValidation` | **Real, partial.** | Notebook URL/ID/session validators are real. But `get_notebook_chat_history.output_file` and a few other paths are unvalidated (Vuln 1). Not consistently applied. |
| `urlWhitelisting` | **Real for notebook navigation; not enforced for `gemini_query.urls`.** | `validateNotebookUrl` allowlists the `notebooklm.google.com.*` family; `validateSourceUrl` only blocks dangerous schemes. |
| `rateLimiting` | **Real.** | `RateLimiter` class with bounded map size and per-window eviction. |
| `logSanitization` | **Real.** | `sanitizeForLogging` masks emails/secrets in log lines; audit logger redacts sensitive keys. |
| `credentialMasking` | **Real.** | `maskEmail`, secret patterns. |
| `auditLogging` | **Real and well-built.** | Hash-chained, cross-day chain link, tamper detection on read, 7-year retention. Good. |
| `sessionTimeout` | **Real.** | Session manager + bounded lockouts. |
| `mcpAuthentication` | **Real and secure-by-default.** | SHA3-256 + persistent salt, exponential lockout, secure-compare on a fixed-length canonical buffer. Solid. |
| `responseValidation` | **Real but pattern-based.** | Useful as defense-in-depth; do not rely on it to stop a determined prompt-injection attacker. |
| `postQuantumEncryption` | **Real implementation, weak threat model.** | ML-KEM-768 + ChaCha20-Poly1305 hybrid is correctly built. But the storage threat being defended against ("steal encrypted blob today, decrypt in 2040 with quantum") is largely irrelevant for a local stdio tool, especially since the keystore is decrypted by a key derived from the same machine. **An attacker who can read `state.json.pqenc` can almost always also read `machine.key` next to it.** Symbolic value > security value. |
| `secretsScanning` | **Real.** | TruffleHog/GitLeaks-style patterns with entropy gates and context allow-lists. Not a silver bullet, but genuinely useful. |
| `memoryScrubbing` | **Real for Buffers, mostly theatre for strings.** | `SecureString` zero-fills the backing Buffer, but the original `string` argument lives on in V8's heap until GC. This is honestly disclosed in the source comment, less so in the README. |
| `medusaIntegration` | **Real (CI workflow).** | `.github/workflows/ci.yml` runs `medusa scan . --fail-on high`. Caveat: the README still has a TODO comment about verifying the pip package name, so trust the workflow only after one green run. |
| `secureByDefaultAuth` | **Real.** | Auth is on unless `NLMCP_AUTH_DISABLED=true` is explicitly set; the legacy `NLMCP_AUTH_ENABLED` flag wins ties. |
| `exponentialBackoffLockout` | **Real.** | `5min × 3^(n-1)`, capped at 4h. Includes a separate non-locking-but-alerting bucket for unknown clients (smart — prevents DoS of legit unconfigured clients). |
| `credentialIsolation` | **Real.** | `LOGIN_PASSWORD` and `GEMINI_API_KEY` are read into `SecureCredential`s, then `delete process.env.X`. So a child-process inheriting env doesn't get them. |

| Compliance claim | Verdict |
|---|---|
| `gdpr.*` (consent, DSAR, erasure, portability, privacy notice) | **Real primitives, marketing framing.** All the building blocks are there: consent manager, DSAR handler, data-erasure with secure-overwrite, data exporter. But "GDPR-compliant" is an organizational property, not a tool property. The tool gives you primitives — your deployment, DPA, retention policies, access controls, and lawful basis make it compliant or not. |
| `soc2.hashChainedAuditLogs` | **Real.** Hash chain works, cross-day linkage closes the obvious "swap a whole day's file" attack. |
| `soc2.changeManagement` | **Real.** ChangeLog records are written for auth/webhook mutations. |
| `cssf.sevenYearRetention` | **Real.** `NLMCP_AUDIT_RETENTION_DAYS=2555` default; old logs are pruned by the retention engine. |

**Bottom line on claims:** roughly two-thirds are real and load-bearing, one-third are real-but-overhyped (post-quantum at-rest encryption, "compliance"), zero are pure fabrication. The single inconsistency that bites operationally is Vuln 1.

---

## Attack vectors you specifically asked about

### Gemini API key exfiltration

How the key is held: `GEMINI_API_KEY` env var → `SecureCredential` (5-min TTL) → `delete process.env.GEMINI_API_KEY`. The key is then handed to `new GoogleGenAI({ apiKey })` and lives on the Google SDK client. Sanitizers redact `AIza[35chars]` in any log/response output via the `Google API Key` pattern in `secrets-scanner.ts`.

Realistic exfil paths:

1. **Admin-token holder uploads `.env` to Gemini Files API** — `upload_document` reads any path the process can read, including `~/.notebooklm-mcp-secure/.env` or wherever the operator stored the key. `query_document` can then ask the model to read it back. *Mitigation: admin auth is required, and admin auth being compromised is its own incident. But anyone with admin rights effectively has key-exfil capability already.*
2. **Vuln 1 → write a malicious npm `preinstall` to `~/.npm/scripts/...`** — pivot to RCE on next install, then read env. Plausible chain, defended only by the OS and by the user not running `npm install` in this env again.
3. **Token-file disclosure** — the `auth-token.hash` stores SHA3-256 with persistent salt. Pre-image resistance protects you; the disk file alone is not directly usable.
4. **Logging leak** — I checked: the key is never logged. The Gemini error message returned via `getSanitizedErrorMessage` is also stripped of paths; the secrets-scanner pattern would catch any AIza-shaped key that did slip into a log line.

Net: with auth-on, key exfil requires either admin-token compromise or Vuln 1 → RCE pivot. With auth-off, the surface widens and Vuln 1 is the cheapest path.

### Supply-chain risks

* **`patchright` (1.57.0)** — fork of Playwright explicitly designed to evade automation detection. It's a less-vetted upstream than Playwright proper. If Playwright's fingerprint-evasion behavior is acceptable for your use case, switching back to upstream `playwright` reduces supply-chain surface. If not, audit the `patchright` source on each upgrade — it patches Chromium-launch internals, which is an excellent place to hide a backdoor.
* **`@noble/post-quantum`, `pdf-lib`, `@modelcontextprotocol/sdk`, `@google/genai`** — mainstream, all well-known authors/orgs.
* **CI uses `npm ci --ignore-scripts`** — good, defeats the standard install-script supply-chain attack class for builds.
* **End-user installs (`npx notebooklm-mcp`) do NOT use `--ignore-scripts`** — `prepare`/`postbuild` lifecycle scripts run normally on user machines. The published scripts only do `tsc` and `chmod`, but a compromised future version of any transitive dep could land arbitrary code. Consider documenting `npm install --ignore-scripts` as the recommended install for the sensitive-deployment path, then a separate explicit build step.
* **`overrides`** in `package.json` pin specific transitive versions — modest but real anti-typosquatting / known-CVE benefit.
* **Postinstall chmod** — uses `node -e "..."` which is fine; no shell metachars.

### Other vectors I considered and rejected

* **DOM script execution as XSS vector.** `page.evaluate()` calls in audio-manager / chat-history are *closure-free* helpers running inside the browser context, not on Node. Page DOM is on `notebooklm.google.com` (hostname-validated). Risk localized to Google's surface.
* **Webhook outbound SSRF.** Properly defended: scheme allowlist, lexical IPv4/IPv6 private-range check (incl. RFC 6598 CGNAT and v4-mapped v6), DNS resolution with private-range check, `redirect: "error"` to defeat post-validation rebinding, header allowlist (`Host`/`Authorization`/`Content-Length`/`Transfer-Encoding`/`Connection` blocked).
* **Audit log tampering.** Hash chain is verified on startup and includes cross-day linkage; `disableHashChainForSession()` is invoked rather than silently resetting on corruption. Solid.
* **Token timing attacks.** `secureCompare` always copies into a fixed 64-byte canonical buffer before `timingSafeEqual`, then asserts equal length post-hoc. No length-leak.
* **Prompt-injection via env var.** `NLMCP_FOLLOW_UP_REMINDER` is sanitized for control chars before injection into responses.
* **Path traversal in `validateNotebookUrl`.** Blocks `..` after `decodeURIComponent`. Reasonable.
* **MCP error message leaking absolute paths.** Stripped via regex in `index.ts` before return.
* **Race conditions in concurrent auth.** `validateWithRetry` distinguishes "another session is renewing" from "real expiry" and reloads cookies — well designed.

---

## Recommendation

Block the next release on **Vuln 1**. Everything else is either solid or an honest-to-the-source defense-in-depth gap. The codebase is, in fact, what it claims to be **except** for the post-quantum-at-rest theatre (mostly harmless) and the inconsistent compliance framing (read it as a primitives library, not a compliance certification).

Once Vuln 1 is fixed, I would re-audit the new path-validation helper to ensure it doesn't get bypassed by symlinks, `..`/`..%2F` decoding, or relative paths anchored to the wrong base.
