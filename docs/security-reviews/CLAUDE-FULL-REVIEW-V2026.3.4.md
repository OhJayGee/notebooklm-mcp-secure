# Whole-repo correctness and robustness review — v2026.3.4

Reviewer: Claude (Opus 4.7).
Method: Template 2 from `docs/security-reviews/REVIEW_PROMPT_TEMPLATE.md`,
applied against the post-v2026.3.4 tree (commit `5df01eb`). Prior
review reports in this directory were treated as the baseline; the
v2026.3.3 + v2026.3.4 CHANGELOG entries were used to filter
already-addressed findings before reporting.

The bar is confidence ≥ 7; below the bar is omitted.

## Summary

| # | Severity | Confidence | Finding |
|---|---|:---:|---|
| 1 | Medium | 9 | Library mutations are not audit-logged |
| 2 | Medium | 8 | Audit log / query log not flushed by the shutdown handler — writes can be lost on SIGINT or `process.exit()` |
| 3 | Low (DiD) | 8 | `alert-manager.ts` and `siem-exporter.ts` outbound HTTP not routed through `validateWebhookUrl` |
| 4 | Low | 7 | Quota file persisted to disk with no integrity check — a local user can edit `quota.json` to bypass rate limits |
| 5 | Low | 7 | `get_health` with `deep_check: true` is read-scope but creates a real browser session as a side effect |

Five findings. Two of medium impact, three low. None are exploitable
without local access to the user's data dir or without admin auth, but
all five are real gaps a security-claiming fork should close.

What I looked at and found nothing fresh on (i.e. prior reviews +
v2026.3.3/4 fixes are sufficient): every item in template areas 2, 3,
6, 7, 9, 11, 12 except as noted in the findings below.

---

## 1. Library mutations are not audit-logged

**Severity:** Medium · **Confidence:** 9 · **Category:** Audit-log
gap.

**Summary.** `addNotebook`, `updateNotebook`, `removeNotebook`, and
`selectNotebook` mutate persistent local state (`library.json`) but
emit no `audit.tool` / `audit.security` / `audit.compliance` event.
Every other admin-scope tool surface in this codebase audits (search
the tree: `grep -n "audit\." src/tools/handlers/*.ts` lights up
ask_question, gemini handlers, notebook-creation handlers,
audio-video, system, webhooks). Only the library handlers and the
library class itself are silent.

**Location.**

- `src/library/notebook-library.ts` — `addNotebook` (line 349),
  `updateNotebook` (line 447), `removeNotebook` (lines around
  `removeNotebook(id`), `selectNotebook` (line 420). None call
  `audit.*`.
- `src/tools/handlers/notebook-management.ts` — `handleAddNotebook`,
  `handleUpdateNotebook`, `handleRemoveNotebook`, `handleSelectNotebook`.
  None call `audit.*`. (`grep -n 'audit\.' …` returns zero hits.)

**Reproduction / why it matters.** v2026.3.3 moved these tools into
`TOOLS_REQUIRING_AUTH` precisely because they mutate persistent
library state — and that state is itself a privilege boundary
(library URLs are later trusted by `SessionManager` for browser
navigation). The trust-boundary side is now enforced. The audit
side is not: every admin-scope library mutation happens silently.
For a fork that ships hash-chained audit logs as a SOC2-style change-
management story, this is the largest visible gap — every other
admin-scope tool is in the audit trail, library mutations aren't.

The `src/compliance/change-log.ts` ChangeLog *is* used for webhook
and auth-token mutations (see `webhook-dispatcher.ts:recordWebhookChange`
and `auth/mcp-auth.ts:rotateToken`). It is NOT used for library
mutations. Both code paths exist, only one set of mutating handlers
calls them.

**Suggested change.** Either:

(a) Add `audit.tool(...)` calls in each of the four notebook-management
handlers, mirroring the pattern in `handleCreateNotebook`:

```ts
await audit.tool("add_notebook", {
  name: input.name,
  url_host: new URL(safeUrl).host,  // host only — never the full URL
  topics: input.topics,
}, true, 0);
```

…and equivalent calls in update / remove / select. Sanitise the URL
the same way `recordWebhookChange` does (host-only, never full path).

(b) Or layer a `getChangeLog().recordChange("library", …)` call into
each mutator so the SOC2 change-management trail is consistent with
how webhook + auth-token mutations are already recorded.

I'd do both: `audit.tool` for the dispatcher trail, ChangeLog for the
SOC2 trail. They serve different consumers (audit-logger feeds the
hash chain; ChangeLog feeds compliance reports).

A regression test would mirror the existing pattern and assert that
`auditMock.tool` was called with the right tool name after each
handler. This would also catch the case where someone re-classifies a
mutating tool as read-scope without removing the audit call.

---

## 2. Audit-log and query-log not flushed on shutdown

**Severity:** Medium · **Confidence:** 8 · **Category:** Lifecycle.

**Summary.** Both `AuditLogger` and `QueryLogger` write asynchronously
through a queue (`writeQueue` chain in audit-logger, `isWriting` flag +
`writeQueue` in query-logger). Pending writes are flushed only when
`process.on("beforeExit")` or `process.on("SIGTERM")` fires. The MCP
server's own shutdown handler in `src/index.ts` calls `process.exit(0)`
after `server.close()` *without* awaiting either logger's `flush()`.
`process.exit()` does NOT trigger `beforeExit` (Node docs explicitly
say so). Result: any audit / query event written within milliseconds
of shutdown can be lost.

**Location.**

- `src/utils/audit-logger.ts` — `flush()` method (line 627 area), and
  the process-handler registration in `registerProcessHandlers`:
  `process.on("beforeExit", ...)` and `process.on("SIGTERM", ...)`.
  No SIGINT / uncaughtException / unhandledRejection.
- `src/logging/query-logger.ts` — `flush()` method (line 352 area),
  registered only on `process.on("beforeExit", QueryLogger.flushAllSync)`.
  No SIGTERM, no SIGINT, etc.
- `src/index.ts` — the `shutdown(signal, error)` callback (line 590-ish)
  awaits `flushFatalError`, the retention timer, `toolHandlers.cleanup()`,
  `server.close()`, then `wipeGlobalCredentials()`, then `process.exit(0)`.
  Never awaits `getAuditLogger().flush()` or `getQueryLogger().flush()`.

**Reproduction.** Send a SIGINT to a running server immediately after
a tool call that emits an audit event. Trace the event through the
`writeQueue`. Because `shutdown()` calls `process.exit(0)` after a
short async chain that never awaits the logger flush, the queue may
not have drained before the process terminates.

The audit logger's hash-chain integrity is robust against this in the
sense that it won't be left in a corrupt state — `flushPendingEventsSync`
is registered on `beforeExit` and `SIGTERM`, and the hash pointer is
only advanced *after* a successful write. But losing audit events
silently is itself a compliance issue: the next event after a partial
shutdown will be missing its predecessor, which `verifyIntegrity`
would surface as a chain break.

**Suggested change.** In `src/index.ts:shutdown`, after `server.close()`
and before `wipeGlobalCredentials()`, await both flushes:

```ts
// Drain the write queues so audit / query events written in the
// final ms of operation are not lost. Each flush method is idempotent
// and resolves promptly when the queue is empty.
try {
  await getAuditLogger().flush();
} catch (err) {
  log.warning(`audit flush failed: ${err instanceof Error ? err.message : String(err)}`);
}
try {
  await getQueryLogger().flush();
} catch (err) {
  log.warning(`query log flush failed: ${err instanceof Error ? err.message : String(err)}`);
}
```

Also extend the audit-logger and query-logger process handlers to
register on SIGINT (currently only beforeExit + audit-logger SIGTERM).
The audit-logger's `flushPendingEventsSync` works synchronously and is
safe to call from a SIGINT handler.

A regression test would write an event, immediately call
`getAuditLogger().flush()`, then assert the file on disk contains the
event. (The current `tests/audit-logger.test.ts` exercises some of
this surface but doesn't pin the shutdown integration.)

---

## 3. `alert-manager.ts` and `siem-exporter.ts` outbound HTTP not protected

**Severity:** Low (defence-in-depth) · **Confidence:** 8 · **Category:**
Outbound-HTTP consistency.

**Summary.** v2026.3.4 hardened the webhook-dispatcher's outbound HTTP
end-to-end: scheme allowlist, lexical IPv4/IPv6 private-range check,
DNS resolution check, refusal of redirects, header allowlist, and
send-time re-validation against DNS rebinding. None of those
protections apply to `src/compliance/alert-manager.ts` or
`src/compliance/siem-exporter.ts`, which both make outbound HTTP via
plain `https.request` against env-supplied URLs.

The previous review rounds (v2026.3.3 and the original CLAUDE_REVIEW)
flagged this and waived it under the precedent that env vars are
trusted. That waiver is correct as a threat-model decision but the
code-quality argument is weaker: the same outbound-HTTP code lives in
three places with three different levels of hardening. A future
contributor who copy-pastes from alert-manager into a non-env-driven
context inherits the weaker pattern.

**Location.**

- `src/compliance/alert-manager.ts` — around line 264, `https.request`
  is called with `url.hostname` and `url.port` derived from
  `NLMCP_ALERTS_WEBHOOK_URL`. No scheme check, no private-range
  check, no DNS resolution check, no redirect refusal.
- `src/compliance/siem-exporter.ts` — similar, around line 480.
  Adds an `Authorization: Bearer ${api_key}` header and posts JSON.

**Reproduction.** Set `NLMCP_ALERTS_WEBHOOK_URL=http://169.254.169.254/`
(cloud metadata IP) and trigger any alert (e.g. by getting auth
locked-out enough to trip the alert manager). The request goes
through. `webhook-dispatcher` would refuse the same URL.

**Suggested change.** Factor out a small `validateOutboundUrl(url)`
helper from `webhook-dispatcher.ts` that does the scheme + private-
range + DNS check, and call it from both `alert-manager.ts` and
`siem-exporter.ts` before `https.request`. The caller should refuse
to start (log + exit, or skip the channel) if the env-supplied URL
fails validation.

This is intentionally listed as Low because env vars are trusted;
the practical impact is small. But the codebase-consistency argument
is what justifies it for a security-claiming fork.

---

## 4. Quota state file persisted with no integrity check

**Severity:** Low · **Confidence:** 7 · **Category:** Persisted-state
trust.

**Summary.** `src/quota/quota-manager.ts` reads / writes
`<dataDir>/quota.json` as plain JSON. On load, the file's contents
are accepted at face value: no schema validation, no signature, no
hash chain, no rejection of out-of-range values beyond the runtime
clamp. A local user (or a malicious process running as the same user)
can edit `quota.json` to set `queriesUsedToday: 0` and reset the day's
count, bypassing the rate limit.

The threat model question here is "do we treat the data dir as a
trust boundary against the user it runs as?" — and historically this
codebase says no. But several of the v2026.3.3/4 fixes (sessionStorage
origin pin, library URL revalidation on load) explicitly do treat
persisted state as untrusted. Quota state is the remaining inhabitant
of "trusted on read" land.

**Location.**

- `src/quota/quota-manager.ts:103` — `loadSettings()`:
  `JSON.parse(data) as QuotaSettings` with no validation.
- `src/quota/quota-manager.ts:139` — `saveSettings()`: plain JSON.

**Reproduction.** Run a query on the free tier until quota hits the
limit. `cat ~/.local/share/notebooklm-mcp/quota.json` and edit
`usage.queriesUsedToday` to `0`, save. Run another query. Goes
through.

This is genuinely a local-only attack so the security impact is
small. The argument for fixing it is consistency with the
"persisted state is untrusted" pattern that the rest of the
codebase now enforces.

**Suggested change.** Either:

(a) Apply the audit-logger pattern: write a hash chain over
quota updates so a tampered record is detected on next load. The
chain doesn't have to be cryptographically expensive; an HMAC over
the previous record's hash plus the current is enough. On
verification failure, reset the record to a conservative default
(treat tampering as a fresh install) and emit `audit.security
("quota_state_tampered", ...)`.

(b) Or simpler: validate the loaded record against a Zod schema, and
reject `queriesUsedToday < 0` or `notebooks > 100000` or other
implausible values. Reset to defaults on rejection. This isn't
tamper-proof but catches the unsophisticated edit case and the
"older release wrote a different field shape" case.

I'd do (b) — option (a) is more work for a smaller threat surface than
auth tokens or session state.

---

## 5. `get_health` with `deep_check: true` is read-scope but creates a real session

**Severity:** Low · **Confidence:** 7 · **Category:** Trust-boundary
consistency.

**Summary.** `handleGetHealth` is in `TOOLS_EXEMPT_FROM_AUTH`
(read-scope). When called with `deep_check: true`, the handler
**creates a temporary browser session** (`ctx.sessionManager.
getOrCreateSession(...)` with a fresh `health-check-${Date.now()}`
session id), navigates to a notebook, probes the chat UI, and closes
the session. That is a real side effect: spawns a Chrome process,
makes outbound network calls, can mutate the shared Chrome profile.

A read-scope tool should not have those side effects. The deep-check
path is genuinely useful for health diagnostics, but it should be an
admin-scope operation (or a separate tool) — the scope classification
test in `tests/auth-scope-classification.test.ts` was added to catch
exactly this kind of mismatch and currently doesn't because
`get_health` *as a name* is read-only. The discrepancy is hidden
inside the optional `deep_check` flag.

**Location.**

- `src/tools/handlers/session-management.ts:151` — `handleGetHealth`
  signature: `args?.deep_check?: boolean`.
- Inside the handler, when `deep_check && authenticated`, the code
  calls `ctx.sessionManager.getOrCreateSession(sessionId, notebookUrl)`
  — see lines around the comment "Create a temporary session to
  test".
- `src/index.ts` — `get_health` is in `TOOLS_EXEMPT_FROM_AUTH`.

**Reproduction.** Call `get_health` with `deep_check: true` from a
read-scope token. The handler spawns a Chrome session for the probe
and tears it down. No assertion needed; the side effect is
observable in process listings during the call.

This is also a small DoS-shape: a read-scope caller can repeatedly
trigger Chrome process churn. (The review charter's exclusion list
keeps DoS findings out of scope, so I'm flagging this as the
trust-boundary violation, not as DoS.)

**Suggested change.** Two options:

(a) Reject `deep_check: true` in the handler unless the call has
admin scope. Read the scope from `authResult` (currently the
authentication result is consumed in `src/index.ts` and not passed
down). Plumbing required: pass the scope into `HandlerContext` or
into the handler signature, then in `handleGetHealth` refuse with
`"deep_check requires admin scope"` when it's not admin.

(b) Split into two tools: `get_health` (read-scope, the cheap
introspection) and `verify_health` (admin-scope, the deep check
with a real browser session). Cleaner UX, less plumbing.

I'd do (b) — splitting matches how `delete_document` already gates
with an explicit `confirm: true` flag plus admin scope. The
asymmetric-side-effect-in-flag pattern is brittle and doesn't show up
in scope-classification tests.

---

## What I looked at and didn't flag

For completeness — these are the things the prompt asked me to
evaluate where I either confirmed prior reviews + recent fixes are
sufficient, or where the finding sits below confidence 7.

- **Trust-boundary consistency** (Template area 1) — the
  `auth-scope-classification.test.ts` test plus the v2026.3.3
  classification rewrite plus v2026.3.4's `COMPLIANCE_TOOLS_REQUIRING_AUTH`
  set close every concrete mutating-tool case I could find. Finding 5
  is the residual: a side effect hidden inside an optional flag.
- **Persistent-state validation on read** (area 2) — notebook library
  ✓, webhook config ✓ (legacy secret scrub), audit log ✓ (hash
  chain). Quota state is the residual (Finding 4). Settings file is
  validated by reading against a hard-coded `PROFILES` enum, so a
  tampered profile name harmlessly falls back to the valid set.
  Browser state is encrypted at rest.
- **Input validators applied uniformly** (area 3) — v2026.3.4 closed
  the `validateSessionId` / `validateQuestion` / `validateSourceUrl`
  / `validateFilePath` consistency gaps. The remaining variance
  (`search_notebooks` query, `get_query_history` search) is
  free-text-into-substring-match, no validator strictly required.
- **Async / lifecycle correctness** (area 4) — Finding 2 is the only
  concrete gap. The webhook init race was closed in v2026.3.4. Auth
  manager `initialize()` is awaited from `start()`. SecureStorage
  lazy init is awaited inside its `save` / `load` methods.
- **Error-message consistency** (area 5) — `getSanitizedErrorMessage`
  now strips paths AND stack frames. Compliance dispatcher in
  `src/compliance/compliance-tools.ts:445` correctly uses it. The
  `PathPolicyError` echoes back the user-supplied path verbatim,
  which the prior review-2 reviewer noted; I agree that's fine
  because the user already supplied that path.
- **Credential lifecycle** (area 6) — `wipeGlobalCredentials()` runs
  on every shutdown path. Webhook secrets in `webhookSecrets` Map are
  `SecureCredential`s that auto-wipe via TTL; on process exit they
  are GC'd. A more aggressive change would explicitly `.wipe()` each
  on shutdown, but the auto-wipe + process termination is sufficient
  for the threat model.
- **Outbound-HTTP surface** (area 7) — Finding 3 is the residual.
  webhook-dispatcher is fully hardened.
- **Audit-log correctness** (area 8) — Finding 1 (library mutations
  silent) is the largest gap. The hash chain itself works correctly,
  including cross-day chaining and tamper detection on read. The
  breach detector + SIEM exporter subscriber path is robust against
  subscriber errors (each call is `.catch(() => {})`).
- **`response-validator.ts` coverage** (area 9) — v2026.3.4 closed
  the deep_research / gemini_query / query_document / chunked /
  chat-history paths. The remaining unvalidated surface is compliance
  reports / DSAR exports, which contain user-controlled free text
  but are returned only to admin-scope callers; lower priority.
- **Test gaps** (area 10) — coverage looks reasonable across the
  tree. The compliance modules have lighter coverage than the
  security-critical ones. Worth a separate pass; not a v2026.3.5
  blocker.
- **Concurrency invariants** (area 11) — per-page mutex ✓,
  audit-log write queue ✓, file lock for state.json ✓, webhook
  saveQueue ✓, quota increment atomic ✓
  (`incrementQueryCountAtomic` uses `notebookIncrementQueue` chain).
- **Cross-OS robustness** (area 12) — path-policy now handles
  Windows path separators, denylist absolute paths, alt-streams,
  reserved device names, trailing-dot/space stripping. Token file
  path is `path.join`-clean. Chrome profile dir respects
  `os.homedir()`.

## Recommendation for v2026.3.5

Findings 1 and 2 are the two I'd ship in a v2026.3.5 release.
Finding 1 because it closes the largest visible gap in the audit-trail
story (which is itself a headline claim of the fork). Finding 2
because audit-event loss is exactly the kind of bug that breaks the
"hash-chained audit log" story silently — you only notice when the
chain fails to verify.

Findings 3, 4, 5 are nice-to-have. They don't move the threat model
much; they're consistency tightening. Bundle them with the next round
of work whenever convenient.

No critical or high findings emerged from this round. The two prior
external-review rounds plus the v2026.3.3/4 fixes have substantially
closed the surface I'd expect a security-claiming fork to defend.

## Process note

Reading order I followed (Template 2's "How to start"):

1. `docs/security-reviews/README.md` and the four prior reports.
2. `CHANGELOG.md` v2026.3.3 + v2026.3.4 entries (per-finding fix map).
3. `src/index.ts` end-to-end.
4. Trust-boundary first (the table in `TOOLS_REQUIRING_AUTH` /
   `TOOLS_EXEMPT_FROM_AUTH`), then audit-trail coverage, then
   outbound-HTTP, then persisted-state.

The CHANGELOG-as-baseline approach worked well. Several findings I
initially considered (`updateWebhook` legacy secret persistence,
`validateFilePath` startsWith bug, `add_folder` symlink bypass) were
already addressed; CHANGELOG let me filter them quickly.
