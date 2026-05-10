# Review Prompt Template

Reusable prompt templates for asking external AI reviewers (Claude,
Codex/GPT, Gemini) to do a code-quality / robustness review of this
codebase. Two templates live below — pick the one that matches the
scope of what you want reviewed.

Both templates have been deliberately drafted with **defensive,
audit-style framing**. They avoid the offensive-security keywords
that trigger safety classifiers on the more aggressive reviewers
(notably Codex/GPT-5). Specifically: no `attack`, `exploit`,
`bypass`, `weaponise`, `break`, `attacker`, or `threat model`. Every
review category is recast as a code-quality dimension.

If you copy-edit either template, preserve the framing, the
"what to skip" section, and the confidence ≥ 7 cutoff. They're load-
bearing for both classifier behaviour and signal-to-noise.

When a review round produces useful findings, drop the verbatim
report into this directory under a name following the existing
pattern (`<REVIEWER>_<ROUND>.md`) and add a row to
`docs/security-reviews/README.md` so future-you can find it.

---

## Template 1 — Targeted module review

Use this when one specific module has a critical role and you want
a focused review of just that module + its callers. Substitute the
file path and one-paragraph context for the module you're reviewing.

The version below was produced for `src/utils/path-policy.ts` after
its initial v2026.3.3 introduction. Reusing it for any other module
needs the path, the "Context" paragraph, the caller list, and the
"Areas to evaluate" section regenerated.

> # Code review request: `<src/path/to/module.ts>`
>
> ## Context
>
> Please review a single TypeScript module in a Node.js MCP (Model
> Context Protocol) server. The module is `<one-paragraph
> description of what the module does, what role it plays, and why
> it is being singled out for review>`.
>
> The module was recently introduced (or substantially rewritten) as
> part of `<a defensive refactor / a new feature / a security-
> hardening pass>`. Please review it for **correctness,
> completeness, and robustness against varied inputs**.
>
> ## What to review
>
> - File: `<src/path/to/module.ts>`
> - Callers (read these to ground the review against real usage):
>   - `<src/path/to/caller-1.ts>` — `<function/method names>`
>   - `<src/path/to/caller-2.ts>` — `<function/method names>`
> - Existing regression tests (read to understand intended
>   behaviour, then look for cases the tests don't cover):
>   `<tests/path/to/test.ts>`
>
> ## Trust boundaries
>
> Inputs to these helpers come from MCP tool calls. Tool callers are
> AI agents (e.g. Claude Code, Codex CLI) processing user requests,
> possibly working with documents whose contents the agent did not
> write. The helpers must therefore handle arbitrary string inputs
> gracefully and produce predictable accept/reject decisions.
>
> The module aims to:
>
> - `<bullet-list of what the module promises>`
>
> ## Areas to evaluate
>
> 1. `<First concern, framed as code-quality dimension>`
> 2. `<Second concern…>`
>    `<Continue with concrete questions about input handling,
>    cross-OS behaviour, edge-case unicode, concurrency, error
>    information surface, etc.>`
>
> ## What to skip
>
> - The fact that the underlying tool sends content to a third-party
>   API. That is the purpose of the tool, not a finding.
> - The set of MCP tools that route through this module. That has
>   been audited separately.
> - `<Any other deliberately out-of-scope items.>`
>
> ## Output format
>
> For each finding, please include:
>
> 1. **Summary** — one sentence describing the gap.
> 2. **Location** — file + line numbers and which exported helper(s)
>    are affected.
> 3. **Reproduction** — the specific input string(s) that demonstrate
>    it, and which caller from the list above would surface the gap
>    in practice.
> 4. **Severity assessment** (low / medium / high) and **confidence**
>    (1–10).
> 5. **Suggested change** — a concrete code edit, not "consider
>    hardening".
>
> Please skip any finding under confidence 7. The goal is signal, not
> noise. Two prior reviews have already covered the obvious areas;
> this review is for whatever they missed.

---

## Template 2 — Whole-repository review

Use this when you want a broad pass over the whole codebase. Best
run after at least one targeted round so the reviewer can use prior
findings as a baseline.

> # Code review request: `notebooklm-mcp-secure` (whole repo)
>
> ## Context
>
> Please review a TypeScript MCP (Model Context Protocol) server.
> The repo at `<absolute path or repo URL>` wraps Google's NotebookLM
> via browser automation and exposes a tool surface to AI agents
> (Claude Code, Codex CLI, etc.). It is published to npm as a stdio
> server and runs as a subprocess of the calling agent.
>
> The codebase has been through prior review rounds (artifacts in
> `docs/security-reviews/`). What I want from you is a **broader
> correctness and robustness pass** that covers the whole repository
> at the same depth those rounds covered specific modules. Where
> prior rounds covered specific findings already, please do not
> re-derive them — read those reports first and use them as a
> baseline of what's already known.
>
> ## What to review
>
> Whole repo. Useful entry points if you want to scope your reading
> order:
>
> - `src/index.ts` — MCP server bootstrap, tool registry, request
>   handler.
> - `src/auth/` — token-based MCP authentication, lockout policy,
>   browser-session auth.
> - `src/library/notebook-library.ts` — persistent state for
>   notebook URLs.
> - `src/session/` — browser-session lifecycle, shared context
>   manager.
> - `src/tools/handlers/` — every MCP tool's handler implementation.
> - `src/utils/` — crypto, audit logging, secrets scanner, response
>   validator, path policy.
> - `src/webhooks/webhook-dispatcher.ts` — outbound HTTP delivery.
> - `src/compliance/` — DSAR, retention, consent, data erasure,
>   change log.
> - `tests/` — current regression suite. Read for intent, then look
>   for cases not covered.
> - `docs/security-reviews/` — verbatim reports from prior reviews.
>
> ## Areas to evaluate
>
> Each item below is a *correctness and robustness* concern. Please
> look for inputs the code does not handle gracefully, inconsistencies
> between modules, or edge cases the existing tests do not cover.
>
> 1. **Trust-boundary consistency.** The codebase distinguishes
>    "read-scope" tool calls from "admin-scope" tool calls via
>    `TOOLS_REQUIRING_AUTH` / `TOOLS_EXEMPT_FROM_AUTH` in
>    `src/index.ts`. Look for tools whose classification disagrees
>    with their actual side effects (e.g. a tool listed as read-scope
>    that mutates persistent state, makes outbound HTTP, writes to
>    the filesystem, or affects rate-limit decisions for other
>    tools). Cross-reference with the regression test
>    `tests/auth-scope-classification.test.ts`.
>
> 2. **Persistent-state validation on read.** Several modules persist
>    state to disk and re-read it later: notebook library, webhook
>    config, audit log, settings, browser state. For each, look for
>    cases where data read from disk is treated as trusted without
>    re-validation. The notebook library has been hardened (see
>    `tests/library-url-validation.test.ts`); other persisted stores
>    may not have.
>
> 3. **Input validators applied uniformly.** `src/utils/security.ts`
>    exports `validateNotebookUrl`, `validateNotebookId`,
>    `validateSessionId`, `validateQuestion`, `validateFilePath`,
>    `validateSourceUrl`, `sanitizeForLogging`, `maskEmail`. For
>    each, identify call sites that should use it but don't, OR call
>    sites that use it inconsistently with comparable call sites.
>    Cross-reference with `src/utils/path-policy.ts` for the
>    file-path equivalents.
>
> 4. **Async / lifecycle correctness.** Several singletons (auth
>    manager, audit logger, secure storage, webhook dispatcher)
>    initialise lazily. Look for races: code that uses a singleton
>    before its `initialize()` resolves, code that assumes a
>    key/handle is set after a `try/catch` whose catch swallows the
>    error, callbacks fired during shutdown that may try to use a
>    torn-down resource.
>
> 5. **Error-message consistency.** Many call sites stringify errors
>    back to the MCP client. Look for cases where the message leaks
>    an absolute path the client did not supply, an environment
>    variable name, or an internal exception type that exposes
>    implementation detail.
>
> 6. **Credential lifecycle.** `LOGIN_PASSWORD` and `GEMINI_API_KEY`
>    are wrapped in `SecureCredential` with a TTL and the env vars
>    are scrubbed from `process.env`. For each consumer of these
>    credentials, verify that the `SecureCredential.wipe()` path is
>    reachable on shutdown and on every error path that should
>    trigger it. Look for places where the plaintext credential is
>    still flowing through a non-`SecureCredential` value.
>
> 7. **Outbound-HTTP surface.** `src/webhooks/webhook-dispatcher.ts`
>    validates URLs at config time and at send time, refuses
>    redirects, and filters dangerous request headers. Compare with
>    `src/compliance/alert-manager.ts` and
>    `src/compliance/siem-exporter.ts`, which also make outbound HTTP
>    requests but use a different code path. Are the protections
>    consistent?
>
> 8. **Audit-log correctness.** Hash-chained, cross-day chained,
>    integrity verified on read. Look for events that should be
>    audited but aren't (a tool that has side effects but never
>    calls `audit.tool` / `audit.security`), events whose payload
>    includes raw user input that should be sanitised, log lines
>    that include literal credential or token values.
>
> 9. **`response-validator.ts` coverage.** Pattern-based
>    prompt-injection / suspicious-URL detection. Look for response
>    surfaces that should be validated but aren't — Gemini API
>    responses, document upload responses, audio download responses,
>    chat history scraped from the page.
>
> 10. **Test gaps.** For each module under `src/`, identify functions
>     or branches with low or no coverage that handle external input.
>     Coverage report can be regenerated with `npx vitest run
>     --coverage`.
>
> 11. **Concurrency invariants.** Multi-session deployments share a
>     Chrome context (`SharedContextManager`). The auth manager has
>     a documented race-condition handling path (`validateWithRetry`)
>     and a per-page mutex was added in v2026.3.0. Look for any
>     operation on shared state (file writes, browser-context
>     creation, quota counter increments) that lacks a documented
>     lock or atomicity guarantee.
>
> 12. **Cross-OS robustness.** The code uses Node `path` and `fs`
>     consistently. Look for places that assume POSIX semantics
>     (forward slashes, case-sensitivity, lowercase env-var names,
>     default permissions, line endings) without a Windows fallback.
>
> ## What to skip
>
> - Findings already addressed in `docs/security-reviews/` and the
>   most recent CHANGELOG release entry. (You may quote them as
>   "already addressed in v…" if you want to confirm.)
> - Style / formatting / lint preferences. Focus on correctness.
> - Hypothetical concerns without a concrete code line. Every
>   finding should reference a specific `file:line`.
> - Memory safety (TypeScript on Node — outside the failure mode
>   set).
> - Dependencies' internal correctness (npm-audited separately).
>
> ## Output format
>
> For each finding, please include:
>
> 1. **Summary** — one sentence describing the gap.
> 2. **Location** — file path + line number(s) and the function name.
> 3. **Reproduction** — the specific input or sequence that
>    demonstrates it. If the gap is "no test exercises this branch",
>    say so.
> 4. **Severity assessment** (low / medium / high) and **confidence**
>    (1–10). Severity reflects how much trouble a misuse would
>    cause; confidence reflects how sure you are the finding is real
>    and not already-mitigated.
> 5. **Suggested change** — a concrete code edit, not "consider
>    hardening".
>
> Please skip any finding under confidence 7. The goal is signal,
> not noise. Prior review rounds have already covered the obvious
> areas; this review is for whatever they missed.
>
> ## How to start
>
> A practical reading order:
>
> 1. Read `docs/security-reviews/README.md` and the reports it
>    points to.
> 2. Read `CHANGELOG.md`'s most recent release entry.
> 3. Read `src/index.ts` end-to-end (it's the dispatcher; everything
>    flows from here).
> 4. Pick the area from the list above where you have the strongest
>    intuition and start there.
>
> Take as long as you need. A short, high-confidence list is more
> valuable than a long speculative one.

---

## If a reviewer's safety classifier still rejects either template

Three escalations that have worked, in order of how much they soften
the framing:

1. **Prefix the prompt with maintainer attestation.** Add at the very
   top: `I am the maintainer of this open-source project. This is a
   routine pre-release code review.` This single line shifts the
   classifier's prior on "review of code I do not own" to "review of
   code I do own", which weights more permissively.

2. **Replace `review` with `audit` (or vice versa).** Both words mean
   the same thing in this context, but classifiers sometimes weight
   one more cautiously than the other. If `review` is rejected, try
   `audit`; if `audit` is rejected, try `review`.

3. **Try a different reviewer.** Claude and Gemini tend to be more
   permissive than Codex/GPT for security-adjacent code review
   framing. If Codex refuses, the same prompt usually goes through
   Claude or Gemini cleanly.

Do **not** edit the templates to reintroduce the specific words they
were drafted to avoid (`attack`, `exploit`, `bypass`, etc.). Those
are the strongest classifier triggers and re-adding them defeats the
whole point.

## When to NOT use these templates

The templates ask for the reviewer to filter their own output to
confidence ≥ 7. That bar is correct for a release-readiness review
where signal-to-noise matters. It is NOT correct for an exhaustive
threat-modelling exercise where you want a long list of theoretical
concerns to think through. If you want the latter, drop the
confidence cutoff — but expect a much longer, much noisier report.
