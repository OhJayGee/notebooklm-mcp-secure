# Code review request: `notebooklm-mcp-secure` (whole repo)

Review performed by Gemini 3.1 Pro based on Template 2.

## Areas Evaluated

The review focused on trust-boundary consistency, persistent-state validation, uniform application of input validators, async/lifecycle correctness, error-message consistency, and credential lifecycle.

## Findings

1. **Summary:** `get_notebook_chat_history` writes to the local filesystem but remains classified as read-scope in `TOOLS_EXEMPT_FROM_AUTH`.
   **Location:** `src/index.ts` lines 105-106, `src/tools/handlers/gemini.ts` lines 867-915.
   **Reproduction:** Call `get_notebook_chat_history` with an `output_file` argument and a valid read-scope token. The tool will execute the write using `fs.writeFile`, bypassing the admin-scope boundary intended for filesystem writes. The `CHANGELOG.md` explicitly notes this should be admin-scope, but the move was not executed in `src/index.ts`.
   **Severity:** Medium
   **Confidence:** 10
   **Suggested change:** Remove `"get_notebook_chat_history"` from `TOOLS_EXEMPT_FROM_AUTH` and add it to `TOOLS_REQUIRING_AUTH` in `src/index.ts`. Also update `tests/auth-scope-classification.test.ts` to expect it in the `mutatingTools` list.

2. **Summary:** `validateSessionId` is omitted in `close_session` and `reset_session`, where the raw parameter is passed directly to the session manager.
   **Location:** `src/tools/handlers/session-management.ts` lines 105-128.
   **Reproduction:** Call `close_session` or `reset_session` with an invalid `session_id` (e.g. containing illegal characters). It will bypass the format restrictions enforced by `validateSessionId` (which is correctly used in `ask_question`).
   **Severity:** Low
   **Confidence:** 10
   **Suggested change:** Call `validateSessionId(args.session_id)` at the start of `handleCloseSession` and `handleResetSession`.

3. **Summary:** `deep_research` and `gemini_query` manually validate the `query` length and emptiness instead of using the shared `validateQuestion` helper.
   **Location:** `src/tools/handlers/gemini.ts` lines 77-82 and 183-188.
   **Reproduction:** Send a `gemini_query` with a string of 15,000 characters. The inline validation allows up to 30,000 characters without using `validateQuestion`, leading to inconsistent maximums and rules across the codebase.
   **Severity:** Low
   **Confidence:** 9
   **Suggested change:** Replace the inline validation logic with a call to `validateQuestion(args.query)`, potentially extending `validateQuestion` to accept an optional `maxLength` parameter.

4. **Summary:** In `gemini_query`, the `urls` parameter is manually validated instead of using the shared `validateSourceUrl`, allowing non-HTTPS schemes.
   **Location:** `src/tools/handlers/gemini.ts` lines 192-196.
   **Reproduction:** Send a `gemini_query` with `urls: ["http://attacker.com/script.js"]`. It passes the inline check `url.startsWith("http://")` and is fetched, whereas `validateSourceUrl` would correctly block the non-HTTPS scheme.
   **Severity:** Medium
   **Confidence:** 10
   **Suggested change:** Replace the inline URL check loop with `const safeUrls = args.urls.map(validateSourceUrl);` and pass `safeUrls` to the client.

5. **Summary:** `WebhookDispatcher` initializes from environment variables asynchronously without awaiting the promise, causing a race condition if events are dispatched immediately.
   **Location:** `src/webhooks/webhook-dispatcher.ts` lines 205-207.
   **Reproduction:** Configure an event webhook via `NLMCP_WEBHOOK_URL` in the environment. Boot the server and trigger an event synchronously upon startup before the `initializeFromEnv()` promise (which does async DNS lookups) resolves. The webhook will not fire because the in-memory array does not yet contain it.
   **Severity:** Medium
   **Confidence:** 9
   **Suggested change:** Store the initialization promise (`this.initPromise = this.initializeFromEnv()`) and explicitly `await this.initPromise` at the start of `dispatch()`, `listWebhooks()`, and `addWebhook()`.

6. **Summary:** Stack fragments are not stripped in handler-caught errors, contradicting the global MCP exception handler's error sanitization.
   **Location:** `src/tools/handlers/error-utils.ts` line 25, compared to `src/index.ts` line 348.
   **Reproduction:** Trigger an error inside `deep_research` that includes a stack trace in its message. The returned `ToolResult` will contain the stack trace because `getSanitizedErrorMessage` from `error-utils.ts` only strips absolute paths, unlike the global handler which uses `/\bat\s+\S+\s+\(\S+:\d+:\d+\)/g`.
   **Severity:** Low
   **Confidence:** 9
   **Suggested change:** Copy the stack fragment stripping regex (`/\bat\s+\S+\s+\(\S+:\d+:\d+\)/g`) from `src/index.ts` into `getSanitizedErrorMessage` in `src/tools/handlers/error-utils.ts`.

7. **Summary:** `LOGIN_PASSWORD` and `GEMINI_API_KEY` are wrapped in `SecureCredential`, but their `.wipe()` methods are never called during shutdown.
   **Location:** `src/config.ts` lines 233-241, `src/index.ts` lines 422-446 (shutdown handler).
   **Reproduction:** Start the server with `LOGIN_PASSWORD` set. Send a SIGTERM to gracefully shut down. The shutdown handler closes the MCP server but fails to wipe the `secureLoginPassword` and `secureGeminiApiKey` from memory before exiting, contradicting the credential lifecycle rules in `AGENTS.md`.
   **Severity:** Medium
   **Confidence:** 10
   **Suggested change:** Export a `wipeGlobalCredentials()` function from `src/config.ts` that calls `.wipe()` on both instances, and invoke it in the `shutdown` callback in `src/index.ts`.