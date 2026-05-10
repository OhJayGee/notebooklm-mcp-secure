# Codex Full-Repository Findings

Date: 2026-05-10

Scope: whole-repository correctness and robustness review using
`docs/security-reviews/REVIEW_PROMPT_TEMPLATE.md` Template 2. Prior
reports and the v2026.3.3 changelog were treated as baseline; findings
below are either still present in the current tree or are gaps outside
the previous review scope.

## 1. `get_notebook_chat_history` is still read-scope even when it writes a file

**Summary** - The path handling was hardened, but the tool remains in the read-scope set while `output_file` still performs a filesystem write.

**Location** - `src/index.ts:135`-`146` classifies `get_notebook_chat_history` as read-scope; `src/tools/handlers/gemini.ts:873`-`908` resolves `output_file` and writes JSON; `tests/auth-scope-classification.test.ts:119`-`122` pins the tool as expected read-only.

**Reproduction** - With a read-only token and advanced tools enabled, call:

```json
{
  "name": "get_notebook_chat_history",
  "arguments": {
    "notebook_id": "valid-notebook",
    "output_file": "exports/chat-history.json"
  }
}
```

The write is constrained by `resolveExportFilePath`, but it is still a persistent local filesystem mutation reachable through read-scope auth.

**Severity / confidence** - Medium severity, confidence 10.

**Suggested change** - Move `get_notebook_chat_history` to `TOOLS_REQUIRING_AUTH`, remove it from the expected read-only list in `tests/auth-scope-classification.test.ts`, or split the tool into a read-only history reader and a separate admin-gated export tool.

## 2. `list_webhooks` exposes webhook credentials to read-scope callers

**Summary** - `list_webhooks` is read-scope and returns full `WebhookConfig` objects, including credential-bearing webhook URLs and any legacy persisted `secret` field.

**Location** - `src/index.ts:142` keeps `list_webhooks` in `TOOLS_EXEMPT_FROM_AUTH`; `src/tools/handlers/webhooks.ts:79`-`86` returns `dispatcher.listWebhooks()` directly; `src/webhooks/webhook-dispatcher.ts:223`-`228` loads persisted records without scrubbing legacy `secret`; `src/webhooks/webhook-dispatcher.ts:997`-`999` explicitly notes full URLs may contain secret path tokens; `src/webhooks/webhook-dispatcher.ts:1039`-`1040` returns the raw store.

**Reproduction** - Configure a Slack/Discord-style webhook whose credential is embedded in the URL path, then call `list_webhooks` with a read-only token. The response contains the full URL. On an upgraded install with an older `webhooks.json` containing `"secret": "..."`, that value is also returned because the load path does not migrate or redact it.

**Severity / confidence** - Medium severity, confidence 9.

**Suggested change** - Either admin-gate `list_webhooks` or return a redacted DTO (`id`, `name`, `enabled`, `events`, `format`, `host`, timestamps, `hasSecret`) instead of `WebhookConfig`. On `loadStore()`, migrate persisted records by moving any legacy `secret` into `webhookSecrets` or dropping it, then persist the scrubbed store.

## 3. Compliance tools outside `TOOL_NAMES` default to read auth, including a mutating health check

**Summary** - Compliance tools that are not listed in `TOOL_NAMES` are authenticated as read-scope by default; `run_health_check` writes a probe file, logs a compliance event, and may dispatch alerts.

**Location** - `src/index.ts:389`-`393` logs non-`TOOL_NAMES` compliance tools as read-auth; `src/index.ts:431`-`435` only admin-gates names in `TOOLS_REQUIRING_AUTH`; `src/compliance/compliance-tools.ts:309`-`315` defines `run_health_check`; `src/compliance/compliance-tools.ts:423`-`424` dispatches it; `src/compliance/health-monitor.ts:184`-`197` may send alerts; `src/compliance/health-monitor.ts:200`-`207` writes a compliance log event; `src/compliance/health-monitor.ts:237`-`239` writes and deletes `.health_check`.

**Reproduction** - Call `run_health_check` with a read-only token. The request passes the generic compliance dispatch path and performs the filesystem probe plus compliance logging. If a component is down and alert webhooks are configured, it can also trigger outbound alert delivery.

**Severity / confidence** - Medium severity, confidence 9.

**Suggested change** - Add every compliance tool name to `TOOL_NAMES`, classify each explicitly, and extend `tests/auth-scope-classification.test.ts` to cover compliance tools. At minimum, put `run_health_check` in `TOOLS_REQUIRING_AUTH`.

## 4. MCP resource reads bypass MCP authentication entirely

**Summary** - Tool calls are authenticated, but MCP resources and completions are registered without auth checks and expose notebook library metadata.

**Location** - `src/index.ts:317`-`319` registers resource handlers before any auth wrapper; auth is applied only in the `CallToolRequestSchema` handler at `src/index.ts:411`-`435`; `src/resources/resource-handlers.ts:78`-`153` lists notebook resources; `src/resources/resource-handlers.ts:176`-`218` returns the full library resource; `src/resources/resource-handlers.ts:311`-`327` completes notebook IDs.

**Reproduction** - Send an unauthenticated MCP `resources/read` request for `notebooklm://library`. The response includes notebook IDs, names, descriptions, topics, use cases, URLs, usage counts, and timestamps. No `_meta.authToken` is checked because the resource handlers do not call `authenticateMCPRequest`.

**Severity / confidence** - Medium severity, confidence 10.

**Suggested change** - Wrap `ListResources`, `ReadResource`, and `Complete` resource-template handlers with read-scope authentication, or return only non-sensitive static resource templates until the request is authenticated. Add integration tests that unauthenticated resource reads fail when auth is enabled and succeed with a read token.

## 5. `export_library` still uses a local lexical path helper instead of the shared path policy

**Summary** - `export_library` missed the `resolveExportFilePath` migration and can write through symlinked parents or leaf symlinks inside the export base.

**Location** - `src/tools/handlers/system.ts:32`-`53` uses a local `resolveExportPath()` with only lexical `path.relative` containment; `src/tools/handlers/system.ts:78` uses that helper; `src/tools/handlers/system.ts:112`-`113` writes to the resulting path.

**Reproduction** - Set `NLMCP_EXPORT_DIR=/tmp/nlmcp-export`, create `/tmp/nlmcp-export/s -> ~/.ssh`, then call admin-gated `export_library` with:

```json
{
  "format": "json",
  "output_path": "s/authorized_keys"
}
```

The local helper accepts the lexical path under `/tmp/nlmcp-export`; `fs.writeFileSync` follows the symlinked parent.

**Severity / confidence** - Medium severity, confidence 10.

**Suggested change** - Delete the local `resolveExportPath()` helper and call `resolveExportFilePath(args.output_path, defaultName)` from `src/utils/path-policy.ts`. Return `data: null` on the rejection path to preserve the standard error contract, and add a regression test that mirrors the existing symlink tests for `get_notebook_chat_history` and `download_audio`.

## 6. Gemini and scraped chat-history responses bypass `response-validator.ts`

**Summary** - Only `ask_question` validates model output before returning it to the MCP client; Gemini responses and scraped chat-history text are returned raw.

**Location** - `src/tools/handlers/ask-question.ts:250`-`263` applies `validateResponse`; `src/tools/handlers/gemini.ts:106`-`123` returns `deep_research` answer raw; `src/tools/handlers/gemini.ts:217`-`245` returns `gemini_query` answer raw; `src/tools/handlers/gemini.ts:417`-`431` returns `query_document` result raw; `src/tools/handlers/gemini.ts:581`-`597` returns chunked query output raw; `src/tools/handlers/gemini.ts:781`-`831` scrapes chat-history message content and returns/export it without validation.

**Reproduction** - Have Gemini or an uploaded document return text containing a pattern already blocked by `ResponseValidator`, then call `gemini_query`, `deep_research`, `query_document`, or `query_chunked_document`. The returned `answer` contains the original text and no `security_warnings`, unlike `ask_question`.

**Severity / confidence** - Medium severity, confidence 8.

**Suggested change** - Factor the `ask_question` validation block into a shared helper and apply it to all LLM- or page-scraped text before returning it to MCP clients. Include `security_warnings` in the structured result when sanitization or warnings occur, and add regression tests that feed known validator-blocked strings through each Gemini handler.

