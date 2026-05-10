# Codex Full-Repository Findings — V2026.3.4 Follow-Up

Date: 2026-05-10
Reviewer: Codex (GPT-5)
Scope: Whole repository, using `docs/security-reviews/REVIEW_PROMPT_TEMPLATE.md` Template 2.

Baseline checked before this pass:

- `docs/security-reviews/CODEX_FULL_FINDINGS.md`
- `docs/security-reviews/GEMINI31Pro_FULL_FINDINGS.md`
- `CHANGELOG.md` entry for `2026.3.4`

The prior Codex and Gemini findings were already addressed in the current tree. This follow-up found two additional high-confidence error-surface consistency gaps. Both were addressed in the same pass.

## Finding 1 — Compliance tool errors bypassed the shared sanitizer

1. **Summary** — `handleComplianceToolCall` returned and audited raw exception messages instead of using the shared `getSanitizedErrorMessage` helper, so compliance tool failures could expose absolute paths or stack-frame fragments to the MCP client and audit log.
2. **Location** — `src/compliance/compliance-tools.ts`, `handleComplianceToolCall` catch block around lines 443-450 before this fix.
3. **Reproduction** — Force any compliance handler routed through `handleComplianceToolCall` to throw `new Error("failed at loadPolicy (/Users/alice/project/src/x.ts:12:9)")`. Before this fix, the returned text was `Error executing <tool>: failed at loadPolicy (/Users/alice/project/src/x.ts:12:9)`, preserving the path and stack-frame fragment.
4. **Severity assessment** — Low. The caller already receives a failed tool result, but the raw message unnecessarily discloses local filesystem structure and internal implementation detail. **Confidence:** 9/10.
5. **Suggested change** — Import `getSanitizedErrorMessage` from `src/tools/handlers/error-utils.ts`, use it in the catch block before both `audit.tool(...)` and the returned `TextContent`, and add a regression test that rejects the old raw-stringification pattern.

**Status:** Addressed in this pass.

## Finding 2 — Path-policy rejection branches still returned raw absolute-path details

1. **Summary** — Several client-visible handler branches caught `PathPolicyError` and returned `err.message` directly, bypassing the sanitizer that was added for the previous external-review round.
2. **Location** — `src/tools/handlers/system.ts` (`handleExportLibrary` path-policy branch and handler catch blocks), `src/tools/handlers/audio-video.ts` (`handleDownloadAudio` output-path branch), and `src/tools/handlers/gemini.ts` (`handleUploadDocument` local-read branch and `handleGetNotebookChatHistory` export branch).
3. **Reproduction** — With the default export base, call `export_library` with `output_path: "../escape.json"` or `get_notebook_chat_history` with `output_file: "../escape.json"`. Before this fix, the rejection could include the canonical export base and candidate path, e.g. `output_path must resolve inside /Users/<name> ...`. The same pattern existed for audio download export paths and document-upload local-read path-policy errors.
4. **Severity assessment** — Low. These paths are admin-gated where they write or read files, and the policy correctly rejects the operation. The remaining issue was inconsistent error hygiene: rejected tool calls could still disclose host-specific paths not needed by the client. **Confidence:** 9/10.
5. **Suggested change** — Route every client-visible `PathPolicyError` return through `getSanitizedErrorMessage(err)`, and use the same helper in `system.ts` catch blocks instead of raw `error.message` / `String(error)`. Add a source-text regression test that fails if these branches return `err.message` directly again.

**Status:** Addressed in this pass.
