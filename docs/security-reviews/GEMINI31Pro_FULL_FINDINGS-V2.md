# Code review request: `notebooklm-mcp-secure` (whole repo)

Review performed by Gemini 3.1 Pro based on Template 2 (V2 Pass).

## Areas Evaluated

The review focused on persistent-state validation, concurrency invariants, cross-OS robustness, outbound-HTTP surfaces, and async lifecycle correctness, assuming previous findings were already addressed.

## Findings

1. **Summary:** `AudioManager.downloadAudio` fetches untrusted scraped URLs blindly via `page.goto()`, enabling Server-Side Request Forgery (SSRF) and Local File Read.
   **Location:** `src/notebook-creation/audio-manager.ts` line 383 (`const response = await page.goto(downloadInfo.url);`).
   **Reproduction:** An attacker injects `<a download href="file:///etc/passwd">Download</a>` or `<audio src="http://169.254.169.254/latest/meta-data/">` into the DOM of the NotebookLM page (e.g. via prompt injection in a generated document). `downloadAudio` scrapes this URL from the DOM and calls `page.goto(downloadInfo.url)`. The Playwright context navigates to the local file or internal IP, reads its contents into `response.body()`, and saves it to the local filesystem for the attacker to retrieve.
   **Severity:** Critical
   **Confidence:** 10
   **Suggested change:** Pass `downloadInfo.url` through `validateSourceUrl(url)` (from `src/utils/security.ts`) before calling `page.goto()`. This will correctly enforce HTTPS and reject `file://`, `javascript:`, and other dangerous schemes.

2. **Summary:** `AuditLogger` hash chain suffers from a concurrency flaw where simultaneous logs capture the same `previousHash`, falsely breaking the cryptographic chain and causing `verifyIntegrity` to fail.
   **Location:** `src/utils/audit-logger.ts` lines 365-375 (inside `private async log(...)`).
   **Reproduction:** Invoke two tool calls concurrently that both trigger an audit log. Because `log()` assigns `previousHash` from `this.previousHash` *before* the asynchronous write queue runs, both events will capture the identical `previousHash` string. When `flushEvent` writes them sequentially to the `.jsonl` file, they branch cryptographically rather than chain. A subsequent call to `verifyIntegrity()` will then incorrectly throw `Hash chain broken` because it expects the file's linear ordering to match the hash lineage.
   **Severity:** High
   **Confidence:** 10
   **Suggested change:** Move the computation of the event `hash` and the capture of `this.previousHash` *inside* the `flushEvent` method, which is already serialized safely via `withLock`.

3. **Summary:** `SettingsManager.saveSettings` lacks concurrency control, allowing potential race conditions or lost updates.
   **Location:** `src/utils/settings-manager.ts` lines 140-145.
   **Reproduction:** Send two concurrent requests that mutate settings (e.g. via a CLI handler or future mutating tools). Both async requests load the same `this.settings` in memory, merge their new values, and then call the synchronous `writeFileSecure`. If the event loop yields between the merge and the write, one request will overwrite the other's changes, leading to lost updates.
   **Severity:** Low
   **Confidence:** 9
   **Suggested change:** Serialize writes using a promise queue (`this.saveQueue = this.saveQueue.then(...)`) in `SettingsManager`, identical to the serialization pattern used by `WebhookDispatcher` for its JSON store.
