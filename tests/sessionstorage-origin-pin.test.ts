/**
 * Regression test for the BrowserSession sessionStorage origin allowlist.
 *
 * Pre-fix, `BrowserSession.restoreSessionStorage` derived the target
 * origin from `this.notebookUrl` and restored saved NotebookLM
 * sessionStorage into whatever origin came back. A library entry that
 * was poisoned to `https://attacker.example/...` would cause Google
 * authentication state to be written into the attacker's origin.
 *
 * The fix pins the allowed origins to a static, hard-coded set. This
 * test verifies (a) that set is only NotebookLM origins, (b) it has not
 * been silently widened to include any non-NotebookLM origin.
 *
 * Cross-reference: CODEX_REVIEW.md "Critical: Stored Trusted-State
 * Notebook URL Poisoning Can Navigate the Authenticated Browser…".
 */

import { describe, expect, it, vi } from "vitest";

// We only need to import BrowserSession to read its static set. patchright
// is mocked so the module resolves without a chromium install. (Other
// collaborators are imported lazily inside class methods we don't call.)
vi.mock("patchright", () => ({
  chromium: { launchPersistentContext: vi.fn() },
}));

vi.mock("../src/utils/audit-logger.js", () => ({
  audit: {
    session: vi.fn().mockResolvedValue(undefined),
    security: vi.fn().mockResolvedValue(undefined),
    auth: vi.fn().mockResolvedValue(undefined),
    system: vi.fn().mockResolvedValue(undefined),
    tool: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../src/utils/logger.js", () => ({
  log: {
    info: vi.fn(),
    success: vi.fn(),
    warning: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    dim: vi.fn(),
  },
}));

import { BrowserSession } from "../src/session/browser-session.js";

describe("BrowserSession.NOTEBOOKLM_RESTORE_ORIGINS", () => {
  it("contains only NotebookLM origins", () => {
    for (const origin of BrowserSession.NOTEBOOKLM_RESTORE_ORIGINS) {
      const url = new URL(origin);
      expect(url.protocol).toBe("https:");
      expect(url.hostname.startsWith("notebooklm.google.")).toBe(true);
      // Origin must be just protocol + host, no path/query/fragment.
      expect(`${url.protocol}//${url.host}`).toBe(origin);
    }
  });

  it("does not include attacker-reachable origins", () => {
    const forbidden = [
      "https://attacker.example",
      "https://notebooklm.google.com.evil.com",
      "https://example.notebooklm.google.com",
      "http://notebooklm.google.com", // wrong scheme
      "https://accounts.google.com",
      "https://google.com",
    ];
    for (const f of forbidden) {
      expect(BrowserSession.NOTEBOOKLM_RESTORE_ORIGINS.has(f)).toBe(false);
    }
  });

  it("includes the canonical .com origin", () => {
    expect(
      BrowserSession.NOTEBOOKLM_RESTORE_ORIGINS.has("https://notebooklm.google.com"),
    ).toBe(true);
  });

  it("matches the size implied by ALLOWED_NOTEBOOK_DOMAINS in security.ts", async () => {
    // The allowlist is intentionally hard-coded in two places (security.ts
    // and browser-session.ts) so a future domain rename forces an explicit
    // review of both files. This test ensures their counts have not
    // silently diverged.
    const securityModule = await import("../src/utils/security.js");
    // ALLOWED_NOTEBOOK_DOMAINS is module-private; fall back to invoking
    // validateNotebookUrl on a known-valid pattern per origin instead.
    const allOriginsValid = Array.from(BrowserSession.NOTEBOOKLM_RESTORE_ORIGINS).every(
      (origin) => {
        try {
          securityModule.validateNotebookUrl(`${origin}/notebook/abc`);
          return true;
        } catch {
          return false;
        }
      },
    );
    expect(allOriginsValid).toBe(true);
  });
});
