/**
 * Regression test for SessionManager.getOrCreateSession() URL revalidation.
 *
 * The pre-fix code accepted any URL whose string starts with "http", so a
 * library entry that had been poisoned to `http://attacker.example/...`
 * would be passed straight to BrowserSession and `page.goto`. This test
 * pins the new behaviour: every URL passed to `getOrCreateSession` is
 * revalidated through `validateNotebookUrl`, regardless of where it came
 * from (caller argument, library lookup, CONFIG default).
 *
 * Cross-reference: CODEX_REVIEW.md "Critical: Stored Trusted-State
 * Notebook URL Poisoning…".
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock patchright so importing SessionManager (transitively) doesn't
// require a chromium install during tests.
vi.mock("patchright", () => ({
  chromium: { launchPersistentContext: vi.fn() },
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
  logger: {
    info: vi.fn(),
    success: vi.fn(),
    warning: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock("../src/utils/audit-logger.js", () => ({
  audit: {
    session: vi.fn().mockResolvedValue(undefined),
    security: vi.fn().mockResolvedValue(undefined),
    auth: vi.fn().mockResolvedValue(undefined),
    system: vi.fn().mockResolvedValue(undefined),
    tool: vi.fn().mockResolvedValue(undefined),
  },
  getAuditLogger: vi.fn(() => ({
    onEvent: vi.fn(),
    getStats: vi.fn(() => ({ totalEvents: 0 })),
  })),
}));

vi.mock("../src/session/shared-context-manager.js", () => {
  class FakeSharedContextManager {
    getOrCreateContext = vi.fn().mockResolvedValue({});
    closeContext = vi.fn().mockResolvedValue(undefined);
    needsHeadlessModeChange = vi.fn().mockReturnValue(false);
    getCurrentHeadlessMode = vi.fn().mockReturnValue(null);
  }
  return { SharedContextManager: FakeSharedContextManager };
});

vi.mock("../src/session/browser-session.js", () => {
  class FakeBrowserSession {
    sessionId: string;
    notebookUrl: string;
    createdAt = Date.now();
    lastActivity = Date.now();
    constructor(id: string, _c: unknown, _a: unknown, url: string) {
      this.sessionId = id;
      this.notebookUrl = url;
    }
    init = vi.fn().mockResolvedValue(undefined);
    close = vi.fn().mockResolvedValue(undefined);
    getInfo = vi.fn().mockReturnValue({
      id: this.sessionId,
      notebook_url: this.notebookUrl,
      age_seconds: 0,
      message_count: 0,
      last_activity: new Date().toISOString(),
    });
    isExpired = vi.fn().mockReturnValue(false);
    updateActivity = vi.fn();
  }
  return { BrowserSession: FakeBrowserSession };
});

import { SessionManager } from "../src/session/session-manager.js";
import { AuthManager } from "../src/auth/auth-manager.js";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("SessionManager URL revalidation (CODEX_REVIEW.md poisoned-library finding)", () => {
  function makeManager(): SessionManager {
    const auth = {
      validateWithRetry: vi.fn().mockResolvedValue(true),
    } as unknown as AuthManager;
    return new SessionManager(auth);
  }

  it("accepts a real NotebookLM URL", async () => {
    const sm = makeManager();
    const session = await sm.getOrCreateSession("s1", "https://notebooklm.google.com/notebook/abc");
    expect(session.notebookUrl).toBe("https://notebooklm.google.com/notebook/abc");
    await sm.closeAllSessions();
  });

  it("rejects a poisoned URL even though it starts with http", async () => {
    const sm = makeManager();
    await expect(
      sm.getOrCreateSession("s2", "https://attacker.example/notebook/abc"),
    ).rejects.toThrow(/Notebook URL rejected by allowlist/);
    await sm.closeAllSessions();
  });

  it("rejects javascript: URLs", async () => {
    const sm = makeManager();
    await expect(sm.getOrCreateSession("s3", "javascript:alert(1)")).rejects.toThrow(
      /Notebook URL rejected by allowlist/,
    );
    await sm.closeAllSessions();
  });

  it("rejects http:// (non-HTTPS) NotebookLM URLs", async () => {
    const sm = makeManager();
    await expect(
      sm.getOrCreateSession("s4", "http://notebooklm.google.com/notebook/abc"),
    ).rejects.toThrow(/Notebook URL rejected by allowlist/);
    await sm.closeAllSessions();
  });

  it("rejects empty URL", async () => {
    const sm = makeManager();
    await expect(sm.getOrCreateSession("s5", "")).rejects.toThrow(
      /Notebook URL is required/,
    );
    await sm.closeAllSessions();
  });
});
