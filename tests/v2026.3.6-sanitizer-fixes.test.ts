/**
 * Regression tests for the v2026.3.6 sanitizer-coverage follow-up.
 *
 * v2026.3.4 finding #11 introduced `getSanitizedErrorMessage` (strips
 * absolute paths and stack-frame fragments before returning error text
 * to the MCP client). v2026.3.5 wired it through the per-handler early-
 * return path in three handler files plus the compliance dispatcher.
 * This follow-up extends the same invariant to the remaining client-
 * visible error-field sites:
 *
 *   - src/compliance/health-monitor.ts   (6 sites — `get_health` results)
 *   - src/compliance/retention-engine.ts (1 site — retention result.error)
 *   - src/webhooks/webhook-dispatcher.ts (1 site — webhook delivery.error)
 *
 * Invariant under test: every code path that constructs a client-visible
 * `error:` field from a caught Error routes the message through
 * `getSanitizedErrorMessage`.
 *
 * Two layers of coverage:
 *  1. Source-grep — each affected file imports the helper and contains
 *     no leftover raw `error instanceof Error ? error.message : String(error)`
 *     pattern feeding a client-visible field.
 *  2. Runtime — exercise the compliance dispatcher end-to-end with an
 *     injected throwing dependency and assert both the returned text
 *     and the audit-log argument are stripped.
 */

import { describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";

// ────────────────────────────────────────────────────────────────────
// 1. Source-grep coverage
// ────────────────────────────────────────────────────────────────────

function source(...parts: string[]): string {
  return fs.readFileSync(path.join(__dirname, "..", ...parts), "utf8");
}

describe("v2026.3.6 sanitizer coverage: source-grep", () => {
  describe("handler files (v2026.3.5 follow-up sites, re-pinned here)", () => {
    it("compliance-tools dispatcher uses sanitizer in catch", () => {
      const src = source("src", "compliance", "compliance-tools.ts");
      expect(src).toContain(
        'import { getSanitizedErrorMessage } from "../tools/handlers/error-utils.js";',
      );
      expect(src).toMatch(/const errorMessage = getSanitizedErrorMessage\(error\);/);
      expect(src).not.toContain(
        "const errorMessage = error instanceof Error ? error.message : String(error);",
      );
    });

    it("PathPolicyError branches in handlers route err.message via sanitizer", () => {
      const files = [
        ["src", "tools", "handlers", "system.ts"],
        ["src", "tools", "handlers", "audio-video.ts"],
        ["src", "tools", "handlers", "gemini.ts"],
      ];
      for (const f of files) {
        const src = source(...f);
        expect(src).not.toMatch(
          /if\s*\(err instanceof PathPolicyError\)\s*\{[\s\S]{0,260}error:\s*err\.message/,
        );
        expect(src).not.toMatch(
          /return\s*\{\s*success:\s*false,\s*data:\s*null,\s*error:\s*err\.message\s*\}/,
        );
      }
    });
  });

  describe("compliance + webhook sites (v2026.3.6 expansion)", () => {
    it("health-monitor: all component-down error fields use sanitizer", () => {
      const src = source("src", "compliance", "health-monitor.ts");
      expect(src).toContain(
        'import { getSanitizedErrorMessage } from "../tools/handlers/error-utils.js";',
      );
      expect(src).not.toMatch(
        /error:\s*error instanceof Error\s*\?\s*error\.message\s*:\s*String\(error\)/,
      );
      const matches = src.match(/error:\s*getSanitizedErrorMessage\(error\)/g) ?? [];
      expect(matches.length).toBeGreaterThanOrEqual(6);
    });

    it("retention-engine: result.error uses sanitizer", () => {
      const src = source("src", "compliance", "retention-engine.ts");
      expect(src).toContain(
        'import { getSanitizedErrorMessage } from "../tools/handlers/error-utils.js";',
      );
      expect(src).not.toMatch(
        /result\.error\s*=\s*error instanceof Error\s*\?\s*error\.message\s*:\s*String\(error\)/,
      );
      expect(src).toMatch(/result\.error\s*=\s*getSanitizedErrorMessage\(error\);/);
    });

    it("webhook-dispatcher: delivery.error / log messages use sanitizer", () => {
      const src = source("src", "webhooks", "webhook-dispatcher.ts");
      expect(src).toContain(
        'import { getSanitizedErrorMessage } from "../tools/handlers/error-utils.js";',
      );
      expect(src).toMatch(
        /const errorMessage = getSanitizedErrorMessage\(error\);/,
      );
      expect(src).not.toMatch(
        /const errorMessage = error instanceof Error\s*\?\s*error\.message\s*:\s*String\(error\);/,
      );
    });
  });
});

// ────────────────────────────────────────────────────────────────────
// 2. Runtime coverage — compliance dispatcher end-to-end
// ────────────────────────────────────────────────────────────────────
//
// Force a compliance tool to throw an Error whose message carries
// (a) an absolute path and (b) a stack-frame fragment. The dispatcher
// catches it and serialises into the TextContent reply. Both the reply
// text AND the audit-log argument must be scrubbed.

vi.mock("../src/utils/logger.js", () => ({
  log: {
    info: vi.fn(), success: vi.fn(), warning: vi.fn(),
    error: vi.fn(), debug: vi.fn(), dim: vi.fn(),
  },
  logger: {
    info: vi.fn(), success: vi.fn(), warning: vi.fn(),
    error: vi.fn(), debug: vi.fn(),
  },
}));

const auditMock = vi.hoisted(() => ({
  tool: vi.fn().mockResolvedValue(undefined),
  auth: vi.fn().mockResolvedValue(undefined),
  session: vi.fn().mockResolvedValue(undefined),
  security: vi.fn().mockResolvedValue(undefined),
  system: vi.fn().mockResolvedValue(undefined),
  compliance: vi.fn().mockResolvedValue(undefined),
  dataAccess: vi.fn().mockResolvedValue(undefined),
  configChange: vi.fn().mockResolvedValue(undefined),
  retention: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../src/utils/audit-logger.js", () => ({
  audit: auditMock,
  getAuditLogger: vi.fn(() => ({
    onEvent: vi.fn(() => () => undefined),
    getStats: vi.fn(() => ({ totalEvents: 0 })),
    flush: vi.fn().mockResolvedValue(undefined),
  })),
}));

// One bare path (outside any stack-frame fragment) so the `[path]`
// placeholder survives, plus one path nested inside a stack frame so
// the stack-frame strip has work to do. Existing finding-#11 tests
// already cover the order-of-replacement (stack-frame replacement
// consumes any `[path]` substituted into a `(... :line:col)` match).
const LEAKY_MESSAGE =
  "failed reading /Users/leak/private/notes.json: boom at parseDashboard (/Users/leak/inner/path.ts:42:11) tail";

vi.mock("../src/compliance/dashboard.js", () => ({
  getDashboardCLI: vi.fn(async () => {
    throw new Error(LEAKY_MESSAGE);
  }),
  getComplianceDashboard: vi.fn(() => ({
    generateDashboard: vi.fn(),
    getComplianceScore: vi.fn(),
  })),
}));

import { handleComplianceToolCall } from "../src/compliance/compliance-tools.js";

describe("v2026.3.6 runtime: compliance dispatcher sanitizes leaked path + stack frame", () => {
  it("returned text and audit arg contain neither absolute path nor stack-frame fragment", async () => {
    auditMock.tool.mockClear();

    const result = await handleComplianceToolCall("compliance_dashboard", {
      format: "cli",
    });

    expect(result).toHaveLength(1);
    const text = result[0]?.text ?? "";

    // Sanity: dispatcher caught the thrown error
    expect(text).toMatch(/Error executing compliance_dashboard/);

    // Absolute path stripped → replaced by `[path]`
    expect(text).not.toContain("/Users/leak/private/path.ts");
    expect(text).toContain("[path]");

    // Stack-frame fragment stripped
    expect(text).not.toMatch(/at\s+\S+\s+\(\S+:\d+:\d+\)/);

    // Audit log received the sanitised form
    const auditCall = auditMock.tool.mock.calls.find(
      (c) => c[0] === "compliance_dashboard" && c[2] === false,
    );
    expect(auditCall).toBeDefined();
    const auditErrorArg = auditCall?.[4] as string | undefined;
    expect(auditErrorArg).toBeDefined();
    expect(auditErrorArg).not.toContain("/Users/leak/private/path.ts");
    expect(auditErrorArg).not.toMatch(/at\s+\S+\s+\(\S+:\d+:\d+\)/);
  });
});
